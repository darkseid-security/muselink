"""
routers/teams.py
Team invitation and management endpoints with IDOR protection and rate limiting
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field, validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import select, update, delete, insert, and_, or_, func
from database.models import team_invitations, notifications, teams, team_members, users
from database.sqlalchemy_db import execute_query
from utils.auth_dependencies import require_auth
from utils.audit import log_audit_event
from utils.input_sanitizer import validate_and_sanitize, MaliciousInputDetected
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# =============================================================================
# Pydantic Models
# =============================================================================

class TeamInviteRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern=r'^[a-zA-Z0-9_-]+$')
    message: Optional[str] = Field(None, max_length=500)

    @validator('message')
    def validate_message(cls, v):
        if v:
            v = v.strip()
            # Check for malicious content
            from utils.input_sanitizer import comprehensive_input_scan
            is_malicious, attack_type, pattern = comprehensive_input_scan(v)
            if is_malicious:
                raise ValueError(f"Invalid message content")
        return v

class InvitationResponse(BaseModel):
    action: str = Field(..., pattern=r'^(accept|reject)$')

class RemoveMemberRequest(BaseModel):
    user_id: int = Field(..., gt=0)

# =============================================================================
# Helper Functions
# =============================================================================

async def get_current_user_id(current_user: dict = Depends(require_auth)) -> int:
    """Get current user ID from authentication dependency"""
    return current_user["id"]

def verify_team_ownership(team_id: int, user_id: int) -> bool:
    """Verify if user is the team owner or admin"""
    result = execute_query(
        select(team_members).where(
            and_(
                team_members.c.team_id == team_id,
                team_members.c.user_id == user_id,
                team_members.c.role.in_(['owner', 'admin']),
                team_members.c.is_active == True
            )
        ),
        fetch_one=True
    )
    return result is not None

def create_notification(user_id: int, notif_type: str, title: str, message: str,
                       related_type: Optional[str] = None, related_id: Optional[int] = None,
                       action_url: Optional[str] = None, priority: str = 'normal'):
    """Create a notification for a user"""
    execute_query(
        insert(notifications).values(
            user_id=user_id,
            type=notif_type,
            title=title,
            message=message,
            priority=priority,
            related_type=related_type,
            related_id=related_id,
            action_url=action_url
        ),
        commit=True
    )

def log_team_audit_event(user_id: int, action: str, resource_type: str, resource_id: int,
                         ip_address: Optional[str], status: str = "success", details: str = ""):
    """Wrapper for log_audit_event that creates its own cursor"""
    from database.connection import get_db_connection, return_db_connection

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        log_audit_event(
            cursor, user_id, action, status, ip_address,
            {"resource_type": resource_type, "resource_id": resource_id, "details": details}
        )
        conn.commit()
        return_db_connection(conn)
    except Exception as e:
        return_db_connection(conn)
        logger.error(f"Failed to log audit event: {e}")

# =============================================================================
# Team Invitation Endpoints
# =============================================================================

@router.post("/{team_id}/invite")
@limiter.limit("10/hour")  # Rate limit: 10 invites per hour
async def send_team_invitation(
    request: Request,
    team_id: int,
    invite: TeamInviteRequest,
    user_id: int = Depends(get_current_user_id)
):
    """
    Send a team invitation to a user by username

    Security:
    - IDOR protection: Verifies team ownership
    - Rate limited: 10 invites/hour to prevent spam
    - Input validation: Username sanitization
    - Audit logging: All invitation attempts logged
    """
    # Verify team ownership/admin role
    if not verify_team_ownership(team_id, user_id):
        log_team_audit_event(
            user_id=user_id,
            action="team_invite_unauthorized",
            resource_type="team",
            resource_id=team_id,
            ip_address=request.client.host,
            status="failed"
        )
        raise HTTPException(status_code=403, detail="Only team owners/admins can send invitations")

    # Find invitee by username
    invitee_row = execute_query(
        select(users).where(users.c.username == invite.username),
        fetch_one=True
    )

    if not invitee_row:
        return {"success": False, "message": f"User '{invite.username}' not found"}

    invitee = dict(invitee_row._mapping)
    invitee_id = invitee['id']

    # Check if user is already a team member
    existing_member_row = execute_query(
        select(team_members).where(
            and_(
                team_members.c.team_id == team_id,
                team_members.c.user_id == invitee_id
            )
        ),
        fetch_one=True
    )

    if existing_member_row:
        return {"success": False, "message": "User is already a team member"}

    # Check for existing pending invitation
    existing_invite_row = execute_query(
        select(team_invitations).where(
            and_(
                team_invitations.c.team_id == team_id,
                team_invitations.c.invitee_id == invitee_id,
                team_invitations.c.status == 'pending'
            )
        ),
        fetch_one=True
    )

    if existing_invite_row:
        return {"success": False, "message": "Invitation already sent to this user"}

    # Get team name
    team_row = execute_query(
        select(teams).where(teams.c.id == team_id),
        fetch_one=True
    )
    team = dict(team_row._mapping)

    # Create invitation
    invitation_id = execute_query(
        insert(team_invitations).values(
            team_id=team_id,
            inviter_id=user_id,
            invitee_id=invitee_id,
            message=invite.message,
            status='pending',
            expires_at=datetime.utcnow() + timedelta(days=7)
        ).returning(team_invitations.c.id),
        commit=True,
        fetch_one=True
    )[0]

    # Create notification for invitee (no invitation_id in URL to prevent IDOR)
    create_notification(
        user_id=invitee_id,
        notif_type='team_invitation',
        title=f"Team Invitation: {team['name']}",
        message=f"You've been invited to join the team '{team['name']}'",
        related_type='team_invitation',
        related_id=invitation_id,
        action_url="/dashboard?tab=teams",  # No invitation_id - user sees their own invitations
        priority='high'
    )

    # Log audit event
    log_team_audit_event(
        user_id=user_id,
        action="team_invite_sent",
        resource_type="team_invitation",
        resource_id=invitation_id,
        ip_address=request.client.host,
        status="success"
    )

    return {
        "success": True,
        "message": f"Invitation sent to {invite.username}",
        "invitation_id": invitation_id
    }

@router.get("/invitations")
async def get_my_invitations(user_id: int = Depends(get_current_user_id)):
    """Get pending team invitations for the current user"""
    invitations_rows = execute_query(
        select(
            team_invitations,
            teams.c.name.label('team_name'),
            users.c.username.label('inviter_username')
        )
        .join(teams, team_invitations.c.team_id == teams.c.id)
        .join(users, team_invitations.c.inviter_id == users.c.id)
        .where(
            and_(
                team_invitations.c.invitee_id == user_id,
                team_invitations.c.status == 'pending',
                team_invitations.c.expires_at > datetime.utcnow()
            )
        )
        .order_by(team_invitations.c.created_at.desc()),
        fetch_all=True
    )

    # Convert Row objects to dicts
    invitations = [dict(row._mapping) for row in invitations_rows]

    return {
        "invitations": [
            {
                "id": inv['id'],
                "team_id": inv['team_id'],
                "team_name": inv['team_name'],
                "inviter_username": inv['inviter_username'],
                "message": inv['message'],
                "created_at": inv['created_at'].isoformat(),
                "expires_at": inv['expires_at'].isoformat()
            }
            for inv in invitations
        ]
    }

@router.post("/invitations/{invitation_id}/respond")
async def respond_to_invitation(
    request: Request,
    invitation_id: int,
    response: InvitationResponse,
    user_id: int = Depends(get_current_user_id)
):
    """Accept or reject a team invitation"""
    # Get invitation with IDOR check
    invitation_row = execute_query(
        select(team_invitations).where(
            and_(
                team_invitations.c.id == invitation_id,
                team_invitations.c.invitee_id == user_id,  # IDOR protection
                team_invitations.c.status == 'pending'
            )
        ),
        fetch_one=True
    )

    if not invitation_row:
        raise HTTPException(status_code=404, detail="Invitation not found")

    invitation = dict(invitation_row._mapping)

    # Check expiration
    if invitation['expires_at'] < datetime.utcnow():
        execute_query(
            update(team_invitations)
            .where(team_invitations.c.id == invitation_id)
            .values(status='expired'),
            commit=True
        )
        raise HTTPException(status_code=400, detail="Invitation has expired")

    # Update invitation status
    execute_query(
        update(team_invitations)
        .where(team_invitations.c.id == invitation_id)
        .values(status='accepted' if response.action == 'accept' else 'rejected'),
        commit=True
    )

    team_id = invitation['team_id']

    if response.action == 'accept':
        # Get team encryption key from an existing member
        existing_member_row = execute_query(
            select(team_members).where(
                and_(
                    team_members.c.team_id == team_id,
                    team_members.c.is_active == True
                )
            ).limit(1),
            fetch_one=True
        )
        existing_member = dict(existing_member_row._mapping)

        # Add user to team
        execute_query(
            insert(team_members).values(
                team_id=team_id,
                user_id=user_id,
                role='member',
                team_key_encrypted=existing_member['team_key_encrypted'],  # Same encrypted team key
                added_by=invitation['inviter_id'],
                is_active=True
            ),
            commit=True
        )

        # Notify inviter
        create_notification(
            user_id=invitation['inviter_id'],
            notif_type='team_invitation_accepted',
            title="Invitation Accepted",
            message=f"User accepted your team invitation",
            related_type='team',
            related_id=team_id,
            priority='normal'
        )

    else:
        # Notify inviter
        create_notification(
            user_id=invitation['inviter_id'],
            notif_type='team_invitation_rejected',
            title="Invitation Declined",
            message=f"User declined your team invitation",
            related_type='team',
            related_id=team_id,
            priority='low'
        )

    # Log audit event
    log_team_audit_event(
        user_id=user_id,
        action=f"team_invite_{response.action}ed",
        resource_type="team_invitation",
        resource_id=invitation_id,
        ip_address=request.client.host,
        status="success"
    )

    return {"success": True, "action": response.action}

@router.delete("/{team_id}/members/{member_user_id}")
async def remove_team_member(
    request: Request,
    team_id: int,
    member_user_id: int,
    user_id: int = Depends(get_current_user_id)
):
    """
    Remove a member from the team and revoke all access

    Security:
    - Only team owner/admin can remove members
    - Revokes access to all team files, notes, and ideas
    - Audit logged
    """
    # Verify team ownership/admin role
    if not verify_team_ownership(team_id, user_id):
        raise HTTPException(status_code=403, detail="Only team owners/admins can remove members")

    # Cannot remove yourself
    if member_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself from the team")

    # Get team member
    member_row = execute_query(
        select(team_members).where(
            and_(
                team_members.c.team_id == team_id,
                team_members.c.user_id == member_user_id
            )
        ),
        fetch_one=True
    )

    if not member_row:
        raise HTTPException(status_code=404, detail="Team member not found")

    member = dict(member_row._mapping)

    # Cannot remove owner
    if member['role'] == 'owner':
        raise HTTPException(status_code=400, detail="Cannot remove team owner")

    # Remove team membership (soft delete)
    execute_query(
        update(team_members)
        .where(
            and_(
                team_members.c.team_id == team_id,
                team_members.c.user_id == member_user_id
            )
        )
        .values(is_active=False),
        commit=True
    )

    # Notify removed user
    team_row = execute_query(
        select(teams).where(teams.c.id == team_id),
        fetch_one=True
    )
    team = dict(team_row._mapping)

    create_notification(
        user_id=member_user_id,
        notif_type='team_member_removed',
        title="Removed from Team",
        message=f"You have been removed from the team '{team['name']}'",
        priority='high'
    )

    # Log audit event
    log_team_audit_event(
        user_id=user_id,
        action="team_member_removed",
        resource_type="team",
        resource_id=team_id,
        ip_address=request.client.host,
        status="success",
        details=f"Removed user_id: {member_user_id}"
    )

    return {"success": True, "message": "Team member removed"}

# =============================================================================
# Notification Endpoints
# =============================================================================

@router.get("/notifications")
async def get_notifications(
    unread_only: bool = False,
    user_id: int = Depends(get_current_user_id)
):
    """Get user notifications"""
    query = select(notifications).where(notifications.c.user_id == user_id)

    if unread_only:
        query = query.where(notifications.c.is_read == False)

    query = query.order_by(notifications.c.created_at.desc()).limit(50)

    notifs_rows = execute_query(query, fetch_all=True)

    # Convert Row objects to dicts
    notifs = [dict(row._mapping) for row in notifs_rows]

    return {
        "notifications": [
            {
                "id": n['id'],
                "type": n['type'],
                "title": n['title'],
                "message": n['message'],
                "is_read": n['is_read'],
                "priority": n['priority'],
                "action_url": n['action_url'],
                "created_at": n['created_at'].isoformat(),
                "read_at": n['read_at'].isoformat() if n['read_at'] else None
            }
            for n in notifs
        ]
    }

@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    user_id: int = Depends(get_current_user_id)
):
    """Mark a notification as read"""
    # IDOR protection
    result = execute_query(
        update(notifications)
        .where(
            and_(
                notifications.c.id == notification_id,
                notifications.c.user_id == user_id
            )
        )
        .values(is_read=True, read_at=datetime.utcnow()),
        commit=True
    )

    return {"success": True}

@router.get("/notifications/count")
async def get_unread_count(user_id: int = Depends(get_current_user_id)):
    """Get count of unread notifications"""
    result = execute_query(
        select(func.count(notifications.c.id)).where(
            and_(
                notifications.c.user_id == user_id,
                notifications.c.is_read == False
            )
        ),
        fetch_one=True
    )

    return {"unread_count": result[0]}
