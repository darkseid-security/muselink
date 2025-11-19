"""
database/query_helpers.py
Safe Query Builders with Second-Order SQL Injection Protection

Provides high-level functions for common database operations
All functions use SQLAlchemy Core for automatic parameterization

Security Features:
- Automatic SQL injection protection
- Second-order SQLi prevention via safe value binding
- IDOR protection built into queries
- Audit logging integration
- Type validation
"""

import logging
from typing import Any, Dict, List, Optional, Union
from sqlalchemy import select, insert, update, delete, and_, or_, func
from sqlalchemy.sql import ClauseElement

from database.models import (
    users, user_sessions, user_mfa, messages, teams, team_members,
    drive_files, drive_folders, notes, ideas, audit_logs, security_incidents,
    password_reset_tokens, email_verification_tokens, drive_backups, backup_schedules
)
from database.sqlalchemy_db import execute_query, safe_bind, get_db

logger = logging.getLogger(__name__)


# =============================================================================
# User Queries
# =============================================================================

def get_user_by_id(user_id: int) -> Optional[Dict]:
    """
    Get user by ID

    Args:
        user_id: User ID

    Returns:
        User row or None
    """
    result = execute_query(
        select(users).where(users.c.id == user_id),
        fetch_one=True
    )
    return dict(result._mapping) if result else None


def get_user_by_email(email: str) -> Optional[Dict]:
    """
    Get user by email (safe from second-order SQLi)

    Args:
        email: User email (may come from database)

    Returns:
        User row or None
    """
    # safe_bind() protects against second-order SQLi
    safe_email = safe_bind(email)

    result = execute_query(
        select(users).where(users.c.email == safe_email),
        fetch_one=True
    )
    return dict(result._mapping) if result else None


def get_user_by_username(username: str) -> Optional[Dict]:
    """
    Get user by username (safe from second-order SQLi)

    Args:
        username: Username (may contain SQL syntax from previous storage)

    Returns:
        User row or None
    """
    safe_username = safe_bind(username)

    result = execute_query(
        select(users).where(users.c.username == safe_username),
        fetch_one=True
    )
    return dict(result._mapping) if result else None


def create_user(
    email: str,
    username: str,
    password_hash: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    encryption_key: str = None,
    is_admin: bool = False
) -> int:
    """
    Create new user

    Args:
        email: User email
        username: Username
        password_hash: Argon2id password hash
        first_name: First name
        last_name: Last name
        encryption_key: Encrypted encryption key
        is_admin: Admin flag

    Returns:
        User ID
    """
    result = execute_query(
        insert(users).values(
            email=safe_bind(email),
            username=safe_bind(username),
            password_hash=password_hash,
            first_name=safe_bind(first_name) if first_name else None,
            last_name=safe_bind(last_name) if last_name else None,
            encryption_key=encryption_key,
            is_admin=is_admin
        ).returning(users.c.id),
        commit=True,
        fetch_one=True
    )
    return result[0]


def update_user_password(user_id: int, new_password_hash: str) -> bool:
    """
    Update user password

    Args:
        user_id: User ID
        new_password_hash: New Argon2id password hash

    Returns:
        True if successful
    """
    result = execute_query(
        update(users)
        .where(users.c.id == user_id)
        .values(password_hash=new_password_hash),
        commit=True
    )
    return result.rowcount > 0


def increment_failed_login(user_id: int) -> bool:
    """
    Increment failed login attempts counter

    Args:
        user_id: User ID

    Returns:
        True if successful
    """
    result = execute_query(
        update(users)
        .where(users.c.id == user_id)
        .values(failed_login_attempts=users.c.failed_login_attempts + 1),
        commit=True
    )
    return result.rowcount > 0


def reset_failed_login(user_id: int) -> bool:
    """
    Reset failed login attempts to 0

    Args:
        user_id: User ID

    Returns:
        True if successful
    """
    result = execute_query(
        update(users)
        .where(users.c.id == user_id)
        .values(
            failed_login_attempts=0,
            locked_until=None
        ),
        commit=True
    )
    return result.rowcount > 0


def lock_user_account(user_id: int, locked_until) -> bool:
    """
    Lock user account until specified time

    Args:
        user_id: User ID
        locked_until: Datetime until account is locked

    Returns:
        True if successful
    """
    result = execute_query(
        update(users)
        .where(users.c.id == user_id)
        .values(locked_until=locked_until),
        commit=True
    )
    return result.rowcount > 0


# =============================================================================
# Session Queries (IDOR-Protected)
# =============================================================================

def get_active_session(session_token: str) -> Optional[Dict]:
    """
    Get active session by token

    Args:
        session_token: Session token

    Returns:
        Session row or None
    """
    safe_token = safe_bind(session_token)

    result = execute_query(
        select(user_sessions)
        .where(
            and_(
                user_sessions.c.session_token == safe_token,
                user_sessions.c.is_active == True,
                user_sessions.c.expires_at > func.now()
            )
        ),
        fetch_one=True
    )
    return dict(result._mapping) if result else None


def create_session(
    user_id: int,
    session_token: str,
    ip_address: str,
    user_agent: str,
    expires_at
) -> int:
    """
    Create new user session

    Args:
        user_id: User ID
        session_token: Session token
        ip_address: Client IP
        user_agent: Client user agent
        expires_at: Expiration datetime

    Returns:
        Session ID
    """
    result = execute_query(
        insert(user_sessions).values(
            user_id=user_id,
            session_token=session_token,
            ip_address=safe_bind(ip_address),
            user_agent=safe_bind(user_agent),
            expires_at=expires_at
        ).returning(user_sessions.c.id),
        commit=True,
        fetch_one=True
    )
    return result[0]


def invalidate_session(session_token: str) -> bool:
    """
    Invalidate session (logout)

    Args:
        session_token: Session token

    Returns:
        True if successful
    """
    safe_token = safe_bind(session_token)

    result = execute_query(
        update(user_sessions)
        .where(user_sessions.c.session_token == safe_token)
        .values(is_active=False),
        commit=True
    )
    return result.rowcount > 0


def invalidate_all_user_sessions(user_id: int) -> int:
    """
    Invalidate all sessions for a user

    Args:
        user_id: User ID

    Returns:
        Number of sessions invalidated
    """
    result = execute_query(
        update(user_sessions)
        .where(
            and_(
                user_sessions.c.user_id == user_id,
                user_sessions.c.is_active == True
            )
        )
        .values(is_active=False),
        commit=True
    )
    return result.rowcount


def cleanup_expired_sessions() -> int:
    """
    Delete expired sessions

    Returns:
        Number of sessions deleted
    """
    result = execute_query(
        delete(user_sessions)
        .where(
            or_(
                user_sessions.c.expires_at < func.now(),
                and_(
                    user_sessions.c.is_active == False,
                    user_sessions.c.last_activity < func.now() - func.cast('7 days', type_=user_sessions.c.last_activity.type)
                )
            )
        ),
        commit=True
    )
    return result.rowcount


# =============================================================================
# Message Queries (IDOR-Protected)
# =============================================================================

def get_message_by_id(message_id: int, user_id: int) -> Optional[Dict]:
    """
    Get message by ID with IDOR protection

    Only returns message if user is sender or receiver

    Args:
        message_id: Message ID
        user_id: Requesting user ID

    Returns:
        Message row or None
    """
    result = execute_query(
        select(messages)
        .where(
            and_(
                messages.c.id == message_id,
                or_(
                    messages.c.sender_id == user_id,
                    messages.c.receiver_id == user_id
                )
            )
        ),
        fetch_one=True
    )
    return dict(result._mapping) if result else None


def get_user_inbox(user_id: int, unread_only: bool = False) -> List[Dict]:
    """
    Get user's inbox messages

    Args:
        user_id: User ID
        unread_only: Only return unread messages

    Returns:
        List of messages
    """
    query = select(messages).where(
        and_(
            messages.c.receiver_id == user_id,
            messages.c.deleted_by_receiver == False
        )
    )

    if unread_only:
        query = query.where(messages.c.is_read == False)

    query = query.order_by(messages.c.created_at.desc())

    result = execute_query(query, fetch_all=True)
    return [dict(row._mapping) for row in result]


def send_message(
    sender_id: int,
    receiver_id: int,
    content_sender: str,
    content_receiver: str,
    subject: Optional[str] = None
) -> int:
    """
    Send encrypted message

    Args:
        sender_id: Sender user ID
        receiver_id: Receiver user ID
        content_sender: Encrypted content for sender
        content_receiver: Encrypted content for receiver
        subject: Message subject

    Returns:
        Message ID
    """
    result = execute_query(
        insert(messages).values(
            sender_id=sender_id,
            receiver_id=receiver_id,
            subject=safe_bind(subject) if subject else None,
            content_sender=content_sender,
            content_receiver=content_receiver
        ).returning(messages.c.id),
        commit=True,
        fetch_one=True
    )
    return result[0]


def mark_message_read(message_id: int, user_id: int) -> bool:
    """
    Mark message as read (IDOR-protected)

    Args:
        message_id: Message ID
        user_id: User ID (must be receiver)

    Returns:
        True if successful
    """
    result = execute_query(
        update(messages)
        .where(
            and_(
                messages.c.id == message_id,
                messages.c.receiver_id == user_id,
                messages.c.is_read == False
            )
        )
        .values(is_read=True, read_at=func.now()),
        commit=True
    )
    return result.rowcount > 0


def delete_message(message_id: int, user_id: int) -> bool:
    """
    Soft delete message (IDOR-protected)

    Args:
        message_id: Message ID
        user_id: User ID (must be sender or receiver)

    Returns:
        True if successful
    """
    # Get message first to determine if user is sender or receiver
    message = get_message_by_id(message_id, user_id)
    if not message:
        return False

    # Determine which field to update
    if message['sender_id'] == user_id:
        update_field = {'deleted_by_sender': True}
    elif message['receiver_id'] == user_id:
        update_field = {'deleted_by_receiver': True}
    else:
        return False

    result = execute_query(
        update(messages)
        .where(messages.c.id == message_id)
        .values(**update_field),
        commit=True
    )
    return result.rowcount > 0


# =============================================================================
# Drive Queries (IDOR-Protected)
# =============================================================================

def get_file_by_id(file_id: int, user_id: int) -> Optional[Dict]:
    """
    Get file by ID with IDOR protection

    Verifies user owns file or is team member

    Args:
        file_id: File ID
        user_id: Requesting user ID

    Returns:
        File row or None
    """
    # First, try owner match
    result = execute_query(
        select(drive_files)
        .where(
            and_(
                drive_files.c.id == file_id,
                drive_files.c.owner_id == user_id,
                drive_files.c.is_deleted == False
            )
        ),
        fetch_one=True
    )

    if result:
        return dict(result._mapping)

    # If not owner, check team membership
    result = execute_query(
        select(drive_files)
        .join(team_members, drive_files.c.team_id == team_members.c.team_id)
        .where(
            and_(
                drive_files.c.id == file_id,
                team_members.c.user_id == user_id,
                team_members.c.is_active == True,
                drive_files.c.is_deleted == False
            )
        ),
        fetch_one=True
    )

    return dict(result._mapping) if result else None


def get_user_files(user_id: int, team_id: Optional[int] = None) -> List[Dict]:
    """
    Get user's files (IDOR-protected)

    Args:
        user_id: User ID
        team_id: Optional team ID filter

    Returns:
        List of files
    """
    if team_id:
        # Verify user is team member first
        is_member = execute_query(
            select(team_members)
            .where(
                and_(
                    team_members.c.team_id == team_id,
                    team_members.c.user_id == user_id,
                    team_members.c.is_active == True
                )
            ),
            fetch_one=True
        )

        if not is_member:
            return []

        # Get team files
        query = select(drive_files).where(
            and_(
                drive_files.c.team_id == team_id,
                drive_files.c.is_deleted == False
            )
        )
    else:
        # Get personal files
        query = select(drive_files).where(
            and_(
                drive_files.c.owner_id == user_id,
                drive_files.c.team_id == None,
                drive_files.c.is_deleted == False
            )
        )

    query = query.order_by(drive_files.c.created_at.desc())

    result = execute_query(query, fetch_all=True)
    return [dict(row._mapping) for row in result]


# =============================================================================
# Audit Logging
# =============================================================================

def log_audit_event(
    user_id: Optional[int],
    action: str,
    status: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict] = None
) -> int:
    """
    Log security audit event

    Args:
        user_id: User ID (None for anonymous)
        action: Action performed
        status: 'success' or 'failed'
        ip_address: Client IP
        user_agent: Client user agent
        details: Additional details (JSONB)

    Returns:
        Audit log ID
    """
    result = execute_query(
        insert(audit_logs).values(
            user_id=user_id,
            action=safe_bind(action),
            status=status,
            ip_address=safe_bind(ip_address) if ip_address else None,
            user_agent=safe_bind(user_agent) if user_agent else None,
            details=details
        ).returning(audit_logs.c.id),
        commit=True,
        fetch_one=True
    )
    return result[0]


def log_security_incident(
    incident_type: str,
    severity: str,
    ip_address: str,
    endpoint: str,
    input_sample: Optional[str] = None,
    pattern_matched: Optional[str] = None,
    user_id: Optional[int] = None,
    details: Optional[Dict] = None
) -> int:
    """
    Log security incident (attack attempt)

    Args:
        incident_type: Type of attack
        severity: 'low', 'medium', 'high', 'critical'
        ip_address: Attacker IP
        endpoint: Targeted endpoint
        input_sample: Sample of malicious input
        pattern_matched: Attack pattern matched
        user_id: User ID if authenticated
        details: Additional details

    Returns:
        Security incident ID
    """
    result = execute_query(
        insert(security_incidents).values(
            user_id=user_id,
            incident_type=safe_bind(incident_type),
            severity=severity,
            ip_address=safe_bind(ip_address),
            endpoint=safe_bind(endpoint),
            input_sample=safe_bind(input_sample[:1000]) if input_sample else None,  # Limit to 1000 chars
            pattern_matched=safe_bind(pattern_matched),
            details=details
        ).returning(security_incidents.c.id),
        commit=True,
        fetch_one=True
    )
    return result[0]


# =============================================================================
# Statistics Queries
# =============================================================================

def get_user_count() -> int:
    """Get total user count"""
    result = execute_query(
        select(func.count(users.c.id)),
        fetch_one=True
    )
    return result[0]


def get_active_user_count() -> int:
    """Get active user count"""
    result = execute_query(
        select(func.count(users.c.id))
        .where(users.c.is_active == True),
        fetch_one=True
    )
    return result[0]


def get_active_session_count() -> int:
    """Get active session count"""
    result = execute_query(
        select(func.count(user_sessions.c.id))
        .where(
            and_(
                user_sessions.c.is_active == True,
                user_sessions.c.expires_at > func.now()
            )
        ),
        fetch_one=True
    )
    return result[0]


def get_unread_message_count(user_id: int) -> int:
    """
    Get unread message count for user

    Args:
        user_id: User ID

    Returns:
        Unread message count
    """
    result = execute_query(
        select(func.count(messages.c.id))
        .where(
            and_(
                messages.c.receiver_id == user_id,
                messages.c.is_read == False,
                messages.c.deleted_by_receiver == False
            )
        ),
        fetch_one=True
    )
    return result[0]
