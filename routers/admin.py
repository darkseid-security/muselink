"""
routers/admin.py
Admin-only routes for user management and system administration
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
import logging

from database.connection import get_db_connection, return_db_connection
from utils.security import verify_session_token, hash_password
from utils.audit import log_audit_event, get_audit_logs, AuditAction
from utils.auth_dependencies import require_admin

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)

# Pydantic Models

class UserUpdate(BaseModel):
    """Model for updating user information"""
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    is_active: Optional[bool] = None
    account_status: Optional[str] = Field(None, pattern='^(active|suspended|pending_verification|deleted)$')

class UserCreate(BaseModel):
    """Model for admin creating new user"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    password: str = Field(..., min_length=12, max_length=128)
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    is_admin: bool = False

# Helper Functions

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """Verify user is admin and return user_id"""
    token = credentials.credentials
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = verify_session_token(cursor, token)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        # Check if user is admin
        cursor.execute(
            "SELECT is_admin, is_active FROM users WHERE id = %s",
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result or not result[0] or not result[1]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        return user_id
        
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# Admin Endpoints

@router.get("/users")
async def list_users(
    current_user: dict = Depends(require_admin),
    limit: int = 50,
    offset: int = 0,
    search: Optional[str] = None
):
    """List all users (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if search:
            query = """
                SELECT id, email, username, first_name, last_name,
                       is_admin, is_active, account_status, email_verified,
                       created_at, last_login
                FROM users
                WHERE email ILIKE %s OR username ILIKE %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """
            search_term = f"%{search}%"
            cursor.execute(query, (search_term, search_term, limit, offset))
        else:
            query = """
                SELECT id, email, username, first_name, last_name,
                       is_admin, is_active, account_status, email_verified,
                       created_at, last_login
                FROM users
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(query, (limit, offset))
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'email': row[1],
                'username': row[2],
                'first_name': row[3],
                'last_name': row[4],
                'is_admin': row[5],
                'is_active': row[6],
                'account_status': row[7],
                'email_verified': row[8],
                'created_at': row[9].isoformat() if row[9] else None,
                'last_login': row[10].isoformat() if row[10] else None
            })
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM users")
        total = cursor.fetchone()[0]
        
        return {
            'users': users,
            'total': total,
            'limit': limit,
            'offset': offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing users: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list users"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/users/{user_id}")
async def get_user_detail(
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """Get detailed user information (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, email, username, first_name, last_name,
                   is_admin, is_active, account_status, email_verified,
                   phone_number, phone_verified, created_at, updated_at,
                   last_login, failed_login_attempts, locked_until
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user = {
            'id': result[0],
            'email': result[1],
            'username': result[2],
            'first_name': result[3],
            'last_name': result[4],
            'is_admin': result[5],
            'is_active': result[6],
            'account_status': result[7],
            'email_verified': result[8],
            'phone_number': result[9],
            'phone_verified': result[10],
            'created_at': result[11].isoformat() if result[11] else None,
            'updated_at': result[12].isoformat() if result[12] else None,
            'last_login': result[13].isoformat() if result[13] else None,
            'failed_login_attempts': result[14],
            'locked_until': result[15].isoformat() if result[15] else None
        }
        
        # Get MFA status
        cursor.execute(
            """
            SELECT mfa_method, is_enabled, last_used
            FROM user_mfa
            WHERE user_id = %s
            """,
            (user_id,)
        )
        
        mfa_methods = []
        for row in cursor.fetchall():
            mfa_methods.append({
                'method': row[0],
                'enabled': row[1],
                'last_used': row[2].isoformat() if row[2] else None
            })
        
        user['mfa_methods'] = mfa_methods
        
        # Get active sessions count
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE user_id = %s AND is_active = TRUE AND expires_at > NOW()
            """,
            (user_id,)
        )
        user['active_sessions'] = cursor.fetchone()[0]
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user detail: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user detail"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_admin)
):
    """Create new user (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email or username exists
        cursor.execute(
            "SELECT id FROM users WHERE email = %s OR username = %s",
            (user_data.email, user_data.username)
        )
        
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists"
            )
        
        # Hash password
        password_hash = hash_password(user_data.password)
        
        # Create user
        cursor.execute(
            """
            INSERT INTO users (
                email, username, password_hash, first_name, last_name,
                is_admin, is_active, account_status, email_verified
            )
            VALUES (%s, %s, %s, %s, %s, %s, TRUE, 'active', TRUE)
            RETURNING id, email, username
            """,
            (
                user_data.email,
                user_data.username,
                password_hash,
                user_data.first_name,
                user_data.last_name,
                user_data.is_admin
            )
        )
        
        new_user_id, email, username = cursor.fetchone()
        
        # Log audit event
        log_audit_event(
            cursor, admin_id, AuditAction.ADMIN_USER_CREATED, "success",
            None, {"created_user_id": new_user_id, "username": username}
        )
        
        conn.commit()
        
        logger.info(f"Admin {admin_id} created user {new_user_id}")
        
        return {
            'message': 'User created successfully',
            'user_id': new_user_id,
            'email': email,
            'username': username
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error creating user: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.put("/users/{user_id}")
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: dict = Depends(require_admin)
):
    """Update user information (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Build update query dynamically
        updates = []
        params = []
        
        if user_data.email is not None:
            updates.append("email = %s")
            params.append(user_data.email)
        
        if user_data.first_name is not None:
            updates.append("first_name = %s")
            params.append(user_data.first_name)
        
        if user_data.last_name is not None:
            updates.append("last_name = %s")
            params.append(user_data.last_name)
        
        if user_data.is_active is not None:
            updates.append("is_active = %s")
            params.append(user_data.is_active)
        
        if user_data.account_status is not None:
            updates.append("account_status = %s")
            params.append(user_data.account_status)
        
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No updates provided"
            )
        
        # Add updated_at
        updates.append("updated_at = NOW()")
        params.append(user_id)
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(query, params)
        
        # Log audit event
        log_audit_event(
            cursor, admin_id, AuditAction.ADMIN_USER_UPDATED, "success",
            None, {"updated_user_id": user_id, "changes": user_data.dict(exclude_none=True)}
        )
        
        conn.commit()
        
        logger.info(f"Admin {admin_id} updated user {user_id}")
        
        return {
            'message': 'User updated successfully',
            'user_id': user_id
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error updating user: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """Delete user (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Prevent deleting yourself
        if user_id == admin_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Check user exists
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        username = result[0]
        
        # Soft delete - mark account as deleted
        cursor.execute(
            """
            UPDATE users
            SET is_active = FALSE, account_status = 'deleted', updated_at = NOW()
            WHERE id = %s
            """,
            (user_id,)
        )
        
        # Invalidate all sessions
        cursor.execute(
            "UPDATE user_sessions SET is_active = FALSE WHERE user_id = %s",
            (user_id,)
        )
        
        # Log audit event
        log_audit_event(
            cursor, admin_id, AuditAction.ADMIN_USER_DELETED, "success",
            None, {"deleted_user_id": user_id, "username": username}
        )
        
        conn.commit()
        
        logger.info(f"Admin {admin_id} deleted user {user_id}")
        
        return {
            'message': 'User deleted successfully',
            'user_id': user_id
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error deleting user: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/audit-logs")
async def get_admin_audit_logs(
    current_user: dict = Depends(require_admin),
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get audit logs (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        logs = get_audit_logs(
            cursor,
            user_id=user_id,
            action=action,
            limit=limit,
            offset=offset
        )
        
        return {
            'logs': logs,
            'total': len(logs)
        }
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audit logs"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/stats")
async def get_system_stats(current_user: dict = Depends(require_admin)):
    """Get system statistics (admin only)"""
    admin_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total users
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Active users
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        active_users = cursor.fetchone()[0]
        
        # Total ideas
        cursor.execute("SELECT COUNT(*) FROM ideas WHERE is_deleted = FALSE")
        total_ideas = cursor.fetchone()[0] if cursor.description else 0

        # Total files
        cursor.execute("SELECT COUNT(*) FROM drive_files WHERE is_deleted = FALSE")
        total_files = cursor.fetchone()[0] if cursor.description else 0
        
        # Active sessions
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE is_active = TRUE AND expires_at > NOW()
            """
        )
        active_sessions = cursor.fetchone()[0]
        
        # Recent activity (last 24 hours)
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE created_at >= NOW() - INTERVAL '24 hours'
            """
        )
        recent_activity = cursor.fetchone()[0]
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'total_ideas': total_ideas,
            'total_files': total_files,
            'active_sessions': active_sessions,
            'recent_activity_24h': recent_activity
        }

    except Exception as e:
        logger.error(f"Error getting system stats: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system statistics"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/sessions/cleanup")
async def cleanup_sessions(current_user: dict = Depends(require_admin)):
    """
    Manually trigger session cleanup (admin only)

    Removes:
    - Expired sessions
    - Inactive sessions older than 7 days
    """
    admin_id = current_user["id"]
    from routers.auth import cleanup_expired_sessions

    conn = None

    try:
        deleted_count = cleanup_expired_sessions()

        # Log admin action
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            admin_id,
            "admin_session_cleanup",
            "success",
            None,
            {"sessions_deleted": deleted_count}
        )

        conn.commit()

        return {
            "message": "Session cleanup completed",
            "sessions_deleted": deleted_count
        }

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Session cleanup error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session cleanup failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/sessions/stats")
async def get_session_stats(current_user: dict = Depends(require_admin)):
    """
    Get session statistics (admin only)

    Returns:
    - Total active sessions
    - Expired sessions pending cleanup
    - Sessions by user
    - Session age distribution
    """
    admin_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Active sessions
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE is_active = TRUE AND expires_at > NOW()
            """
        )
        active_sessions = cursor.fetchone()[0]

        # Expired sessions
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE expires_at < NOW()
            """
        )
        expired_sessions = cursor.fetchone()[0]

        # Inactive sessions
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE is_active = FALSE
            """
        )
        inactive_sessions = cursor.fetchone()[0]

        # Sessions expiring soon (within 1 hour)
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_sessions
            WHERE is_active = TRUE
            AND expires_at > NOW()
            AND expires_at < NOW() + INTERVAL '1 hour'
            """
        )
        expiring_soon = cursor.fetchone()[0]

        # Total sessions
        cursor.execute("SELECT COUNT(*) FROM user_sessions")
        total_sessions = cursor.fetchone()[0]

        # Session age distribution
        cursor.execute(
            """
            SELECT
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as last_hour,
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as last_24h,
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '7 days' THEN 1 END) as last_7d
            FROM user_sessions
            WHERE is_active = TRUE AND expires_at > NOW()
            """
        )
        age_distribution = cursor.fetchone()

        return {
            "active_sessions": active_sessions,
            "expired_sessions": expired_sessions,
            "inactive_sessions": inactive_sessions,
            "expiring_soon": expiring_soon,
            "total_sessions": total_sessions,
            "age_distribution": {
                "last_hour": age_distribution[0],
                "last_24_hours": age_distribution[1],
                "last_7_days": age_distribution[2]
            }
        }

    except Exception as e:
        logger.error(f"Error getting session stats: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get session statistics"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/security-incidents")
async def get_security_incidents(
    current_user: dict = Depends(require_admin),
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get security incidents (admin only)

    Query parameters:
    - severity: Filter by severity (low, medium, high, critical)
    - incident_type: Filter by incident type
    - limit: Number of records to return (default 100)
    - offset: Pagination offset (default 0)
    """
    admin_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Build WHERE clause
        conditions = []
        params = []

        if severity:
            conditions.append("severity = %s")
            params.append(severity)

        if incident_type:
            conditions.append("incident_type = %s")
            params.append(incident_type)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Get incidents
        query = f"""
            SELECT si.id, si.user_id, u.username, u.email, si.incident_type,
                   si.severity, si.ip_address, si.endpoint, si.input_sample,
                   si.pattern_matched, si.details, si.created_at
            FROM security_incidents si
            LEFT JOIN users u ON si.user_id = u.id
            WHERE {where_clause}
            ORDER BY si.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        cursor.execute(query, params)

        incidents = []
        for row in cursor.fetchall():
            incidents.append({
                'id': row[0],
                'user_id': row[1],
                'username': row[2],
                'email': row[3],
                'incident_type': row[4],
                'severity': row[5],
                'ip_address': str(row[6]) if row[6] else None,
                'endpoint': row[7],
                'input_sample': row[8][:200] if row[8] else None,  # Truncate for display
                'pattern_matched': row[9],
                'details': row[10],
                'created_at': row[11].isoformat() if row[11] else None
            })

        # Get total count
        count_query = f"SELECT COUNT(*) FROM security_incidents WHERE {where_clause}"
        cursor.execute(count_query, params[:-2])  # Exclude limit and offset
        total = cursor.fetchone()[0]

        return {
            'incidents': incidents,
            'total': total,
            'limit': limit,
            'offset': offset
        }

    except Exception as e:
        logger.error(f"Error getting security incidents: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security incidents"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/security-summary")
async def get_security_summary(current_user: dict = Depends(require_admin)):
    """
    Get security summary statistics (admin only)

    Returns overview of:
    - Total incidents by severity
    - Recent incidents (last 24h)
    - Top attack types
    - Top targeted endpoints
    """
    admin_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Incidents by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM security_incidents
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """)
        incidents_by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        # Recent incidents (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*)
            FROM security_incidents
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """)
        recent_incidents = cursor.fetchone()[0]

        # Top attack types
        cursor.execute("""
            SELECT incident_type, COUNT(*) as count
            FROM security_incidents
            GROUP BY incident_type
            ORDER BY count DESC
            LIMIT 10
        """)
        top_attack_types = [{'type': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Top targeted endpoints
        cursor.execute("""
            SELECT endpoint, COUNT(*) as count
            FROM security_incidents
            WHERE endpoint IS NOT NULL
            GROUP BY endpoint
            ORDER BY count DESC
            LIMIT 10
        """)
        top_endpoints = [{'endpoint': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Recent audit logs count
        cursor.execute("""
            SELECT COUNT(*)
            FROM audit_logs
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """)
        recent_audit_logs = cursor.fetchone()[0]

        # Failed login attempts (last 24h)
        cursor.execute("""
            SELECT COUNT(*)
            FROM audit_logs
            WHERE action IN ('login', 'login_failed')
            AND status = 'failed'
            AND created_at >= NOW() - INTERVAL '24 hours'
        """)
        failed_logins = cursor.fetchone()[0]

        return {
            'incidents_by_severity': {
                'critical': incidents_by_severity.get('critical', 0),
                'high': incidents_by_severity.get('high', 0),
                'medium': incidents_by_severity.get('medium', 0),
                'low': incidents_by_severity.get('low', 0)
            },
            'recent_incidents_24h': recent_incidents,
            'recent_audit_logs_24h': recent_audit_logs,
            'failed_logins_24h': failed_logins,
            'top_attack_types': top_attack_types,
            'top_targeted_endpoints': top_endpoints
        }

    except Exception as e:
        logger.error(f"Error getting security summary: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security summary"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)