"""
utils/auth_dependencies.py
Authentication dependencies for route protection
Implements ISO 27001 A.8.5 Secure Authentication
"""

from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import RedirectResponse
from typing import Optional, Dict
import logging
from database.connection import get_db_connection, return_db_connection
from datetime import datetime
from utils.session_manager import session_manager

logger = logging.getLogger(__name__)


async def get_current_user_from_token(request: Request) -> Optional[Dict]:
    """
    Extract and validate user from session token
    Checks both cookies and Authorization header
    
    Returns:
        User dict if authenticated, None otherwise
    """
    # Try cookie first (for browser requests)
    token = request.cookies.get("session_token")
    
    # Fallback to Authorization header (for API requests)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    
    if not token:
        return None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify session token and get user data
        cursor.execute(
            """
            SELECT 
                u.id, u.username, u.email, u.first_name, u.last_name, 
                u.is_active, u.account_status, s.id as session_id
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s 
              AND s.is_active = TRUE
              AND s.expires_at > NOW()
            """,
            (token,)
        )
        
        result = cursor.fetchone()
        return_db_connection(conn)
        
        if not result:
            return None
        
        # Check account status (convert to bool to handle PostgreSQL boolean)
        if not bool(result[5]) or result[6] != 'active':
            logger.warning(f"Inactive account attempted access: user_id={result[0]}")
            return None
        
        return {
            "id": result[0],
            "username": result[1],
            "email": result[2],
            "first_name": result[3],
            "last_name": result[4],
            "is_active": result[5],
            "account_status": result[6],
            "session_id": result[7]
        }
        
    except Exception as e:
        logger.error(f"Error validating session token: {e}")
        return None


async def require_auth(request: Request) -> Dict:
    """
    Dependency that requires authentication
    Raises 401 if not authenticated
    
    Use for API endpoints that need authentication
    """
    user = await get_current_user_from_token(request)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return user


async def require_auth_page(request: Request) -> Dict:
    """
    Dependency for page routes that require authentication
    Redirects to /auth if not authenticated
    
    Use for HTML page endpoints
    """
    user = await get_current_user_from_token(request)
    
    if not user:
        # For page routes, redirect to login instead of 401
        return None
    
    return user


async def optional_auth(request: Request) -> Optional[Dict]:
    """
    Optional authentication dependency
    Returns user if authenticated, None otherwise
    Does not raise exception
    
    Use for endpoints that work with or without auth
    """
    return await get_current_user_from_token(request)


async def require_admin(request: Request) -> Dict:
    """
    Dependency that requires admin role
    Implements ISO 27001 A.8.2 Privileged Access Rights

    IDOR Prevention: Always checks users.is_admin flag from database
    """
    user = await require_auth(request)

    # CRITICAL: Always verify is_admin flag from database (not session data)
    # This prevents privilege escalation and IDOR attacks
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT is_admin, is_active, account_status, username
            FROM users
            WHERE id = %s
            """,
            (user['id'],)
        )

        result = cursor.fetchone()

        if not result:
            return_db_connection(conn)
            logger.error(f"User not found in database during admin check: user_id={user['id']}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )

        is_admin, is_active, account_status, username = result

        # Explicitly check is_admin flag (must be TRUE, not just truthy)
        # Convert to bool to handle PostgreSQL boolean type correctly
        if not bool(is_admin):
            # Log unauthorized admin access attempt
            from utils.audit import log_audit_event
            log_audit_event(
                cursor,
                user['id'],
                "unauthorized_admin_access_attempt",
                "failed",
                request.client.host if request.client else None,
                {
                    "path": str(request.url.path),
                    "username": username,
                    "is_admin": is_admin,
                    "reason": "is_admin flag is False or NULL"
                }
            )
            conn.commit()
            return_db_connection(conn)

            logger.warning(
                f"Non-admin user attempted admin access: "
                f"user_id={user['id']}, username={username}, "
                f"is_admin={is_admin}, path={request.url.path}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )

        # Also verify account is active
        if not bool(is_active) or account_status != 'active':
            return_db_connection(conn)
            logger.warning(
                f"Inactive admin account attempted access: "
                f"user_id={user['id']}, is_active={is_active}, "
                f"status={account_status}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active"
            )

        # Log successful admin access
        from utils.audit import log_audit_event
        log_audit_event(
            cursor,
            user['id'],
            "admin_access_granted",
            "success",
            request.client.host if request.client else None,
            {
                "path": str(request.url.path),
                "username": username
            }
        )
        conn.commit()
        return_db_connection(conn)

        user['is_admin'] = True
        user['username'] = username
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking admin privileges: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorization check failed"
        )


def invalidate_session(session_token: str) -> bool:
    """
    Invalidate a session token
    Implements ISO 27001 A.8.5 Secure Authentication - Session Management
    
    Args:
        session_token: Token to invalidate
        
    Returns:
        True if successful, False otherwise
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Mark session as inactive
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE,
                last_activity = NOW()
            WHERE session_token = %s
            RETURNING user_id
            """,
            (session_token,)
        )
        
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            
            # Log logout event
            from utils.audit import log_audit_event
            log_audit_event(
                cursor, user_id, "logout", "success",
                None, {"method": "manual"}
            )
        
        conn.commit()
        return_db_connection(conn)
        
        return True
        
    except Exception as e:
        logger.error(f"Error invalidating session: {e}")
        return False


def invalidate_all_user_sessions(user_id: int) -> bool:
    """
    Invalidate all sessions for a user
    Used for security events like password change
    
    Args:
        user_id: User ID
        
    Returns:
        True if successful, False otherwise
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE,
                last_activity = NOW()
            WHERE user_id = %s AND is_active = TRUE
            """,
            (user_id,)
        )
        
        count = cursor.rowcount
        
        # Log security event
        from utils.audit import log_audit_event
        log_audit_event(
            cursor, user_id, "all_sessions_invalidated", "success",
            None, {"sessions_count": count}
        )
        
        conn.commit()
        return_db_connection(conn)
        
        logger.info(f"Invalidated {count} sessions for user {user_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error invalidating all sessions: {e}")
        return False
