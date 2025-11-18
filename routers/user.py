"""
routers/user.py
User profile and account management routes
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import logging
import pyotp
import qrcode
import io
import base64
import secrets
import random
from datetime import datetime, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.security import (
    verify_session_token, hash_password, verify_password,
    check_password_strength, hash_token
)
from utils.audit import (
    log_audit_event, get_user_activity_summary,
    detect_suspicious_activity, AuditAction
)
from utils.email_service import send_verification_email, send_2fa_code_email
from utils.auth_dependencies import require_auth
from utils.input_sanitizer import (
    comprehensive_input_scan,
    validate_and_sanitize,
    log_malicious_input,
    MaliciousInputDetected
)

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# All routes in this router require authentication
# ISO 27001 A.8.3 Information Access Restriction

# Pydantic Models

class ProfileUpdate(BaseModel):
    """Model for updating user profile"""
    first_name: Optional[str] = Field(None, max_length=100, pattern=r'^[a-zA-Z\s-]+$')
    last_name: Optional[str] = Field(None, max_length=100, pattern=r'^[a-zA-Z\s-]+$')

class PasswordChange(BaseModel):
    """Model for password change"""
    current_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=14, max_length=128)

    @validator('new_password')
    def validate_password_strength(cls, v):
        strength = check_password_strength(v)
        if not strength['is_strong']:
            missing = []
            if not strength['has_uppercase']:
                missing.append('uppercase letter')
            if not strength['has_lowercase']:
                missing.append('lowercase letter')
            if not strength['has_digit']:
                missing.append('digit')
            if not strength['has_special']:
                missing.append('special character')
            raise ValueError(f'Password must contain: {", ".join(missing)}')
        return v

class EmailChange(BaseModel):
    """Model for email change"""
    new_email: EmailStr
    password: str = Field(..., max_length=128)

class MFASetupRequest(BaseModel):
    """Model for MFA setup"""
    mfa_method: str = Field(..., pattern=r'^(totp|email)$')
    password: str = Field(..., max_length=128)

class MFAVerifySetup(BaseModel):
    """Model for verifying MFA setup"""
    mfa_code: str = Field(..., pattern=r'^\d{6}$')

class MFADisable(BaseModel):
    """Model for disabling MFA"""
    password: str = Field(..., max_length=128)
    mfa_code: str = Field(..., pattern=r'^\d{6}$')

# Helper Functions

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """Verify user session and return user_id"""
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
        
        return user_id
        
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# User Endpoints

@router.get("/profile")
async def get_profile(current_user: dict = Depends(require_auth)):
    """Get current user's profile"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, email, username, first_name, last_name,
                   email_verified, is_admin, is_active, account_status,
                   created_at, last_login
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

        profile = {
            'id': result[0],
            'email': result[1],
            'username': result[2],
            'first_name': result[3],
            'last_name': result[4],
            'email_verified': result[5],
            'is_admin': result[6],
            'is_active': result[7],
            'account_status': result[8],
            'created_at': result[9].isoformat() if result[9] else None,
            'last_login': result[10].isoformat() if result[10] else None
        }
        
        # Get MFA status (new schema only supports TOTP)
        cursor.execute(
            """
            SELECT mfa_enabled, mfa_verified
            FROM user_mfa
            WHERE user_id = %s
            """,
            (user_id,)
        )

        mfa_result = cursor.fetchone()
        mfa_enabled_methods = []

        if mfa_result and mfa_result[0] and mfa_result[1]:
            # MFA is both enabled and verified
            mfa_enabled_methods.append('totp')

        profile['mfa_enabled'] = mfa_enabled_methods
        
        return profile
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting profile: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get profile"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.put("/profile")
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: dict = Depends(require_auth)
):
    """Update user profile"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build update query
        updates = []
        params = []
        
        if profile_data.first_name is not None:
            updates.append("first_name = %s")
            params.append(profile_data.first_name)
        
        if profile_data.last_name is not None:
            updates.append("last_name = %s")
            params.append(profile_data.last_name)

        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No updates provided"
            )
        
        updates.append("updated_at = NOW()")
        params.append(user_id)
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(query, params)
        
        log_audit_event(
            cursor, user_id, "profile_updated", "success",
            None, None
        )
        
        conn.commit()
        
        return {"message": "Profile updated successfully"}
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error updating profile: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/change-password")
@limiter.limit("5/hour")
async def change_password(
    password_data: PasswordChange,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Change user password (rate limited)
    ISO 27001 A.9.4.3 Password management system
    OWASP ASVS V2.1 Password Security Requirements
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else "unknown"
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ===== SECURITY VALIDATION LAYER 1: INPUT SANITIZATION =====

        # Scan current password for malicious patterns
        is_malicious_current, attack_type_current, pattern_current = comprehensive_input_scan(
            password_data.current_password
        )

        if is_malicious_current:
            log_malicious_input(
                user_id=user_id,
                input_value="[REDACTED PASSWORD]",
                attack_type=attack_type_current,
                pattern=pattern_current,
                ip_address=ip_address,
                endpoint="/api/v1/user/change-password",
                severity="high"
            )

            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "blocked",
                None, {
                    "reason": "malicious_input_detected",
                    "attack_type": attack_type_current,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            # Provide specific error message based on attack type
            if attack_type_current == "control_characters":
                error_message = "Current password contains invalid control characters. Only printable characters are allowed."
            else:
                error_message = "Current password contains potentially dangerous patterns. Please use only letters, numbers, and standard special characters."

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )

        # Scan new password for malicious patterns
        is_malicious_new, attack_type_new, pattern_new = comprehensive_input_scan(
            password_data.new_password
        )

        if is_malicious_new:
            log_malicious_input(
                user_id=user_id,
                input_value="[REDACTED PASSWORD]",
                attack_type=attack_type_new,
                pattern=pattern_new,
                ip_address=ip_address,
                endpoint="/api/v1/user/change-password",
                severity="high"
            )

            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "blocked",
                None, {
                    "reason": "malicious_input_detected",
                    "attack_type": attack_type_new,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            # Provide specific error message based on attack type
            if attack_type_new == "control_characters":
                error_message = "New password contains invalid control characters. Only printable characters are allowed."
            else:
                error_message = "New password contains potentially dangerous patterns. Please use only letters, numbers, and standard special characters."

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )

        # ===== SECURITY VALIDATION LAYER 2: PASSWORD REQUIREMENTS =====

        # Check password length (additional server-side check)
        if len(password_data.current_password) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password too long"
            )

        if len(password_data.new_password) < 14:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 14 characters"
            )

        if len(password_data.new_password) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password too long (max 128 characters)"
            )

        # Check passwords are not the same
        if password_data.current_password == password_data.new_password:
            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "failed",
                None, {
                    "reason": "same_password",
                    "ip_address": ip_address
                }
            )
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password"
            )

        # Additional password strength check (server-side)
        strength = check_password_strength(password_data.new_password)
        if not strength['is_strong']:
            missing = []
            if not strength['has_uppercase']:
                missing.append('uppercase letter')
            if not strength['has_lowercase']:
                missing.append('lowercase letter')
            if not strength['has_digit']:
                missing.append('digit')
            if not strength['has_special']:
                missing.append('special character')

            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "failed",
                None, {
                    "reason": "weak_password",
                    "missing_requirements": missing,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password must contain: {', '.join(missing)}"
            )

        # ===== SECURITY VALIDATION LAYER 3: USER VERIFICATION =====

        # Get current password hash and verify user status
        cursor.execute(
            """
            SELECT password_hash, is_active, account_status, email
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

        current_hash, is_active, account_status, user_email = result

        # Check if account is active
        if not is_active or account_status != 'active':
            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "blocked",
                None, {
                    "reason": "inactive_account",
                    "account_status": account_status,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active"
            )

        # Verify current password
        if not verify_password(password_data.current_password, current_hash):
            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "failed",
                None, {
                    "reason": "invalid_current_password",
                    "ip_address": ip_address
                }
            )
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )

        # ===== SECURITY VALIDATION LAYER 4: SUSPICIOUS ACTIVITY CHECK =====

        # Check for recent password change attempts
        cursor.execute(
            """
            SELECT COUNT(*) FROM audit_logs
            WHERE user_id = %s
            AND action = %s
            AND created_at > NOW() - INTERVAL '1 hour'
            """,
            (user_id, AuditAction.PASSWORD_CHANGED)
        )

        recent_attempts = cursor.fetchone()[0]
        if recent_attempts > 10:
            log_audit_event(
                cursor, user_id, AuditAction.PASSWORD_CHANGED, "blocked",
                None, {
                    "reason": "too_many_attempts",
                    "attempts": recent_attempts,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            logger.warning(f"Suspicious password change activity for user {user_id}: {recent_attempts} attempts in 1 hour")

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many password change attempts. Please try again later."
            )

        # ===== PASSWORD UPDATE =====

        # Hash new password with Argon2id
        new_hash = hash_password(password_data.new_password)

        # Update password in database
        cursor.execute(
            """
            UPDATE users
            SET password_hash = %s, updated_at = NOW()
            WHERE id = %s
            """,
            (new_hash, user_id)
        )

        # Invalidate ALL sessions for security (user must re-login)
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE
            WHERE user_id = %s
            """,
            (user_id,)
        )

        # Log successful password change
        log_audit_event(
            cursor, user_id, AuditAction.PASSWORD_CHANGED, "success",
            None, {
                "ip_address": ip_address,
                "user_agent": request.headers.get("user-agent", "unknown")[:200]
            }
        )

        conn.commit()

        logger.info(f"User {user_id} ({user_email}) successfully changed password from IP {ip_address}")

        return {
            "message": "Password changed successfully. Please log in again."
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error changing password for user {user_id}: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/sessions")
async def get_active_sessions(current_user: dict = Depends(require_auth)):
    """Get user's active sessions"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, created_at, last_activity, expires_at, user_agent
            FROM user_sessions
            WHERE user_id = %s AND is_active = TRUE AND expires_at > NOW()
            ORDER BY last_activity DESC
            """,
            (user_id,)
        )
        
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'id': row[0],
                'created_at': row[1].isoformat() if row[1] else None,
                'last_activity': row[2].isoformat() if row[2] else None,
                'expires_at': row[3].isoformat() if row[3] else None,
                'user_agent': row[4][:100] if row[4] else None  # Truncate for display
            })
        
        return {
            'sessions': sessions,
            'total': len(sessions)
        }
        
    except Exception as e:
        logger.error(f"Error getting sessions: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get sessions"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: int,
    current_user: dict = Depends(require_auth)
):
    """Revoke a specific session"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify session belongs to user
        cursor.execute(
            "SELECT user_id FROM user_sessions WHERE id = %s",
            (session_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        if result[0] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Revoke session
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE
            WHERE id = %s
            """,
            (session_id,)
        )
        
        conn.commit()
        
        return {"message": "Session revoked successfully"}
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error revoking session: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/activity")
async def get_activity(
    current_user: dict = Depends(require_auth),
    days: int = 30
):
    """Get user activity summary"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        activity = get_user_activity_summary(cursor, user_id, days)
        
        return activity
        
    except Exception as e:
        logger.error(f"Error getting activity: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get activity"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/security-check")
async def security_check(current_user: dict = Depends(require_auth)):
    """Check for suspicious activity on account"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        suspicious = detect_suspicious_activity(cursor, user_id)
        
        # Get password age
        cursor.execute(
            """
            SELECT updated_at
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )
        
        result = cursor.fetchone()
        password_age_days = None
        if result and result[0]:
            from datetime import datetime
            password_age = datetime.now() - result[0]
            password_age_days = password_age.days
        
        return {
            'suspicious_activity': suspicious,
            'password_age_days': password_age_days,
            'recommendations': []
        }
        
    except Exception as e:
        logger.error(f"Error in security check: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform security check"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/account")
async def delete_account(
    password: str,
    current_user: dict = Depends(require_auth)
):
    """Delete user account (requires password confirmation)"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify password
        cursor.execute(
            "SELECT password_hash, is_admin FROM users WHERE id = %s",
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        password_hash, is_admin = result
        
        if not verify_password(password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
        
        # Prevent deleting admin accounts this way
        if is_admin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admin accounts cannot be self-deleted. Contact another admin."
            )
        
        # Soft delete account
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
        
        log_audit_event(
            cursor, user_id, AuditAction.ACCOUNT_DELETED, "success",
            None, {"self_deleted": True}
        )
        
        conn.commit()
        
        logger.info(f"User {user_id} deleted their account")
        
        return {"message": "Account deleted successfully"}
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error deleting account: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


# Settings Endpoints

@router.post("/settings/change-email")
@limiter.limit("3/hour")
async def change_email(
    email_data: EmailChange,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Change user email (requires password confirmation and email verification)
    ISO 27001 A.9.2.4 Management of secret authentication information
    OWASP ASVS V2.1 Password Security Requirements
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else "unknown"
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ===== SECURITY VALIDATION LAYER 1: INPUT SANITIZATION =====

        # Scan new email for malicious patterns
        is_malicious_new, attack_type_new, pattern_new = comprehensive_input_scan(
            str(email_data.new_email)
        )
        if is_malicious_new:
            log_malicious_input(
                user_id=user_id,
                input_value=str(email_data.new_email),
                attack_type=attack_type_new,
                pattern=pattern_new,
                ip_address=ip_address,
                endpoint="/api/v1/user/settings/change-email",
                severity="high"
            )
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "blocked",
                None, {
                    "reason": "malicious_input_new_email",
                    "attack_type": attack_type_new,
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid new email format detected"
            )

        # Scan password for malicious patterns
        is_malicious_password, attack_type_password, pattern_password = comprehensive_input_scan(
            email_data.password
        )
        if is_malicious_password:
            log_malicious_input(
                user_id=user_id,
                input_value="[REDACTED PASSWORD]",
                attack_type=attack_type_password,
                pattern=pattern_password,
                ip_address=ip_address,
                endpoint="/api/v1/user/settings/change-email",
                severity="critical"
            )
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "blocked",
                None, {
                    "reason": "malicious_input_password",
                    "attack_type": attack_type_password,
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid input detected"
            )

        # ===== SECURITY VALIDATION LAYER 2: USER VERIFICATION =====

        # Get user data and verify account status
        cursor.execute(
            """
            SELECT password_hash, email, is_active, account_status
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

        password_hash, current_email_db, is_active, account_status = result

        # Check if account is active
        if not is_active or account_status != 'active':
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "blocked",
                None, {
                    "reason": "inactive_account",
                    "account_status": account_status,
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active"
            )

        # Check if new email is same as current email
        if current_email_db.lower() == str(email_data.new_email).lower():
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "failed",
                None, {
                    "reason": "same_email",
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New email must be different from current email"
            )

        # Verify password with Argon2id
        if not verify_password(email_data.password, password_hash):
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "failed",
                None, {
                    "reason": "invalid_password",
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )

        # ===== SECURITY VALIDATION LAYER 3: EMAIL VALIDATION =====

        # Check if new email already exists
        cursor.execute(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(%s) AND id != %s",
            (str(email_data.new_email), user_id)
        )

        if cursor.fetchone():
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "failed",
                None, {
                    "reason": "email_already_exists",
                    "ip_address": ip_address
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use"
            )

        # ===== SECURITY VALIDATION LAYER 4: RATE LIMITING CHECK =====

        # Check for recent email change attempts
        cursor.execute(
            """
            SELECT COUNT(*) FROM audit_logs
            WHERE user_id = %s
            AND action = %s
            AND created_at > NOW() - INTERVAL '1 hour'
            """,
            (user_id, AuditAction.EMAIL_CHANGED)
        )

        recent_attempts = cursor.fetchone()[0]
        if recent_attempts > 5:
            log_audit_event(
                cursor, user_id, AuditAction.EMAIL_CHANGED, "blocked",
                None, {
                    "reason": "too_many_attempts",
                    "attempts": recent_attempts,
                    "ip_address": ip_address
                }
            )
            conn.commit()
            logger.warning(f"Suspicious email change activity for user {user_id}: {recent_attempts} attempts in 1 hour")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many email change attempts. Please try again later."
            )

        # ===== EMAIL CHANGE =====

        # Generate email verification token
        verification_token = secrets.token_urlsafe(32)
        token_hash = hash_token(verification_token)
        expires_at = datetime.now() + timedelta(hours=24)

        # Store pending email change
        cursor.execute(
            """
            INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, token_hash, expires_at)
        )

        # Update email (mark as unverified for security)
        cursor.execute(
            """
            UPDATE users
            SET email = %s, email_verified = FALSE, updated_at = NOW()
            WHERE id = %s
            """,
            (str(email_data.new_email), user_id)
        )

        # Invalidate all sessions for security (user must re-login)
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE
            WHERE user_id = %s
            """,
            (user_id,)
        )

        # Log successful email change
        log_audit_event(
            cursor, user_id, AuditAction.EMAIL_CHANGED, "success",
            None, {
                "old_email": current_email_db,
                "new_email": str(email_data.new_email),
                "ip_address": ip_address,
                "user_agent": request.headers.get("user-agent", "unknown")[:200]
            }
        )

        conn.commit()

        # Send verification email
        try:
            send_verification_email(str(email_data.new_email), verification_token, None)
        except Exception as email_error:
            logger.error(f"Failed to send verification email: {email_error}")
            # Don't fail the request if email fails

        logger.info(f"User {user_id} changed email from {current_email_db} to {email_data.new_email} from IP {ip_address}")

        return {
            "message": "Email changed successfully. Please check your new email for verification link and log in again."
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error changing email for user {user_id}: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change email"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/settings/mfa/setup")
@limiter.limit("5/hour")
async def setup_mfa(
    mfa_data: MFASetupRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Setup MFA (TOTP or Email)

    TODO: This endpoint needs refactoring for new MFA schema
    Use /api/v1/auth/mfa/setup instead (in auth.py)
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="MFA setup temporarily disabled. Use /api/v1/auth/mfa/setup endpoint instead."
    )

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify password
        cursor.execute(
            "SELECT password_hash, email, username FROM users WHERE id = %s",
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        password_hash, email, username = result
        
        if not verify_password(mfa_data.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
        
        # Check if MFA already enabled
        cursor.execute(
            """
            SELECT id FROM user_mfa
            WHERE user_id = %s AND mfa_method = %s AND is_enabled = TRUE
            """,
            (user_id, mfa_data.mfa_method)
        )
        
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{mfa_data.mfa_method.upper()} MFA already enabled"
            )
        
        if mfa_data.mfa_method == 'totp':
            # Generate TOTP secret
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            
            # Generate QR code
            provisioning_uri = totp.provisioning_uri(
                name=email,
                issuer_name="Genesis AI"
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            # Store MFA setup (not enabled yet - needs verification)
            cursor.execute(
                """
                INSERT INTO user_mfa (user_id, mfa_method, secret_key, is_enabled)
                VALUES (%s, %s, %s, FALSE)
                ON CONFLICT (user_id, mfa_method) DO UPDATE
                SET secret_key = EXCLUDED.secret_key, is_enabled = FALSE
                """,
                (user_id, 'totp', secret)
            )
            
            conn.commit()
            
            return {
                "message": "TOTP MFA setup initiated. Scan QR code with your authenticator app.",
                "mfa_method": "totp",
                "secret": secret,
                "qr_code": f"data:image/png;base64,{qr_code_base64}",
                "provisioning_uri": provisioning_uri
            }
            
        else:  # email
            # Generate and send verification code
            mfa_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            mfa_code_hash = hash_password(mfa_code)
            mfa_code_expires_at = datetime.now() + timedelta(minutes=15)
            
            # Store MFA setup (not enabled yet - needs verification)
            cursor.execute(
                """
                INSERT INTO user_mfa (user_id, mfa_method, mfa_code_hash, mfa_code_expires_at, is_enabled)
                VALUES (%s, %s, %s, %s, FALSE)
                ON CONFLICT (user_id, mfa_method) DO UPDATE
                SET mfa_code_hash = EXCLUDED.mfa_code_hash,
                    mfa_code_expires_at = EXCLUDED.mfa_code_expires_at,
                    is_enabled = FALSE
                """,
                (user_id, 'email', mfa_code_hash, mfa_code_expires_at)
            )
            
            conn.commit()
            
            # Send code via email
            send_2fa_code_email(email, mfa_code, username)
            
            return {
                "message": "Email MFA setup initiated. Check your email for verification code.",
                "mfa_method": "email"
            }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error setting up MFA: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup MFA"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/settings/mfa/verify")
@limiter.limit("10/hour")
async def verify_mfa_setup(
    verify_data: MFAVerifySetup,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Verify and enable MFA

    TODO: This endpoint needs refactoring for new MFA schema
    Use /api/v1/auth/mfa/enable instead (in auth.py)
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="MFA verify temporarily disabled. Use /api/v1/auth/mfa/enable endpoint instead."
    )

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get MFA setup
        cursor.execute(
            """
            SELECT mfa_method, secret_key, mfa_code_hash, mfa_code_expires_at
            FROM user_mfa
            WHERE user_id = %s AND is_enabled = FALSE
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No MFA setup found. Please initiate setup first."
            )
        
        mfa_method, secret_key, mfa_code_hash, mfa_code_expires_at = result
        
        if mfa_method == 'totp':
            # Verify TOTP code
            totp = pyotp.TOTP(secret_key)
            if not totp.verify(verify_data.mfa_code, valid_window=1):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authenticator code"
                )
        else:  # email
            # Check expiry
            if datetime.now() > mfa_code_expires_at:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Verification code expired. Please request a new one."
                )
            
            # Verify code
            if not verify_password(verify_data.mfa_code, mfa_code_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid verification code"
                )
        
        # Enable MFA
        cursor.execute(
            """
            UPDATE user_mfa
            SET is_enabled = TRUE, mfa_code_hash = NULL, mfa_code_expires_at = NULL
            WHERE user_id = %s AND mfa_method = %s
            """,
            (user_id, mfa_method)
        )
        
        log_audit_event(
            cursor, user_id, "mfa_enabled", "success",
            None, {"mfa_method": mfa_method}
        )
        
        conn.commit()
        
        logger.info(f"User {user_id} enabled {mfa_method} MFA")
        
        return {
            "message": f"{mfa_method.upper()} MFA enabled successfully",
            "mfa_method": mfa_method
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error verifying MFA: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/settings/mfa/disable")
@limiter.limit("5/hour")
async def disable_mfa(
    disable_data: MFADisable,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Disable MFA (requires password and MFA code)

    TODO: This endpoint needs refactoring for new MFA schema
    Contact admin to disable MFA for now
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="MFA disable temporarily unavailable. Contact admin for assistance."
    )

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify password
        cursor.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not verify_password(disable_data.password, result[0]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
        
        # Get enabled MFA
        cursor.execute(
            """
            SELECT mfa_method, secret_key
            FROM user_mfa
            WHERE user_id = %s AND is_enabled = TRUE
            LIMIT 1
            """,
            (user_id,)
        )
        
        mfa_record = cursor.fetchone()
        if not mfa_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not enabled"
            )
        
        mfa_method, secret_key = mfa_record
        
        # Verify MFA code
        if mfa_method == 'totp':
            totp = pyotp.TOTP(secret_key)
            if not totp.verify(disable_data.mfa_code, valid_window=1):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )
        
        # Disable MFA
        cursor.execute(
            """
            UPDATE user_mfa
            SET is_enabled = FALSE
            WHERE user_id = %s AND mfa_method = %s
            """,
            (user_id, mfa_method)
        )
        
        log_audit_event(
            cursor, user_id, "mfa_disabled", "success",
            None, {"mfa_method": mfa_method}
        )
        
        conn.commit()
        
        logger.info(f"User {user_id} disabled {mfa_method} MFA")
        
        return {
            "message": "MFA disabled successfully"
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error disabling MFA: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/settings/mfa/status")
async def get_mfa_status(current_user: dict = Depends(require_auth)):
    """Get MFA status for user (TOTP only in new schema)"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT mfa_enabled, mfa_verified, created_at
            FROM user_mfa
            WHERE user_id = %s
            """,
            (user_id,)
        )

        result = cursor.fetchone()
        mfa_methods = []

        if result:
            mfa_enabled, mfa_verified, created_at = result
            if mfa_enabled and mfa_verified:
                mfa_methods.append({
                    "method": "totp",
                    "enabled": True,
                    "setup_date": created_at.isoformat() if created_at else None
                })

        return {
            "mfa_methods": mfa_methods,
            "mfa_enabled": len(mfa_methods) > 0
        }

    except Exception as e:
        logger.error(f"Error getting MFA status: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get MFA status"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


# ============================================================================
# API Key Management Routes
# ============================================================================

class APIKeyUpdate(BaseModel):
    """Model for saving API keys"""
    gemini_api_key: Optional[str] = Field(None, max_length=500)
    aimlapi_key: Optional[str] = Field(None, max_length=500)


@router.post("/settings/api-keys")
@limiter.limit("10/hour")
async def save_api_keys(
    request: Request,
    api_keys: APIKeyUpdate,
    current_user: dict = Depends(require_auth)
):
    """
    Save user's API keys with double encryption

    Security:
    - Double-encrypted with user's encryption key
    - Keys never stored in plaintext
    - Each user has their own isolated keys
    - Rate limited to prevent abuse
    """
    user_id = current_user["id"]

    try:
        from utils.api_key_crypto import save_user_api_key

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encrypted encryption key
        cursor.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        return_db_connection(conn)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user_encrypted_key = result[0]
        saved_keys = []

        # Save Gemini API key if provided
        if api_keys.gemini_api_key:
            # Validate input for malicious patterns (but don't log API keys - they're sensitive!)
            # API keys should not contain malicious patterns, but we validate for security
            is_malicious, attack_type, pattern = comprehensive_input_scan(api_keys.gemini_api_key)
            if is_malicious:
                # Log incident without the actual API key
                logger.warning(f"Suspicious input detected in Gemini API key for user {user_id}: {attack_type}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid API key format"
                )

            if save_user_api_key(user_id, 'gemini', api_keys.gemini_api_key, user_encrypted_key):
                saved_keys.append('gemini')

        # Save AIMLAPI key if provided
        if api_keys.aimlapi_key:
            # Validate input for malicious patterns (but don't log API keys - they're sensitive!)
            is_malicious, attack_type, pattern = comprehensive_input_scan(api_keys.aimlapi_key)
            if is_malicious:
                # Log incident without the actual API key
                logger.warning(f"Suspicious input detected in AIMLAPI key for user {user_id}: {attack_type}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid API key format"
                )

            if save_user_api_key(user_id, 'aimlapi', api_keys.aimlapi_key, user_encrypted_key):
                saved_keys.append('aimlapi')

        if not saved_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No API keys provided or failed to save"
            )

        # Log audit event
        try:
            audit_conn = get_db_connection()
            audit_cursor = audit_conn.cursor()
            log_audit_event(
                audit_cursor,
                user_id=user_id,
                action='api_keys_updated',
                status='success',
                ip_address=request.client.host if request.client else None,
                details={'keys_updated': saved_keys}
            )
            audit_conn.commit()
            audit_cursor.close()
            return_db_connection(audit_conn)
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        return {
            "success": True,
            "message": f"Successfully saved {len(saved_keys)} API key(s)",
            "saved_keys": saved_keys
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"Error saving API keys: {type(e).__name__} - {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save API keys: {str(e)}"
        )


@router.get("/settings/api-keys/status")
async def get_api_keys_status(current_user: dict = Depends(require_auth)):
    """
    Check which API keys the user has configured

    Returns:
        Dictionary indicating which keys are set up
    """
    user_id = current_user["id"]

    try:
        from utils.api_key_crypto import check_user_has_api_keys

        api_keys_status = check_user_has_api_keys(user_id)

        return {
            "api_keys": api_keys_status,
            "has_all_keys": api_keys_status['gemini'] and api_keys_status['aimlapi']
        }

    except Exception as e:
        logger.error(f"Error getting API keys status: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get API keys status"
        )


@router.delete("/settings/api-keys/{api_key_type}")
@limiter.limit("10/hour")
async def delete_api_key(
    request: Request,
    api_key_type: str,
    current_user: dict = Depends(require_auth)
):
    """
    Delete (deactivate) a user's API key

    Args:
        api_key_type: Either 'gemini' or 'aimlapi'
    """
    user_id = current_user["id"]

    if api_key_type not in ['gemini', 'aimlapi']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid API key type. Must be 'gemini' or 'aimlapi'"
        )

    try:
        from utils.api_key_crypto import delete_user_api_key

        if delete_user_api_key(user_id, api_key_type):
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='api_key_deleted',
                details=f"Deleted {api_key_type} API key",
                ip_address=request.client.host if request.client else None
            )

            return {
                "success": True,
                "message": f"Successfully deleted {api_key_type} API key"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No {api_key_type} API key found"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete API key"
        )
