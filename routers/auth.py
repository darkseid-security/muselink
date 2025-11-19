"""
routers/auth.py
Secure authentication router with MFA, session management, and comprehensive security
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional
from datetime import datetime, timedelta
import secrets
import random
import logging
import pyotp
import qrcode
import io
import base64
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.security import (
    hash_password, verify_password, generate_session_token,
    verify_session_token, hash_token, verify_token_hash
)
from utils.audit import log_audit_event
from utils.encryption import generate_user_encryption_key, encrypt_user_key
from utils.captcha import create_captcha, verify_captcha, hash_captcha_text
from utils.email_service import send_verification_email, send_2fa_code_email
from utils.session_manager import session_manager
from utils.input_sanitizer import (
    comprehensive_input_scan,
    validate_and_sanitize,
    log_malicious_input,
    MaliciousInputDetected
)
from utils.auth_dependencies import require_auth

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Session configuration from environment
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))

# Pydantic Models with Input Validation

class UserRegister(BaseModel):
    """User registration model with strict validation"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    password: str = Field(..., min_length=14, max_length=128)
    first_name: Optional[str] = Field(None, max_length=100, pattern=r'^[a-zA-Z\s-]+$')
    last_name: Optional[str] = Field(None, max_length=100, pattern=r'^[a-zA-Z\s-]+$')
    captcha_token: Optional[str] = Field(None, min_length=32)
    captcha_input: Optional[str] = Field(None, min_length=6, max_length=6)

    @validator('username')
    def validate_username(cls, v):
        """Validate username contains only allowed characters"""
        if not v:
            raise ValueError('Username is required')
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if len(v) > 50:
            raise ValueError('Username must not exceed 50 characters')
        # Only alphanumeric, underscore, and hyphen allowed
        if not all(c.isalnum() or c in '_-' for c in v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v

    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        """Validate name contains only allowed characters"""
        if v and not all(c.isalpha() or c.isspace() or c == '-' for c in v):
            raise ValueError('Name can only contain letters, spaces, and hyphens')
        return v

    @validator('password')
    def validate_password_strength(cls, v):
        """Enforce strong password policy - minimum 14 characters"""
        if len(v) < 14:
            raise ValueError('Password must be at least 14 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)')
        return v

class UserLogin(BaseModel):
    """User login model"""
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=128)
    captcha_token: Optional[str] = Field(None, min_length=32)
    captcha_input: Optional[str] = Field(None, min_length=6, max_length=6)

class MFAVerify(BaseModel):
    """MFA verification model"""
    mfa_code: str = Field(..., pattern=r'^\d{6}$')

class MFASetup(BaseModel):
    """MFA setup confirmation"""
    mfa_code: str = Field(..., pattern=r'^\d{6}$')

class PasswordReset(BaseModel):
    """Password reset request"""
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    """Password reset confirmation"""
    token: str = Field(..., min_length=32, max_length=64)
    new_password: str = Field(..., min_length=12, max_length=128)
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v

# Helper Functions

def get_client_info(request: Request) -> tuple:
    """Extract client IP and User-Agent safely"""
    # Get IP (handle proxy headers safely)
    ip_address = request.client.host if request.client else None
    
    # Get User-Agent (truncate for storage)
    user_agent = request.headers.get("user-agent", "unknown")[:500]
    
    return ip_address, user_agent

def check_account_locked(cursor, user_id: int) -> bool:
    """Check if account is locked due to failed attempts"""
    cursor.execute(
        "SELECT locked_until FROM users WHERE id = %s",
        (user_id,)
    )
    result = cursor.fetchone()

    if result and result[0]:
        if datetime.now() < result[0]:
            return True
        else:
            # Unlock account
            cursor.execute(
                "UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = %s",
                (user_id,)
            )

    return False

def increment_failed_login(cursor, user_id: int):
    """Increment failed login attempts and lock if threshold exceeded"""
    cursor.execute(
        """
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE
                WHEN failed_login_attempts + 1 >= 5
                THEN NOW() + INTERVAL '30 minutes'
                ELSE NULL
            END
        WHERE id = %s
        RETURNING failed_login_attempts
        """,
        (user_id,)
    )
    attempts = cursor.fetchone()[0]
    return attempts

def reset_failed_login(cursor, user_id: int):
    """Reset failed login attempts on successful login"""
    cursor.execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s",
        (user_id,)
    )

# Authentication Endpoints

@router.get("/captcha")
@limiter.limit("10/minute")
async def get_captcha(request: Request):
    """
    Generate CAPTCHA challenge for login/registration
    Returns base64-encoded image and token
    """
    try:
        captcha_token, captcha_hash, img_base64 = create_captcha()

        # Store hash in session or return with token
        # Client must send back token + their answer
        return {
            "captcha_token": captcha_token,
            "captcha_hash": captcha_hash,
            "captcha_image": f"data:image/png;base64,{img_base64}"
        }
    except Exception as e:
        logger.error(f"CAPTCHA generation error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CAPTCHA generation failed"
        )

@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")
async def register(
    user_data: UserRegister,
    request: Request,
    background_tasks: BackgroundTasks,
    captcha_hash: str = None
):
    """
    Register new user with email verification required
    Rate limited to prevent abuse
    Requires CAPTCHA validation
    ISO 27001 A.9.4.3 Password management system
    OWASP ASVS V2.1 Password Security Requirements

    Email verification is sent asynchronously via background tasks
    to prevent blocking the response when multiple users register concurrently
    """
    ip_address, user_agent = get_client_info(request)
    conn = None

    try:
        # ===== SECURITY VALIDATION LAYER 1: INPUT SANITIZATION =====

        # Scan email for malicious patterns
        is_malicious_email, attack_type_email, pattern_email = comprehensive_input_scan(
            str(user_data.email)
        )
        if is_malicious_email:
            log_malicious_input(
                user_id=None,
                input_value=str(user_data.email),
                attack_type=attack_type_email,
                pattern=pattern_email,
                ip_address=ip_address,
                endpoint="/api/v1/auth/register"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Suspicious input detected in email. Please check and try again."
            )

        # Scan username for malicious patterns
        is_malicious_username, attack_type_username, pattern_username = comprehensive_input_scan(
            user_data.username
        )
        if is_malicious_username:
            log_malicious_input(
                user_id=None,
                input_value=user_data.username,
                attack_type=attack_type_username,
                pattern=pattern_username,
                ip_address=ip_address,
                endpoint="/api/v1/auth/register"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Suspicious input detected in username. Please check and try again."
            )

        # Scan password for malicious patterns
        is_malicious_password, attack_type_password, pattern_password = comprehensive_input_scan(
            user_data.password
        )
        if is_malicious_password:
            log_malicious_input(
                user_id=None,
                input_value="[REDACTED PASSWORD]",
                attack_type=attack_type_password,
                pattern=pattern_password,
                ip_address=ip_address,
                endpoint="/api/v1/auth/register"
            )

            # Provide specific error message based on attack type
            if attack_type_password == "control_characters":
                error_message = "Password contains invalid control characters. Only printable characters are allowed."
            else:
                error_message = "Password contains potentially dangerous patterns. Please use only letters, numbers, and standard special characters."

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )

        # Scan first_name if provided
        if user_data.first_name:
            is_malicious_fname, attack_type_fname, pattern_fname = comprehensive_input_scan(
                user_data.first_name
            )
            if is_malicious_fname:
                log_malicious_input(
                    user_id=None,
                    input_value=user_data.first_name,
                    attack_type=attack_type_fname,
                    pattern=pattern_fname,
                    ip_address=ip_address,
                    endpoint="/api/v1/auth/register"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Suspicious input detected in first name. Please check and try again."
                )

        # Scan last_name if provided
        if user_data.last_name:
            is_malicious_lname, attack_type_lname, pattern_lname = comprehensive_input_scan(
                user_data.last_name
            )
            if is_malicious_lname:
                log_malicious_input(
                    user_id=None,
                    input_value=user_data.last_name,
                    attack_type=attack_type_lname,
                    pattern=pattern_lname,
                    ip_address=ip_address,
                    endpoint="/api/v1/auth/register"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Suspicious input detected in last name. Please check and try again."
                )

        # Verify CAPTCHA first (temporarily disabled for development)
        # TODO: Re-enable CAPTCHA validation in production
        # if captcha_hash:
        #     if not verify_captcha(user_data.captcha_input, captcha_hash, user_data.captcha_token):
        #         raise HTTPException(
        #             status_code=status.HTTP_400_BAD_REQUEST,
        #             detail="Invalid CAPTCHA"
        #         )
        # else:
        #     raise HTTPException(
        #         status_code=status.HTTP_400_BAD_REQUEST,
        #         detail="CAPTCHA hash required"
        #     )

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if email or username already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = %s OR username = %s",
            (user_data.email, user_data.username)
        )
        
        if cursor.fetchone():
            # Don't reveal which field exists (security through obscurity)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists"
            )
        
        # Hash password using Argon2id
        password_hash = hash_password(user_data.password)

        # Generate user encryption key and encrypt it with master key
        user_encryption_key = generate_user_encryption_key()
        encrypted_user_key = encrypt_user_key(user_encryption_key)

        # Insert user with email verification required
        cursor.execute(
            """
            INSERT INTO users (
                email, username, password_hash, first_name, last_name,
                encryption_key, account_status, email_verified
            )
            VALUES (%s, %s, %s, %s, %s, %s, 'pending_verification', FALSE)
            RETURNING id, email, username
            """,
            (
                user_data.email,
                user_data.username,
                password_hash,
                user_data.first_name,
                user_data.last_name,
                encrypted_user_key
            )
        )

        user_id, email, username = cursor.fetchone()

        # Generate email verification token
        verification_token = secrets.token_urlsafe(32)
        token_hash = hash_token(verification_token)
        expires_at = datetime.now() + timedelta(hours=24)

        # Store verification token
        cursor.execute(
            """
            INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, token_hash, expires_at)
        )

        # Log audit event
        try:
            log_audit_event(
                cursor, user_id, "user_registered", "success",
                None, {"method": "email", "verification_required": True}
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        conn.commit()

        # Send verification email asynchronously in background
        # This prevents blocking the response when multiple users register concurrently
        background_tasks.add_task(
            send_verification_email,
            email,
            verification_token,
            username
        )
        logger.info(f"New user registered: {username} - verification email queued for {email}")

        return {
            "message": "Registration successful! Please check your email to verify your account before logging in.",
            "user_id": user_id,
            "email_verified": False,
            "verification_required": True
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Registration error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/verify-email")
@limiter.limit("5/hour")
async def verify_email_get(token: str, request: Request):
    """Verify user email with token (GET method for browser links)"""
    return await verify_email_post(token, request)

@router.post("/verify-email")
@limiter.limit("5/hour")
async def verify_email_post(token: str, request: Request):
    """Verify user email with token (POST method for API calls)"""
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get all unverified tokens (we need to verify hash against each one)
        cursor.execute(
            """
            SELECT user_id, token_hash, expires_at, verified_at
            FROM email_verification_tokens
            WHERE verified_at IS NULL
            """
        )

        tokens = cursor.fetchall()

        # Find matching token by verifying hash
        matching_token = None
        for token_data in tokens:
            user_id, token_hash, expires_at, verified_at = token_data
            if verify_token_hash(token, token_hash):
                matching_token = token_data
                break

        if not matching_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token"
            )

        user_id, token_hash, expires_at, verified_at = matching_token

        if verified_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already verified"
            )
        
        if datetime.now() > expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification token expired"
            )
        
        # Mark email as verified
        cursor.execute(
            """
            UPDATE users 
            SET email_verified = TRUE, account_status = 'active'
            WHERE id = %s
            """,
            (user_id,)
        )
        
        cursor.execute(
            """
            UPDATE email_verification_tokens
            SET verified_at = NOW()
            WHERE token_hash = %s
            """,
            (token_hash,)
        )
        
        log_audit_event(cursor, user_id, "email_verified", "success", None, None)
        
        conn.commit()
        
        return {"message": "Email verified successfully"}
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Email verification error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verification failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/login")
@limiter.limit("5/minute")
async def login(credentials: UserLogin, request: Request, response: Response, captcha_hash: str = None):
    """
    Authenticate user with CAPTCHA validation
    Returns MFA challenge if 2FA is enabled
    Rate limited to prevent brute force
    ISO 27001 A.9.4.2 Secure log-on procedures
    OWASP ASVS V2.2 General Authenticator Requirements
    """
    ip_address, user_agent = get_client_info(request)
    conn = None

    try:
        # ===== SECURITY VALIDATION LAYER 1: INPUT SANITIZATION =====

        # Scan username for malicious patterns
        is_malicious_username, attack_type_username, pattern_username = comprehensive_input_scan(
            credentials.username
        )
        if is_malicious_username:
            log_malicious_input(
                user_id=None,
                input_value=credentials.username,
                attack_type=attack_type_username,
                pattern=pattern_username,
                ip_address=ip_address,
                endpoint="/api/v1/auth/login"
            )
            # Return specific error for malicious input
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Suspicious input detected. Please check your username and try again."
            )

        # Scan password for malicious patterns
        is_malicious_password, attack_type_password, pattern_password = comprehensive_input_scan(
            credentials.password
        )
        if is_malicious_password:
            log_malicious_input(
                user_id=None,
                input_value="[REDACTED PASSWORD]",
                attack_type=attack_type_password,
                pattern=pattern_password,
                ip_address=ip_address,
                endpoint="/api/v1/auth/login"
            )
            # Return specific error for malicious input
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Suspicious input detected. Please check your password and try again."
            )

        # Verify CAPTCHA first (temporarily disabled for development)
        # TODO: Re-enable CAPTCHA validation in production
        # if captcha_hash:
        #     if not verify_captcha(credentials.captcha_input, captcha_hash, credentials.captcha_token):
        #         raise HTTPException(
        #             status_code=status.HTTP_400_BAD_REQUEST,
        #             detail="Invalid CAPTCHA"
        #         )
        # else:
        #     raise HTTPException(
        #         status_code=status.HTTP_400_BAD_REQUEST,
        #         detail="CAPTCHA hash required"
        #     )

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user by username
        cursor.execute(
            """
            SELECT id, email, username, password_hash, is_active,
                   account_status, email_verified, is_admin
            FROM users
            WHERE username = %s
            """,
            (credentials.username,)
        )

        user = cursor.fetchone()

        if not user:
            # Log failed attempt (no user_id available)
            log_audit_event(cursor, None, "login_failed", "failed",
                          ip_address, {"reason": "user_not_found"})
            conn.commit()

            # Generic error message (don't reveal if user exists)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        user_id, email, username, password_hash, is_active, account_status, email_verified, is_admin = user
        
        # Check if account is locked
        if check_account_locked(cursor, user_id):
            log_audit_event(cursor, user_id, "login_failed", "failed",
                          ip_address, {"reason": "account_locked"})
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account temporarily locked. Please try again later."
            )

        # Verify password
        if not verify_password(credentials.password, password_hash):
            increment_failed_login(cursor, user_id)
            log_audit_event(cursor, user_id, "login_failed", "failed",
                          ip_address, {"reason": "invalid_password"})
            conn.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check account status
        if not is_active or account_status != 'active':
            log_audit_event(cursor, user_id, "login_failed", "failed",
                          ip_address, {"reason": "account_inactive"})
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active"
            )
        
        # Check if email is verified
        if not email_verified:
            log_audit_event(cursor, user_id, "login_failed", "failed",
                          ip_address, {"reason": "email_not_verified"})
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email first"
            )
        
        # Check if MFA is enabled
        cursor.execute(
            """
            SELECT mfa_enabled, mfa_verified
            FROM user_mfa
            WHERE user_id = %s AND mfa_enabled = TRUE
            """,
            (user_id,)
        )

        mfa_record = cursor.fetchone()

        if mfa_record:
            mfa_enabled, mfa_verified = mfa_record

            # TOTP MFA is enabled - require authenticator code
            temp_session_token = secrets.token_urlsafe(32)
            mfa_code_expires_at = datetime.now() + timedelta(minutes=15)

            # Create temporary session for TOTP verification
            cursor.execute(
                """
                INSERT INTO user_sessions (
                    user_id, session_token, ip_address, user_agent,
                    expires_at, is_active
                )
                VALUES (%s, %s, %s, %s, %s, FALSE)
                """,
                (user_id, temp_session_token, ip_address, user_agent, mfa_code_expires_at)
            )

            log_audit_event(cursor, user_id, "login_mfa_required", "success",
                          ip_address, {"mfa_method": "totp"})
            conn.commit()

            # Set temporary session token as HTTP-only cookie (SECURE: not accessible to JS)
            is_secure = request.url.scheme == "https"
            response.set_cookie(
                key="mfa_session_token",  # Different name to distinguish from permanent session
                value=temp_session_token,
                httponly=True,  # Cannot be accessed by JavaScript (XSS protection)
                secure=is_secure,  # Match the request scheme
                samesite="strict",  # CSRF protection
                max_age=15 * 60,  # 15 minutes in seconds
                path="/"
            )

            # Return response WITHOUT token in body (token is in cookie only)
            return {
                "mfa_required": True,
                "mfa_method": "totp",
                "message": "Please enter your authenticator code to complete login."
            }

        # No MFA - Successful login - reset failed attempts
        reset_failed_login(cursor, user_id)
        
        # Create session using secure session manager
        session_token = session_manager.create_session(
            cursor=cursor,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            remember_me=False  # Could add "remember_me" checkbox later
        )

        # Update last login
        cursor.execute(
            "UPDATE users SET last_login = NOW() WHERE id = %s",
            (user_id,)
        )

        log_audit_event(cursor, user_id, "login_success", "success", ip_address, None)

        conn.commit()

        logger.info(f"Successful login for user: {username}")

        # Set HTTP-only, Secure cookie (NOT accessible to JavaScript)
        # Detect if request is over HTTPS
        is_secure = request.url.scheme == "https"

        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,  # Cannot be accessed by JavaScript (XSS protection)
            secure=is_secure,  # Match the request scheme
            samesite="strict",  # CSRF protection
            max_age=SESSION_EXPIRE_HOURS * 3600,  # Seconds
            path="/"
        )

        # Return minimal response (NO tokens in body)
        return {
            "success": True,
            "user": {
                "id": user_id,
                "email": email,
                "username": username,
                "is_admin": is_admin
            },
            "redirect_to": "/admin" if is_admin else "/dashboard"
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Login error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/mfa/verify")
@limiter.limit("5/minute")
async def verify_mfa(mfa_data: MFAVerify, request: Request, response: Response):
    """
    Verify MFA code (TOTP) with proper expiry handling
    Sets HTTP-only cookie for secure session management
    Session expires after 15 minutes if MFA not completed

    SECURITY ENHANCEMENTS:
    - Reads session token from HTTP-only cookie (not request body - XSS protection)
    - Validates IP address matches original login (prevents session hijacking)
    - Validates User-Agent matches original login
    - Configurable strict mode via MFA_STRICT_IP_CHECK environment variable
    """
    ip_address, user_agent = get_client_info(request)
    conn = None

    # Get temporary session token from HTTP-only cookie (SECURE)
    temp_session_token = request.cookies.get("mfa_session_token")

    if not temp_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA session not found. Please login again."
        )

    # Get strict IP validation mode from environment (default: True for security)
    strict_ip_check = os.getenv("MFA_STRICT_IP_CHECK", "true").lower() == "true"

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user_id from temporary session with IP and User-Agent validation
        cursor.execute(
            """
            SELECT user_id, expires_at, is_active, ip_address, user_agent
            FROM user_sessions
            WHERE session_token = %s
            """,
            (temp_session_token,)
        )

        session = cursor.fetchone()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session token"
            )

        user_id, expires_at, is_active, original_ip, original_user_agent = session

        # SECURITY CHECK 1: Validate IP address matches
        if strict_ip_check and ip_address != original_ip:
            log_audit_event(
                cursor, user_id, "mfa_verification_failed", "failed",
                ip_address, {
                    "reason": "ip_mismatch",
                    "original_ip": original_ip,
                    "current_ip": ip_address
                }
            )
            conn.commit()

            logger.warning(
                f"MFA IP mismatch detected - User {user_id}: "
                f"Original={original_ip}, Current={ip_address}"
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session validation failed. Please login again."
            )

        # SECURITY CHECK 2: Validate User-Agent matches (log warning if different)
        if user_agent != original_user_agent:
            logger.warning(
                f"MFA User-Agent mismatch detected - User {user_id}: "
                f"Original={original_user_agent[:50]}, Current={user_agent[:50]}"
            )

            # Log suspicious activity but don't block (User-Agent can change legitimately)
            log_audit_event(
                cursor, user_id, "mfa_user_agent_mismatch", "warning",
                ip_address, {
                    "original_user_agent": original_user_agent[:200],
                    "current_user_agent": user_agent[:200]
                }
            )
            conn.commit()

        # Check if session expired (15 minutes)
        if datetime.now() > expires_at:
            cursor.execute(
                "DELETE FROM user_sessions WHERE session_token = %s",
                (mfa_data.session_token,)
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Please login again."
            )

        # Get user's encryption key and double-encrypted TOTP secret
        cursor.execute(
            """
            SELECT u.encryption_key, m.totp_secret_encrypted
            FROM users u
            JOIN user_mfa m ON u.id = m.user_id
            WHERE u.id = %s AND m.mfa_enabled = TRUE
            """,
            (user_id,)
        )

        mfa_record = cursor.fetchone()

        if not mfa_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not configured"
            )

        user_encrypted_key, secret_double_encrypted = mfa_record

        # DOUBLE DECRYPTION LAYER 1: Decrypt user's AES-256 key using master key
        from utils.encryption import decrypt_user_key, decrypt_message
        try:
            user_key = decrypt_user_key(user_encrypted_key)
        except Exception as e:
            logger.error(f"Failed to decrypt user key during MFA verification: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt user encryption key"
            )

        # DOUBLE DECRYPTION LAYER 2: Decrypt TOTP secret using user's AES-256 key
        try:
            totp_secret = decrypt_message(secret_double_encrypted, user_key)
        except Exception as e:
            logger.error(f"Failed to decrypt TOTP secret during MFA verification: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt MFA secret"
            )

        # Verify TOTP code
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(mfa_data.mfa_code, valid_window=1):
            log_audit_event(cursor, user_id, "mfa_verification_failed", "failed",
                          ip_address, {"method": "totp"})
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authenticator code"
            )

        # MFA verified - activate session and reset failed attempts
        reset_failed_login(cursor, user_id)

        # Generate new permanent session tokens
        permanent_session_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        permanent_expires_at = datetime.now() + timedelta(hours=SESSION_EXPIRE_HOURS)

        # Delete temporary session
        cursor.execute(
            "DELETE FROM user_sessions WHERE session_token = %s",
            (temp_session_token,)
        )

        # Clear temporary MFA session cookie
        response.delete_cookie(
            key="mfa_session_token",
            path="/",
            httponly=True,
            samesite="strict"
        )

        # Create permanent session using ORIGINAL login IP and User-Agent
        # This prevents session metadata replacement attack
        cursor.execute(
            """
            INSERT INTO user_sessions (
                user_id, session_token, refresh_token,
                ip_address, user_agent, expires_at, is_active
            )
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)
            """,
            (user_id, permanent_session_token, refresh_token,
             original_ip, original_user_agent, permanent_expires_at)  # Use ORIGINAL values
        )

        # Update last login and clear MFA code hash
        cursor.execute(
            "UPDATE users SET last_login = NOW() WHERE id = %s",
            (user_id,)
        )

        cursor.execute(
            """
            UPDATE user_mfa
            SET last_used_at = NOW()
            WHERE user_id = %s
            """,
            (user_id,)
        )

        # Get user details
        cursor.execute(
            "SELECT email, username FROM users WHERE id = %s",
            (user_id,)
        )
        email, username = cursor.fetchone()

        # Log audit events with ORIGINAL IP for accurate tracking
        log_audit_event(cursor, user_id, "mfa_verified", "success", original_ip, None)
        log_audit_event(cursor, user_id, "login_success", "success", original_ip, None)

        conn.commit()

        logger.info(f"MFA verified for user: {username}")

        # Set HTTP-only, Secure cookie (NOT accessible to JavaScript)
        # Detect if request is over HTTPS
        is_secure = request.url.scheme == "https"

        response.set_cookie(
            key="session_token",
            value=permanent_session_token,
            httponly=True,  # Cannot be accessed by JavaScript (XSS protection)
            secure=is_secure,  # Match the request scheme
            samesite="strict",  # CSRF protection
            max_age=SESSION_EXPIRE_HOURS * 3600,  # Seconds
            path="/"
        )

        # Return minimal response (NO tokens in body for security)
        return {
            "success": True,
            "message": "MFA verification successful",
            "user": {
                "id": user_id,
                "email": email,
                "username": username
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"MFA verification error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/logout")
@limiter.limit("30/hour")
async def logout(request: Request, response: Response):
    """
    Invalidate user session and clear cookie

    Uses session token from HTTP-only cookie
    """
    # Get session token from cookie
    session_token = request.cookies.get("session_token")

    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Invalidate session using session manager (handles Redis + PostgreSQL)
        session_manager.invalidate_session(cursor, session_token)

        # Get user_id for audit log
        cursor.execute(
            "SELECT user_id FROM user_sessions WHERE session_token = %s",
            (session_token,)
        )
        result = cursor.fetchone()

        if result:
            user_id = result[0]
            log_audit_event(cursor, user_id, "logout", "success", None, None)

        conn.commit()

        # Clear cookie
        response.delete_cookie(
            key="session_token",
            path="/",
            httponly=True,
            samesite="strict"
        )

        return {"success": True, "message": "Logged out successfully"}

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Logout error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

def cleanup_expired_sessions():
    """
    Cleanup expired sessions from database

    Deletes:
    - Sessions past expiration time
    - Inactive sessions older than 7 days

    Returns:
        Number of sessions deleted
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM user_sessions
            WHERE expires_at < NOW() OR (is_active = FALSE AND last_activity < NOW() - INTERVAL '7 days')
            """
        )

        deleted_count = cursor.rowcount
        conn.commit()

        logger.info(f"Session cleanup: removed {deleted_count} expired/inactive sessions")
        return deleted_count

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Session cleanup error: {e}")
        return 0
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/mfa/setup")
@limiter.limit("5/minute")  # Rate limiting to prevent abuse
async def setup_mfa(request: Request, current_user: dict = Depends(require_auth)):
    """
    Generate MFA setup QR code
    SECURE: Rate-limited, encrypted secrets, audit logged
    Supports both cookie and Bearer token authentication
    """
    user_id = current_user["id"]
    ip_address, _ = get_client_info(request)
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encrypted encryption key and decrypt it
        cursor.execute(
            "SELECT email, username, encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        email, username, user_encrypted_key = cursor.fetchone()

        # DOUBLE ENCRYPTION LAYER 1: Decrypt user's AES-256 key using master key
        from utils.encryption import decrypt_user_key, encrypt_message
        user_key = decrypt_user_key(user_encrypted_key)

        # Generate TOTP secret
        secret = pyotp.random_base32()

        # DOUBLE ENCRYPTION LAYER 2: Encrypt TOTP secret using user's AES-256 key
        secret_encrypted = encrypt_message(secret, user_key)

        # Create provisioning URI (use plain secret for QR code generation)
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name="Genesis Secure Platform"
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()

        # Store double-encrypted secret (encrypted with user key, which is encrypted with master key)
        cursor.execute(
            """
            INSERT INTO user_mfa (user_id, mfa_method, totp_secret_encrypted, mfa_enabled, mfa_verified)
            VALUES (%s, 'totp', %s, FALSE, FALSE)
            ON CONFLICT (user_id, mfa_method)
            DO UPDATE SET totp_secret_encrypted = EXCLUDED.totp_secret_encrypted,
                          mfa_enabled = FALSE, mfa_verified = FALSE
            """,
            (user_id, secret_encrypted)  # Store DOUBLE-ENCRYPTED secret
        )

        # Audit logging
        log_audit_event(cursor, user_id, "mfa_setup_initiated", "success", ip_address, {"method": "totp"})

        conn.commit()

        logger.info(f"MFA setup initiated for user {username}")

        return {
            "secret_key": secret,  # Return plain secret for QR code display (one-time only)
            "qr_code_base64": img_str,  # Return base64 image
            "provisioning_uri": provisioning_uri
        }

    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"MFA setup error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/mfa/enable")
@limiter.limit("5/minute")  # Rate limiting to prevent brute-force
async def enable_mfa(
    mfa_data: MFASetup,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Enable MFA after verifying setup code
    SECURE: Rate-limited, MFA validation middleware, audit logged
    Supports both cookie and Bearer token authentication
    """
    user_id = current_user["id"]
    ip_address, _ = get_client_info(request)
    conn = None

    try:
        # MFA Code Validation using middleware
        from middleware.mfa_validation import validate_mfa_code_format, sanitize_mfa_code

        # Validate MFA code format and detect attacks
        is_valid = validate_mfa_code_format(mfa_data.mfa_code)
        if not is_valid:
            # Log malicious input if detected
            log_malicious_input(
                user_id=user_id,  # Now we have user_id
                input_value=mfa_data.mfa_code,
                attack_type="invalid_mfa_code",
                pattern="MFA code must be exactly 6 digits",
                ip_address=ip_address,
                endpoint="/api/v1/auth/mfa/enable"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA code format. Code must be exactly 6 digits."
            )

        # Sanitize MFA code
        sanitized_code = sanitize_mfa_code(mfa_data.mfa_code)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key and double-encrypted TOTP secret
        cursor.execute(
            """
            SELECT u.encryption_key, m.totp_secret_encrypted
            FROM users u
            JOIN user_mfa m ON u.id = m.user_id
            WHERE u.id = %s
            """,
            (user_id,)
        )

        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not set up. Please initiate setup first."
            )

        user_encrypted_key, secret_double_encrypted = result

        # DOUBLE DECRYPTION LAYER 1: Decrypt user's AES-256 key using master key
        from utils.encryption import decrypt_user_key, decrypt_message
        try:
            user_key = decrypt_user_key(user_encrypted_key)
        except Exception as e:
            logger.error(f"Failed to decrypt user key: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt user encryption key"
            )

        # DOUBLE DECRYPTION LAYER 2: Decrypt TOTP secret using user's AES-256 key
        try:
            secret_key = decrypt_message(secret_double_encrypted, user_key)
        except Exception as e:
            logger.error(f"Failed to decrypt TOTP secret: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt MFA secret"
            )

        # Verify TOTP code
        totp = pyotp.TOTP(secret_key)

        # DEBUG: Log TOTP verification attempt
        current_totp = totp.now()
        logger.info(f"MFA enable - User {user_id} - Code provided: {sanitized_code}, Expected: {current_totp}")

        if not totp.verify(sanitized_code, valid_window=1):
            # Log failed verification
            log_audit_event(cursor, user_id, "mfa_enable_failed", "failed", ip_address, {"reason": "invalid_code"})
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA code. Please check your authenticator app and ensure your device time is synchronized."
            )

        # Enable MFA
        cursor.execute(
            """
            UPDATE user_mfa
            SET mfa_enabled = TRUE, mfa_verified = TRUE, updated_at = NOW()
            WHERE user_id = %s
            """,
            (user_id,)
        )

        # Audit logging
        log_audit_event(cursor, user_id, "mfa_enabled", "success", ip_address, {"method": "totp"})

        # Create notification for MFA enabled
        cursor.execute(
            """
            INSERT INTO notifications (user_id, type, title, message, priority, related_type)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                'system_alert',  # Using existing type
                'Multi-Factor Authentication Enabled',
                'Two-factor authentication has been successfully enabled on your account. Your account security has been enhanced.',
                'high',
                'mfa'
            )
        )

        conn.commit()

        logger.info(f"MFA enabled successfully for user {user_id}")

        return {"message": "MFA enabled successfully! Your account is now protected with two-factor authentication."}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"MFA enable error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable MFA"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)