"""
Google OAuth2 Authentication Router
Handles secure OAuth2 flow with email verification requirement
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional

from database.connection import get_db_connection
from database.models import users, email_verification_tokens
from database.sqlalchemy_db import execute_query
from sqlalchemy import select, insert, update, and_
from utils.security import hash_password
from utils.encryption import generate_user_encryption_key, encrypt_user_key
from utils.audit import log_audit_event
from utils.email_service import send_verification_email
from utils.input_sanitizer import validate_and_sanitize, MaliciousInputDetected
from utils.session_manager import SessionManager

router = APIRouter(prefix="/auth/google", tags=["Google OAuth"])

# Session manager
session_manager = SessionManager()

# OAuth configuration
config = Config(environ=os.environ)
oauth = OAuth(config)

# Register Google OAuth client
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'  # Always show account selector
    }
)

# Store OAuth state tokens temporarily (in production, use Redis)
oauth_states = {}

def cleanup_expired_states():
    """Remove expired OAuth state tokens"""
    now = datetime.utcnow()
    expired = [state for state, data in oauth_states.items()
               if data['expires_at'] < now]
    for state in expired:
        del oauth_states[state]


@router.get("/login")
async def google_oauth_login(request: Request):
    """
    Initiate Google OAuth flow
    Generates state parameter for CSRF protection
    """
    try:
        # Clean up expired states
        cleanup_expired_states()

        # Generate secure state token for CSRF protection
        state = secrets.token_urlsafe(32)

        # Store state with expiration (5 minutes)
        oauth_states[state] = {
            'expires_at': datetime.utcnow() + timedelta(minutes=5),
            'ip_address': request.client.host
        }

        # Generate OAuth authorization URL
        redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:8000/auth/google/callback')

        authorization_url = await oauth.google.authorize_redirect(
            request,
            redirect_uri,
            state=state
        )

        return authorization_url

    except Exception as e:
        log_audit_event(
            user_id=None,
            action="google_oauth_init_failed",
            resource_type="oauth",
            resource_id=None,
            ip_address=request.client.host,
            status="failure",
            details={"error": str(e)}
        )
        raise HTTPException(status_code=500, detail="Failed to initiate Google authentication")


@router.get("/callback")
async def google_oauth_callback(request: Request):
    """
    Handle Google OAuth callback
    Exchanges authorization code for access token
    Creates or links user account
    """
    try:
        # Get state parameter
        state = request.query_params.get('state')
        error = request.query_params.get('error')

        # Handle user denial
        if error:
            return RedirectResponse(
                url=f"/auth?error=oauth_denied&message=Google+authentication+was+cancelled",
                status_code=302
            )

        # Verify state parameter (CSRF protection)
        if not state or state not in oauth_states:
            log_audit_event(
                user_id=None,
                action="google_oauth_csrf_violation",
                resource_type="oauth",
                resource_id=None,
                ip_address=request.client.host,
                status="failure",
                details={"reason": "Invalid or missing state parameter"}
            )
            return RedirectResponse(
                url="/auth?error=invalid_state&message=Invalid+authentication+request",
                status_code=302
            )

        # Check state expiration
        state_data = oauth_states[state]
        if state_data['expires_at'] < datetime.utcnow():
            del oauth_states[state]
            return RedirectResponse(
                url="/auth?error=expired_state&message=Authentication+request+expired",
                status_code=302
            )

        # Verify IP address matches (additional security)
        if state_data['ip_address'] != request.client.host:
            log_audit_event(
                user_id=None,
                action="google_oauth_ip_mismatch",
                resource_type="oauth",
                resource_id=None,
                ip_address=request.client.host,
                status="failure",
                details={"original_ip": state_data['ip_address']}
            )
            del oauth_states[state]
            return RedirectResponse(
                url="/auth?error=ip_mismatch&message=Authentication+request+security+violation",
                status_code=302
            )

        # Remove used state
        del oauth_states[state]

        # Exchange authorization code for access token
        token = await oauth.google.authorize_access_token(request)

        # Get user info from Google
        user_info = token.get('userinfo')
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info from Google")

        google_id = user_info.get('sub')
        email = user_info.get('email')
        email_verified_by_google = user_info.get('email_verified', False)
        given_name = user_info.get('given_name', '')
        family_name = user_info.get('family_name', '')

        if not google_id or not email:
            raise HTTPException(status_code=400, detail="Incomplete user information from Google")

        # Sanitize inputs
        try:
            email = validate_and_sanitize(email, max_length=255, user_id=None, ip_address=request.client.host, endpoint="/auth/google/callback")
            given_name = validate_and_sanitize(given_name, max_length=100, user_id=None, ip_address=request.client.host, endpoint="/auth/google/callback")
            family_name = validate_and_sanitize(family_name, max_length=100, user_id=None, ip_address=request.client.host, endpoint="/auth/google/callback")
        except MaliciousInputDetected as e:
            log_audit_event(
                user_id=None,
                action="google_oauth_malicious_input",
                resource_type="oauth",
                resource_id=None,
                ip_address=request.client.host,
                status="failure",
                details={"attack_type": e.attack_type, "email": email}
            )
            return RedirectResponse(
                url="/auth?error=invalid_data&message=Invalid+data+received+from+Google",
                status_code=302
            )

        # Check if user already exists with this Google ID
        existing_user = execute_query(
            select(users).where(users.c.google_id == google_id),
            fetch_one=True
        )

        if existing_user:
            # User exists, log them in
            user_dict = dict(existing_user._mapping)
            user_id = user_dict['id']
            username = user_dict['username']
            is_admin = user_dict.get('is_admin', False)

            # Check if account is active
            if not user_dict['is_active']:
                log_audit_event(
                    user_id=user_id,
                    action="google_login_inactive_account",
                    resource_type="user",
                    resource_id=user_id,
                    ip_address=request.client.host,
                    status="failure"
                )
                return RedirectResponse(
                    url="/auth?error=account_suspended&message=Your+account+has+been+suspended",
                    status_code=302
                )

            # Update last login
            execute_query(
                update(users).where(users.c.id == user_id).values(
                    last_login=datetime.utcnow()
                ),
                commit=True
            )

            # Create session token
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                token = session_manager.create_session(
                    cursor=cursor,
                    user_id=user_id,
                    ip_address=request.client.host,
                    user_agent=request.headers.get('user-agent', 'Unknown'),
                    remember_me=False
                )
                conn.commit()
            finally:
                cursor.close()
                conn.close()

            # Log successful login
            log_audit_event(
                user_id=user_id,
                action="google_login_success",
                resource_type="user",
                resource_id=user_id,
                ip_address=request.client.host,
                status="success"
            )

            # Redirect to dashboard
            redirect_url = "/admin" if is_admin else "/dashboard"
            response = RedirectResponse(url=redirect_url, status_code=302)
            response.set_cookie(
                key="auth_token",
                value=token,
                httponly=True,
                secure=os.getenv('ENV') == 'production',
                samesite='lax',
                max_age=86400  # 24 hours
            )
            return response

        else:
            # Check if user exists with this email (link accounts)
            existing_user_by_email = execute_query(
                select(users).where(users.c.email == email),
                fetch_one=True
            )

            if existing_user_by_email:
                # Link Google account to existing user
                user_dict = dict(existing_user_by_email._mapping)
                user_id = user_dict['id']

                execute_query(
                    update(users).where(users.c.id == user_id).values(
                        google_id=google_id,
                        last_login=datetime.utcnow()
                    ),
                    commit=True
                )

                # Create session token
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    token = session_manager.create_session(
                        cursor=cursor,
                        user_id=user_id,
                        ip_address=request.client.host,
                        user_agent=request.headers.get('user-agent', 'Unknown'),
                        remember_me=False
                    )
                    conn.commit()
                finally:
                    cursor.close()
                    conn.close()

                is_admin = user_dict.get('is_admin', False)

                # Log successful login
                log_audit_event(
                    user_id=user_id,
                    action="google_account_linked",
                    resource_type="user",
                    resource_id=user_id,
                    ip_address=request.client.host,
                    status="success"
                )

                # Redirect to dashboard
                redirect_url = "/admin" if is_admin else "/dashboard"
                response = RedirectResponse(url=redirect_url, status_code=302)
                response.set_cookie(
                    key="auth_token",
                    value=token,
                    httponly=True,
                    secure=os.getenv('ENV') == 'production',
                    samesite='lax',
                    max_age=86400  # 24 hours
                )
                return response

            else:
                # Create new user account
                # Generate username from email (user can change later)
                username = email.split('@')[0]

                # Check if username exists, add numbers if needed
                base_username = username
                counter = 1
                while True:
                    existing = execute_query(
                        select(users).where(users.c.username == username),
                        fetch_one=True
                    )
                    if not existing:
                        break
                    username = f"{base_username}{counter}"
                    counter += 1

                # Generate encryption key for user
                user_key = generate_user_encryption_key()
                encrypted_key = encrypt_user_key(user_key)

                # Create random password (user won't need it, can reset if needed)
                random_password = secrets.token_urlsafe(32)
                password_hash = hash_password(random_password)

                # Create user
                result = execute_query(
                    insert(users).values(
                        username=username,
                        email=email,
                        password_hash=password_hash,
                        first_name=given_name,
                        last_name=family_name,
                        encryption_key=encrypted_key,
                        google_id=google_id,
                        email_verified=email_verified_by_google,  # Trust Google's verification
                        is_active=True,
                        account_status='active',
                        created_at=datetime.utcnow()
                    ).returning(users.c.id),
                    commit=True,
                    fetch_one=True
                )

                user_id = result[0]

                # If email not verified by Google, send verification email
                if not email_verified_by_google:
                    verification_token = secrets.token_urlsafe(32)
                    execute_query(
                        insert(email_verification_tokens).values(
                            user_id=user_id,
                            token=verification_token,
                            created_at=datetime.utcnow(),
                            expires_at=datetime.utcnow() + timedelta(hours=24)
                        ),
                        commit=True
                    )

                    try:
                        send_verification_email(email, verification_token, username)
                    except Exception as e:
                        # Log but don't fail registration
                        log_audit_event(
                            user_id=user_id,
                            action="verification_email_failed",
                            resource_type="user",
                            resource_id=user_id,
                            ip_address=request.client.host,
                            status="failure",
                            details={"error": str(e)}
                        )

                # Create session token
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    token = session_manager.create_session(
                        cursor=cursor,
                        user_id=user_id,
                        ip_address=request.client.host,
                        user_agent=request.headers.get('user-agent', 'Unknown'),
                        remember_me=False
                    )
                    conn.commit()
                finally:
                    cursor.close()
                    conn.close()

                # Log successful registration
                log_audit_event(
                    user_id=user_id,
                    action="google_registration_success",
                    resource_type="user",
                    resource_id=user_id,
                    ip_address=request.client.host,
                    status="success"
                )

                # Redirect to dashboard with welcome message
                response = RedirectResponse(url="/dashboard?welcome=true", status_code=302)
                response.set_cookie(
                    key="auth_token",
                    value=token,
                    httponly=True,
                    secure=os.getenv('ENV') == 'production',
                    samesite='lax',
                    max_age=86400  # 24 hours
                )
                return response

    except HTTPException:
        raise
    except Exception as e:
        log_audit_event(
            user_id=None,
            action="google_oauth_callback_failed",
            resource_type="oauth",
            resource_id=None,
            ip_address=request.client.host,
            status="failure",
            details={"error": str(e)}
        )
        return RedirectResponse(
            url="/auth?error=oauth_failed&message=Google+authentication+failed",
            status_code=302
        )
