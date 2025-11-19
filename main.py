"""
AI Creative Draft Generator - Secure FastAPI Application
Main application file with comprehensive security controls

Requirements:
pip install fastapi uvicorn psycopg2-binary argon2-cffi python-dotenv \
    pydantic[email] python-multipart pyotp qrcode slowapi pyjwt \
    python-jose[cryptography] passlib
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
import logging
from typing import Optional
import os
from dotenv import load_dotenv

# Import routers
from routers import auth, creative, admin, user, messages, drive, video, teams, flowcharts, ideas, google_oauth, gemini
from middleware.security import (
    SecurityHeadersMiddleware,
    InputValidationMiddleware,
    HostHeaderValidationMiddleware,
    SecurityMonitoringMiddleware,
    CSRFProtectionMiddleware
)
from database.connection import DatabasePool, get_db_connection
from utils.audit import log_audit_event

# Load environment variables
load_dotenv()

# Initialize environment secrets (generate keys if dev placeholders detected)
from utils.env_init import (
    initialize_env_secrets,
    validate_required_env_vars,
    check_master_encryption_key,
    display_security_checklist
)

# Auto-generate secure keys if dev placeholders are found
initialize_env_secrets()

# Validate required environment variables
if not validate_required_env_vars():
    raise RuntimeError("Missing required environment variables - check logs")

# Validate master encryption key
if not check_master_encryption_key():
    raise RuntimeError("MASTER_ENCRYPTION_KEY is not properly configured")

# Display security checklist
display_security_checklist()

# Configure secure logging (no PII)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rate limiting configuration
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
    strategy="fixed-window"
)

# Database pool initialization handled in lifespan

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    from database.connection import initialize_pool, close_db_pool
    
    # Startup
    logger.info("Starting AI Creative Draft Generator API")
    logger.info(f"Environment: {os.getenv('ENV', 'development')}")
    logger.info(f"Debug mode: {os.getenv('DEBUG', 'False')}")
    try:
        initialize_pool(
            dbname=os.getenv('DB_NAME', 'creative_ai_db'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', '5432')),
            min_conn=2,
            max_conn=10
        )
        logger.info("Database pool initialized")
        logger.info("API is ready to accept requests")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    
    yield
    
    # Shutdown
    close_db_pool()
    logger.info("Application shutdown complete")

# Initialize FastAPI application
app = FastAPI(
    title="AI Creative Draft Generator API",
    description="Secure API for AI-powered creative content generation",
    version="1.0.0",
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc",
    lifespan=lifespan
)

# Initialize templates (static files mounted later)
templates = Jinja2Templates(directory="templates")

# Security Middleware Configuration

# 1. Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 2. Custom Host Header Validation (more strict than TrustedHostMiddleware)
allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
app.add_middleware(
    HostHeaderValidationMiddleware,
    allowed_hosts=allowed_hosts
)

# 3. CORS Configuration (restrictive)
cors_origins = os.getenv("CORS_ORIGINS", "https://localhost:8000,https://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
    max_age=3600
)

# 4. CSRF Protection (double-submit cookie pattern)
app.add_middleware(CSRFProtectionMiddleware)

# 5. Custom Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 6. Input Validation Middleware
app.add_middleware(InputValidationMiddleware)

# 7. Security Monitoring Middleware (tracks IDOR, rate limits, etc.)
app.add_middleware(SecurityMonitoringMiddleware)

# Exception Handlers

def get_error_details(status_code: int, detail: str = None):
    """Get error page details based on status code"""
    error_configs = {
        400: {
            "title": "Bad Request",
            "message": "The request could not be understood or was missing required parameters.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
        },
        401: {
            "title": "Unauthorized",
            "message": "You need to be logged in to access this page. Please sign in with your account to continue.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
        },
        403: {
            "title": "Forbidden",
            "message": "You don't have permission to access this resource. This area is restricted to authorized users only.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>',
        },
        404: {
            "title": "Page Not Found",
            "message": "Sorry, the page you're looking for doesn't exist. It may have been moved or deleted.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><path d="m21 21-4.35-4.35"></path></svg>',
        },
        500: {
            "title": "Internal Server Error",
            "message": "Something went wrong on our end. Our team has been notified and we're working to fix it.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        },
        503: {
            "title": "Service Unavailable",
            "message": "The service is temporarily unavailable. Please try again in a few moments.",
            "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>',
        }
    }

    config = error_configs.get(status_code, {
        "title": f"Error {status_code}",
        "message": detail or "An error occurred while processing your request.",
        "icon": '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
    })

    # Override message if custom detail provided
    if detail:
        config["message"] = detail

    return config

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions securely"""
    # Log security-relevant errors (no sensitive data)
    if exc.status_code >= 400:
        logger.warning(
            f"HTTP {exc.status_code} - Path: {request.url.path} - "
            f"Method: {request.method}"
        )

    # Check if request expects HTML (browser request)
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        from datetime import datetime

        error_details = get_error_details(exc.status_code, exc.detail)

        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "status_code": exc.status_code,
                "title": error_details["title"],
                "message": error_details["message"],
                "icon": error_details["icon"],
                "show_dashboard": exc.status_code in [401, 403],
                "show_details": os.getenv("ENV") != "production",
                "request_path": request.url.path,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            status_code=exc.status_code
        )

    # Return JSON for API requests
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle Pydantic validation errors with user-friendly messages
    Prevents exposure of internal validation details
    """
    # Extract user-friendly error messages
    errors = []
    for error in exc.errors():
        field = error.get('loc', ['unknown'])[-1]  # Get field name
        msg = error.get('msg', 'Invalid input')

        # Customize error messages for common validation issues
        if 'string_pattern_mismatch' in msg:
            if field == 'username':
                msg = 'Username can only contain letters, numbers, underscores, and hyphens'
            elif field in ['first_name', 'last_name']:
                msg = 'Name can only contain letters, spaces, and hyphens'
            else:
                msg = 'Invalid characters detected'
        elif 'string_too_short' in msg:
            msg = f'{field.replace("_", " ").title()} is too short'
        elif 'string_too_long' in msg:
            msg = f'{field.replace("_", " ").title()} is too long'
        elif 'value_error' in str(error.get('type', '')):
            # Use custom validator message
            msg = error.get('msg', 'Invalid input')

        errors.append({
            "field": field,
            "message": msg
        })

    # Log validation error (without sensitive data)
    error_fields = [f"{e['field']}: {e['message']}" for e in errors]
    logger.info(f"Validation error on {request.url.path}: {len(errors)} fields - {'; '.join(error_fields)}")

    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation failed",
            "details": errors
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions securely"""
    logger.error(f"Unexpected error on {request.url.path}: {type(exc).__name__}")

    # Check if request expects HTML (browser request)
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        from datetime import datetime

        error_details = get_error_details(500)

        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "status_code": 500,
                "title": error_details["title"],
                "message": error_details["message"],
                "icon": error_details["icon"],
                "show_dashboard": False,
                "show_details": os.getenv("ENV") != "production",
                "request_path": request.url.path,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            status_code=500
        )

    # Never expose internal error details to client (API requests)
    return JSONResponse(
        status_code=500,
        content={
            "error": "An internal server error occurred",
            "status_code": 500
        }
    )

# Health Check Endpoint

@app.get("/health", tags=["Health"])
@limiter.limit("10/minute")
async def health_check(request: Request):
    """Health check endpoint (no sensitive info)"""
    return {
        "status": "healthy",
        "service": "ai-creative-generator"
    }

# Template Routes

@app.get("/", tags=["Pages"])
async def index(request: Request):
    """Landing page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/auth", tags=["Pages"])
async def auth_page(request: Request):
    """Authentication page"""
    return templates.TemplateResponse("auth.html", {"request": request})

@app.get("/2fa_verify", tags=["Pages"])
async def two_factor_auth_page(request: Request):
    """Two-Factor Authentication verification page"""
    return templates.TemplateResponse("2fa_verify.html", {"request": request})

@app.get("/dashboard", tags=["Pages"])
async def dashboard_page(request: Request):
    """
    User dashboard page - requires authentication
    ISO 27001 A.8.3 Information Access Restriction
    """
    from utils.auth_dependencies import require_auth_page

    user = await require_auth_page(request)

    if not user:
        # Redirect to login if not authenticated
        return RedirectResponse(url="/auth?redirect=/dashboard", status_code=302)

    return templates.TemplateResponse("user-dashboard.html", {
        "request": request,
        "user": user
    })

@app.get("/admin", tags=["Pages"])
async def admin_redirect(request: Request):
    """Redirect /admin to /admin/dashboard"""
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/dashboard", tags=["Pages"])
async def admin_dashboard_page(request: Request):
    """
    Admin dashboard page - requires admin privileges

    Security:
    - ISO 27001 A.8.2 Privileged Access Rights
    - IDOR Prevention: Explicitly checks users.is_admin = TRUE in database
    - Audit logging: All access attempts (successful and failed) are logged
    - Cannot be bypassed by session manipulation or URL guessing

    Access Control:
    1. Validates session token exists and is active
    2. Queries database: SELECT is_admin FROM users WHERE id = ?
    3. Rejects if is_admin != TRUE (strict boolean check)
    4. Verifies account is_active = TRUE and account_status = 'active'
    5. Logs access attempt to audit_logs table
    """
    from utils.auth_dependencies import require_admin

    try:
        # CRITICAL: require_admin() always checks users.is_admin flag from database
        # This prevents privilege escalation attacks
        user = await require_admin(request)

        return templates.TemplateResponse("admin-dashboard.html", {
            "request": request,
            "user": user
        })
    except HTTPException as e:
        # If user is not authenticated, redirect to login
        if e.status_code == 401:
            return RedirectResponse(url="/auth?redirect=/admin/dashboard", status_code=302)
        # If user is authenticated but not admin, show 403
        elif e.status_code == 403:
            # Return 403 error page with appropriate message
            return templates.TemplateResponse("error.html", {
                "request": request,
                "status_code": 403,
                "title": "Access Denied",
                "message": "You do not have administrator privileges to access this page.",
                "icon": '''<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>''',
                "show_dashboard": True,
                "show_details": False
            }, status_code=403)
        raise

@app.get("/logout", tags=["Pages"])
async def logout(request: Request):
    """
    Logout user and destroy session
    ISO 27001 A.8.5 Secure Authentication - Session Management
    """
    from utils.auth_dependencies import invalidate_session
    
    # Get token from cookie
    token = request.cookies.get("session_token")
    
    if token:
        # Invalidate session in database
        invalidate_session(token)
        logger.info("User logged out successfully")
    
    # Redirect to auth page with cleared cookie
    response = RedirectResponse(url="/auth", status_code=302)
    response.delete_cookie("session_token", path="/")
    response.delete_cookie("session_token", path="/", domain=None)
    
    # Also clear any other session-related cookies
    response.set_cookie(
        key="session_token",
        value="",
        max_age=0,
        expires=0,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict"
    )
    
    return response

# Include Routers

# Auth router - mounted at both /auth (for frontend) and /api/v1/auth (for API)
app.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

app.include_router(
    auth.router,
    prefix="/api/v1/auth",
    tags=["Authentication API"]
)

# Google OAuth router - no prefix as it already has /auth/google in router definition
app.include_router(
    google_oauth.router,
    tags=["Google OAuth"]
)

app.include_router(
    creative.router,
    prefix="/api/v1/creative",
    tags=["Creative Content"]
)

app.include_router(
    user.router,
    prefix="/api/v1/user",
    tags=["User Management"]
)

app.include_router(
    admin.router,
    prefix="/api/v1/admin",
    tags=["Administration"]
)

app.include_router(
    messages.router,
    prefix="/api/v1/messages",
    tags=["Messages"]
)

app.include_router(
    drive.router,
    prefix="/api/v1/drive",
    tags=["Encrypted Drive"]
)

app.include_router(
    video.router,
    prefix="/api/v1/video",
    tags=["Video Calling"]
)

app.include_router(
    teams.router,
    prefix="/api/v1/teams",
    tags=["Teams & Invitations"]
)

app.include_router(
    flowcharts.router,
    prefix="/api/v1/flowcharts",
    tags=["Flowcharts"]
)

app.include_router(
    ideas.router,
    prefix="/api/v1/ideas",
    tags=["AI Ideas & Scripts"]
)

app.include_router(
    gemini.router,
    prefix="/api/v1/gemini",
    tags=["Gemini AI Assistant"]
)

# Mount static files AFTER all routers and middleware
app.mount("/static", StaticFiles(directory="static"), name="static")

# Catch-all route for 404 errors (must be defined AFTER static mount)
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
async def catch_all(request: Request, path_name: str):
    """Catch-all handler for undefined routes - shows custom 404 page"""
    # Don't catch static file requests (they're handled by StaticFiles mount above)
    if path_name.startswith("static/"):
        raise HTTPException(status_code=404, detail="Not found")

    # Check if request expects HTML (browser request)
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        from datetime import datetime

        error_details = get_error_details(404)

        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "status_code": 404,
                "title": error_details["title"],
                "message": error_details["message"],
                "icon": error_details["icon"],
                "show_dashboard": False,
                "show_details": os.getenv("ENV") != "production",
                "request_path": f"/{path_name}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            status_code=404
        )

    # Return JSON for API requests
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not found",
            "status_code": 404
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    # Production-ready server configuration
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=False,  # Disabled to prevent constant restarts from file changes
        log_level="info",
        access_log=True,
        server_header=False,  # Don't expose server info
        date_header=False,  # Reduce fingerprinting
        # SSL enabled for secure cookie support
        ssl_keyfile=os.getenv("SSL_KEY_FILE", "certs/server.key"),
        ssl_certfile=os.getenv("SSL_CERT_FILE", "certs/server.crt")
    )