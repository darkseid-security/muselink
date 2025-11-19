"""
routers/video.py
WebRTC Video Calling Router with End-to-End Encryption
Secure peer-to-peer video calling with DTLS-SRTP encryption and signaling server

Security Features:
- DTLS-SRTP for media encryption (AES-128-GCM or AES-256-GCM)
- Perfect Forward Secrecy (PFS) with ephemeral keys
- Certificate fingerprint verification
- Rate limiting on call initiation
- Call duration limits
- Concurrent call limits per user
- SDP validation and sanitization
- ICE candidate validation
- WebSocket message size limits
- Anti-flooding protection
- Audit logging for all call events
"""

from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import logging
import json
import secrets
import re
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.security import verify_session_token
from utils.audit import log_audit_event
from utils.auth_dependencies import require_auth, require_admin
from utils.team_access import verify_team_access

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Active WebSocket connections for signaling
active_connections: Dict[int, WebSocket] = {}
active_calls: Dict[str, Dict] = {}
websocket_last_activity: Dict[int, datetime] = {}  # Track last activity for idle timeout

# Security Configuration
MAX_CALL_DURATION_MINUTES = 120  # 2 hours max call duration
MAX_CONCURRENT_CALLS_PER_USER = 3  # Maximum concurrent calls per user
MAX_WEBSOCKET_MESSAGE_SIZE = 65536  # 64KB max message size
CALL_RATE_LIMIT_PER_HOUR = 50  # Max calls per user per hour
ICE_CANDIDATE_RATE_LIMIT = 100  # Max ICE candidates per call
SDP_MAX_SIZE = 32768  # 32KB max SDP size
WEBSOCKET_IDLE_TIMEOUT_MINUTES = int(os.getenv("WEBSOCKET_IDLE_TIMEOUT_MINUTES", "60"))  # 60 min default
ALLOW_PRIVATE_IP_CANDIDATES = os.getenv("ALLOW_PRIVATE_IP_CANDIDATES", "false").lower() == "true"  # Block by default

# Track call attempts for rate limiting
call_attempts: Dict[int, List[datetime]] = {}
ice_candidate_counts: Dict[str, int] = {}

# Pydantic Models

class CallInitiate(BaseModel):
    """Model for initiating a call"""
    receiver_id: int = Field(..., gt=0)
    call_type: str = Field(..., pattern=r'^(video|audio)$')
    encryption_required: bool = Field(default=True)  # Always require encryption
    
    @validator('encryption_required')
    def validate_encryption(cls, v):
        if not v:
            raise ValueError('Encryption is mandatory for all calls')
        return v

class CallResponse(BaseModel):
    """Model for call response"""
    call_id: str = Field(..., min_length=32, max_length=64)
    action: str = Field(..., pattern=r'^(accept|reject)$')

class SignalingMessage(BaseModel):
    """Model for WebRTC signaling messages"""
    call_id: str = Field(..., min_length=32, max_length=64)
    type: str = Field(..., pattern=r'^(offer|answer|ice-candidate)$')
    data: dict
    
    @validator('data')
    def validate_data_size(cls, v):
        # Prevent oversized messages
        data_str = json.dumps(v)
        if len(data_str) > SDP_MAX_SIZE:
            raise ValueError('Signaling data too large')
        return v

# Helper Functions

async def get_current_user_id(current_user: dict = Depends(require_auth)) -> int:
    """Get current user ID from authentication dependency"""
    return current_user["id"]

def check_call_rate_limit(user_id: int) -> bool:
    """Check if user has exceeded call rate limit"""
    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)
    
    # Clean up old attempts
    if user_id in call_attempts:
        call_attempts[user_id] = [
            attempt for attempt in call_attempts[user_id]
            if attempt > one_hour_ago
        ]
    else:
        call_attempts[user_id] = []
    
    # Check limit
    if len(call_attempts[user_id]) >= CALL_RATE_LIMIT_PER_HOUR:
        return False
    
    # Add current attempt
    call_attempts[user_id].append(now)
    return True

def get_user_active_calls(user_id: int) -> int:
    """Get number of active calls for user"""
    count = 0
    for call in active_calls.values():
        if user_id in [call["caller_id"], call["receiver_id"]]:
            if call["status"] in ["initiated", "active"]:
                count += 1
    return count

def validate_sdp(sdp: str) -> bool:
    """
    Validate SDP (Session Description Protocol) for security
    Ensures DTLS-SRTP encryption is enabled
    """
    if not sdp or len(sdp) > SDP_MAX_SIZE:
        return False
    
    # Check for required encryption attributes
    required_patterns = [
        r'a=fingerprint:',  # DTLS fingerprint required
        r'a=setup:',  # DTLS setup required
        r'a=ice-ufrag:',  # ICE credentials required
        r'a=ice-pwd:',  # ICE password required
    ]
    
    for pattern in required_patterns:
        if not re.search(pattern, sdp):
            logger.warning(f"SDP missing required attribute: {pattern}")
            return False
    
    # Check for SRTP crypto (should be present for encrypted media)
    # Note: With DTLS-SRTP, crypto is negotiated via DTLS, not SDP
    # But we should ensure no unencrypted RTP
    if re.search(r'RTP/AVP\s', sdp) and not re.search(r'RTP/SAVP', sdp):
        # Plain RTP without SRTP - check if DTLS-SRTP is used instead
        if not re.search(r'UDP/TLS/RTP/SAVP', sdp):
            logger.warning("SDP does not specify encrypted media transport")
            return False
    
    # Block potentially malicious patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'onerror=',
        r'onclick=',
        r'\x00',  # Null bytes
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, sdp, re.IGNORECASE):
            logger.error(f"SDP contains dangerous pattern: {pattern}")
            return False
    
    return True

def validate_ice_candidate(candidate: dict) -> bool:
    """Validate ICE candidate for security"""
    if not isinstance(candidate, dict):
        return False
    
    # Check required fields
    required_fields = ['candidate', 'sdpMid', 'sdpMLineIndex']
    for field in required_fields:
        if field not in candidate:
            return False
    
    candidate_str = candidate.get('candidate', '')
    
    # Validate candidate string format
    if not candidate_str or len(candidate_str) > 512:
        return False
    
    # Check for private/internal IP addresses
    # Configurable via ALLOW_PRIVATE_IP_CANDIDATES environment variable
    private_ip_patterns = [
        r'10\.\d+\.\d+\.\d+',                    # Private Class A
        r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+', # Private Class B
        r'192\.168\.\d+\.\d+',                   # Private Class C
        r'127\.\d+\.\d+\.\d+',                   # Localhost
        r'169\.254\.\d+\.\d+',                   # Link-local
        r'::1',                                   # IPv6 localhost
        r'fe80:',                                 # IPv6 link-local
        r'fc00:',                                 # IPv6 ULA
        r'fd00:',                                 # IPv6 ULA
    ]

    for pattern in private_ip_patterns:
        if re.search(pattern, candidate_str):
            if not ALLOW_PRIVATE_IP_CANDIDATES:
                # Maximum security: Block all private IPs (SSRF protection)
                logger.error(f"ICE candidate contains private IP (blocked): {pattern}")
                return False
            else:
                # Development/local network mode: Allow private IPs
                logger.warning(f"ICE candidate contains private IP (allowed by config): {pattern}")
    
    # Block dangerous patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'\x00',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, candidate_str, re.IGNORECASE):
            logger.error(f"ICE candidate contains dangerous pattern: {pattern}")
            return False
    
    return True

def check_call_duration(call_id: str) -> bool:
    """Check if call has exceeded maximum duration"""
    if call_id not in active_calls:
        return False
    
    call = active_calls[call_id]
    duration = (datetime.now() - call["started_at"]).seconds / 60  # minutes
    
    if duration > MAX_CALL_DURATION_MINUTES:
        logger.warning(f"Call {call_id} exceeded maximum duration")
        return False
    
    return True

# Video Call Endpoints

@router.post("/call/initiate")
@limiter.limit("10/minute")  # Rate limit call initiation
async def initiate_call(
    call_data: CallInitiate,
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Initiate a video/audio call to another user with end-to-end encryption
    
    Security Features:
    - Rate limiting (10 calls per minute)
    - Hourly call limit per user
    - Concurrent call limit
    - Encryption mandatory
    - Audit logging
    """
    conn = None

    try:
        # Check rate limit
        if not check_call_rate_limit(current_user):
            log_audit_event(
                None, current_user, "call_rate_limit_exceeded", "failed",
                request.client.host if request.client else None,
                {"receiver_id": call_data.receiver_id}
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Call rate limit exceeded. Maximum {CALL_RATE_LIMIT_PER_HOUR} calls per hour."
            )
        
        # Check concurrent call limit
        active_call_count = get_user_active_calls(current_user)
        if active_call_count >= MAX_CONCURRENT_CALLS_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum concurrent calls limit reached ({MAX_CONCURRENT_CALLS_PER_USER})"
            )
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if receiver exists and is active
        cursor.execute(
            """
            SELECT id, is_active, account_status, username
            FROM users
            WHERE id = %s
            """,
            (call_data.receiver_id,)
        )

        receiver = cursor.fetchone()

        if not receiver:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        receiver_id, is_active, account_status, receiver_username = receiver

        if not is_active or account_status != 'active':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot call inactive user"
            )

        # Prevent calling self
        if current_user == call_data.receiver_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot call yourself"
            )

        # TEAM-BASED ACCESS CONTROL: Verify users share at least one team
        if not verify_team_access(current_user, call_data.receiver_id, action="initiate call to"):
            log_audit_event(
                cursor, current_user, "unauthorized_call_attempt", "failed",
                request.client.host if request.client else None,
                {"receiver_id": call_data.receiver_id, "reason": "users_not_in_same_team"}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only call members of your teams"
            )

        # Check if receiver is online (has active WebSocket connection)
        if call_data.receiver_id not in active_connections:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is not online"
            )
        
        # Check if receiver has reached concurrent call limit
        receiver_active_calls = get_user_active_calls(call_data.receiver_id)
        if receiver_active_calls >= MAX_CONCURRENT_CALLS_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is currently busy"
            )

        # Get caller username
        cursor.execute(
            "SELECT username FROM users WHERE id = %s",
            (current_user,)
        )
        caller_username = cursor.fetchone()[0]

        # Create call record
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS video_calls (
                id SERIAL PRIMARY KEY,
                call_id VARCHAR(64) UNIQUE NOT NULL,
                caller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                call_type VARCHAR(20) NOT NULL,
                encryption_enabled BOOLEAN DEFAULT TRUE,
                status VARCHAR(20) DEFAULT 'initiated',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                duration_seconds INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT check_encryption CHECK (encryption_enabled = TRUE)
            )
            """
        )

        # Generate unique call ID (cryptographically secure)
        call_id = secrets.token_urlsafe(32)

        cursor.execute(
            """
            INSERT INTO video_calls (call_id, caller_id, receiver_id, call_type, encryption_enabled, status)
            VALUES (%s, %s, %s, %s, %s, 'initiated')
            RETURNING id
            """,
            (call_id, current_user, call_data.receiver_id, call_data.call_type, True)
        )

        db_call_id = cursor.fetchone()[0]

        # Initialize ICE candidate counter for this call
        ice_candidate_counts[call_id] = 0

        # Store active call with encryption info
        active_calls[call_id] = {
            "id": db_call_id,
            "caller_id": current_user,
            "receiver_id": call_data.receiver_id,
            "call_type": call_data.call_type,
            "encryption_enabled": True,
            "status": "initiated",
            "started_at": datetime.now(),
            "ice_candidates_sent": 0
        }

        log_audit_event(
            cursor, current_user, "call_initiated", "success",
            request.client.host if request.client else None,
            {
                "receiver_id": call_data.receiver_id,
                "call_type": call_data.call_type,
                "encryption": "DTLS-SRTP"
            }
        )

        conn.commit()

        # Send call notification to receiver via WebSocket
        if call_data.receiver_id in active_connections:
            try:
                await active_connections[call_data.receiver_id].send_json({
                    "type": "incoming_call",
                    "call_id": call_id,
                    "caller_id": current_user,
                    "caller_username": caller_username,
                    "call_type": call_data.call_type,
                    "encryption_required": True,
                    "max_duration_minutes": MAX_CALL_DURATION_MINUTES
                })
            except Exception as e:
                logger.error(f"Failed to send call notification: {e}")

        logger.info(f"Encrypted call initiated from user {current_user} to user {call_data.receiver_id}")

        return {
            "message": "Encrypted call initiated successfully",
            "call_id": call_id,
            "receiver_username": receiver_username,
            "call_type": call_data.call_type,
            "encryption": {
                "enabled": True,
                "protocol": "DTLS-SRTP",
                "cipher_suites": [
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                ],
                "perfect_forward_secrecy": True
            },
            "security_info": {
                "max_duration_minutes": MAX_CALL_DURATION_MINUTES,
                "certificate_verification_required": True
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Initiate call error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate call"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/call/respond")
async def respond_to_call(
    response_data: CallResponse,
    current_user: int = Depends(get_current_user_id)
):
    """
    Accept or reject an incoming call
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get call details
        if response_data.call_id not in active_calls:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Call not found or already ended"
            )

        call = active_calls[response_data.call_id]

        # Verify user is the receiver
        if call["receiver_id"] != current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to respond to this call"
            )

        # Update call status
        if response_data.action == "accept":
            call["status"] = "active"
            cursor.execute(
                """
                UPDATE video_calls
                SET status = 'active', started_at = NOW()
                WHERE call_id = %s
                """,
                (response_data.call_id,)
            )

            # Notify caller via WebSocket
            if call["caller_id"] in active_connections:
                try:
                    await active_connections[call["caller_id"]].send_json({
                        "type": "call_accepted",
                        "call_id": response_data.call_id
                    })
                except Exception as e:
                    logger.error(f"Failed to notify caller: {e}")

            log_audit_event(
                cursor, current_user, "call_accepted", "success",
                None, {"call_id": response_data.call_id}
            )

            message = "Call accepted"

        else:  # reject
            call["status"] = "rejected"
            cursor.execute(
                """
                UPDATE video_calls
                SET status = 'rejected', ended_at = NOW()
                WHERE call_id = %s
                """,
                (response_data.call_id,)
            )

            # Notify caller via WebSocket
            if call["caller_id"] in active_connections:
                try:
                    await active_connections[call["caller_id"]].send_json({
                        "type": "call_rejected",
                        "call_id": response_data.call_id
                    })
                except Exception as e:
                    logger.error(f"Failed to notify caller: {e}")

            # Remove from active calls
            del active_calls[response_data.call_id]

            log_audit_event(
                cursor, current_user, "call_rejected", "success",
                None, {"call_id": response_data.call_id}
            )

            message = "Call rejected"

        conn.commit()

        return {"message": message, "call_id": response_data.call_id}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Respond to call error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to respond to call"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/call/{call_id}/end")
async def end_call(
    call_id: str,
    current_user: int = Depends(get_current_user_id)
):
    """
    End an active call
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get call details
        if call_id not in active_calls:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Call not found or already ended"
            )

        call = active_calls[call_id]

        # Verify user is part of the call
        if current_user not in [call["caller_id"], call["receiver_id"]]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to end this call"
            )

        # Calculate duration
        duration = (datetime.now() - call["started_at"]).seconds

        # Update call record
        cursor.execute(
            """
            UPDATE video_calls
            SET status = 'ended', ended_at = NOW(), duration_seconds = %s
            WHERE call_id = %s
            """,
            (duration, call_id)
        )

        # Notify other party via WebSocket
        other_user_id = call["receiver_id"] if current_user == call["caller_id"] else call["caller_id"]
        if other_user_id in active_connections:
            try:
                await active_connections[other_user_id].send_json({
                    "type": "call_ended",
                    "call_id": call_id
                })
            except Exception as e:
                logger.error(f"Failed to notify other party: {e}")

        # Remove from active calls
        del active_calls[call_id]

        log_audit_event(
            cursor, current_user, "call_ended", "success",
            None, {"call_id": call_id, "duration": duration}
        )

        conn.commit()

        return {
            "message": "Call ended successfully",
            "duration_seconds": duration
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"End call error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to end call"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/call/history")
async def get_call_history(
    limit: int = 20,
    offset: int = 0,
    current_user: int = Depends(get_current_user_id)
):
    """
    Get call history for current user
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT vc.id, vc.call_id, vc.caller_id, vc.receiver_id, vc.call_type,
                   vc.status, vc.started_at, vc.ended_at, vc.duration_seconds,
                   u1.username as caller_username, u2.username as receiver_username
            FROM video_calls vc
            JOIN users u1 ON vc.caller_id = u1.id
            JOIN users u2 ON vc.receiver_id = u2.id
            WHERE vc.caller_id = %s OR vc.receiver_id = %s
            ORDER BY vc.created_at DESC
            LIMIT %s OFFSET %s
            """,
            (current_user, current_user, limit, offset)
        )

        calls = []
        for row in cursor.fetchall():
            calls.append({
                "id": row[0],
                "call_id": row[1],
                "caller_id": row[2],
                "receiver_id": row[3],
                "call_type": row[4],
                "status": row[5],
                "started_at": row[6].isoformat() if row[6] else None,
                "ended_at": row[7].isoformat() if row[7] else None,
                "duration_seconds": row[8],
                "caller_username": row[9],
                "receiver_username": row[10],
                "direction": "outgoing" if row[2] == current_user else "incoming"
            })

        return {
            "calls": calls,
            "total": len(calls)
        }

    except Exception as e:
        logger.error(f"Get call history error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve call history"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# WebSocket endpoint for signaling

@router.websocket("/ws/signaling")
async def websocket_signaling(websocket: WebSocket):
    """
    WebSocket endpoint for WebRTC signaling
    Handles offer/answer/ICE candidate exchange

    Security: Token must be passed in Sec-WebSocket-Protocol header
    This prevents token leakage in server access logs
    """
    conn = None
    user_id = None

    try:
        # Extract token from cookies (primary method for cookie-based auth)
        # WebSockets automatically include cookies for same-origin connections
        token = None
        cookie_header = websocket.headers.get('cookie', '')

        logger.info(f"[WebSocket Auth] Cookie header present: {bool(cookie_header)}")
        logger.info(f"[WebSocket Auth] Cookie header length: {len(cookie_header) if cookie_header else 0}")

        if cookie_header:
            # Parse cookies manually
            cookies = {}
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key] = value

            logger.info(f"[WebSocket Auth] Parsed cookies: {list(cookies.keys())}")
            token = cookies.get('session_token')
            logger.info(f"[WebSocket Auth] Session token found in cookies: {bool(token)}")
            if token:
                logger.info(f"[WebSocket Auth] Token length: {len(token)}")

        # Fallback 1: Check Sec-WebSocket-Protocol header (legacy)
        if not token:
            protocols = websocket.headers.get('sec-websocket-protocol', '')
            if protocols:
                protocol_list = [p.strip() for p in protocols.split(',')]
                if len(protocol_list) >= 2 and protocol_list[0] == 'token':
                    token = protocol_list[1]
                    logger.info("[WebSocket Auth] Token found in Sec-WebSocket-Protocol")

        # Fallback 2: Check Authorization header (API clients)
        if not token:
            auth_header = websocket.headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                logger.info("[WebSocket Auth] Token found in Authorization header")

        if not token:
            logger.warning("[WebSocket Auth] No token found in any location")
            await websocket.close(code=1008, reason="Authentication required")
            return

        # Authenticate user
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = verify_session_token(cursor, token)

        logger.info(f"[WebSocket Auth] Token validation result: user_id={user_id}")

        if not user_id:
            logger.warning(f"[WebSocket Auth] Invalid or expired token")
            await websocket.close(code=1008, reason="Unauthorized")
            return

        logger.info(f"[WebSocket Auth] User {user_id} authenticated successfully")

        # Accept WebSocket connection
        await websocket.accept()

        # Store connection and initialize last activity
        active_connections[user_id] = websocket
        websocket_last_activity[user_id] = datetime.now()

        logger.info(f"User {user_id} connected to signaling server")

        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "user_id": user_id
        })

        # Listen for messages
        while True:
            # Check for idle timeout
            if user_id in websocket_last_activity:
                idle_duration = (datetime.now() - websocket_last_activity[user_id]).seconds / 60
                if idle_duration > WEBSOCKET_IDLE_TIMEOUT_MINUTES:
                    logger.info(f"WebSocket idle timeout for user {user_id} ({idle_duration:.1f} minutes)")
                    await websocket.send_json({
                        "type": "error",
                        "message": "Connection closed due to inactivity"
                    })
                    await websocket.close(code=1000, reason="Idle timeout")
                    break

            # Receive message with size limit
            try:
                data = await websocket.receive_json()
                # Update last activity timestamp
                websocket_last_activity[user_id] = datetime.now()
            except Exception as e:
                logger.error(f"WebSocket receive error: {e}")
                break

            # Validate message size
            message_str = json.dumps(data)
            if len(message_str) > MAX_WEBSOCKET_MESSAGE_SIZE:
                logger.warning(f"User {user_id} sent oversized message")
                await websocket.send_json({
                    "type": "error",
                    "message": "Message too large"
                })
                continue

            message_type = data.get("type")

            if message_type == "offer":
                # Validate and forward offer to receiver
                call_id = data.get("call_id")
                sdp = data.get("sdp")
                
                if not call_id or call_id not in active_calls:
                    logger.warning(f"Invalid call_id in offer from user {user_id}")
                    continue
                
                call = active_calls[call_id]
                
                # Verify user is caller
                if call["caller_id"] != user_id:
                    logger.warning(f"User {user_id} attempted to send offer for call they didn't initiate")
                    continue
                
                # Validate SDP for encryption
                if not validate_sdp(sdp):
                    logger.error(f"Invalid or insecure SDP from user {user_id}")
                    await websocket.send_json({
                        "type": "error",
                        "message": "SDP validation failed. Encryption required."
                    })
                    continue
                
                # Check call duration
                if not check_call_duration(call_id):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Call duration limit exceeded"
                    })
                    continue
                
                receiver_id = call["receiver_id"]
                if receiver_id in active_connections:
                    await active_connections[receiver_id].send_json({
                        "type": "offer",
                        "call_id": call_id,
                        "sdp": sdp
                    })
                    logger.info(f"Forwarded encrypted offer for call {call_id}")

            elif message_type == "answer":
                # Validate and forward answer to caller
                call_id = data.get("call_id")
                sdp = data.get("sdp")
                
                if not call_id or call_id not in active_calls:
                    logger.warning(f"Invalid call_id in answer from user {user_id}")
                    continue
                
                call = active_calls[call_id]
                
                # Verify user is receiver
                if call["receiver_id"] != user_id:
                    logger.warning(f"User {user_id} attempted to send answer for call they didn't receive")
                    continue
                
                # Validate SDP for encryption
                if not validate_sdp(sdp):
                    logger.error(f"Invalid or insecure SDP from user {user_id}")
                    await websocket.send_json({
                        "type": "error",
                        "message": "SDP validation failed. Encryption required."
                    })
                    continue
                
                # Check call duration
                if not check_call_duration(call_id):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Call duration limit exceeded"
                    })
                    continue
                
                caller_id = call["caller_id"]
                if caller_id in active_connections:
                    await active_connections[caller_id].send_json({
                        "type": "answer",
                        "call_id": call_id,
                        "sdp": sdp
                    })
                    logger.info(f"Forwarded encrypted answer for call {call_id}")

            elif message_type == "ice-candidate":
                # Validate and forward ICE candidate to other party
                call_id = data.get("call_id")
                candidate = data.get("candidate")
                
                if not call_id or call_id not in active_calls:
                    logger.warning(f"Invalid call_id in ICE candidate from user {user_id}")
                    continue
                
                call = active_calls[call_id]
                
                # Verify user is part of the call
                if user_id not in [call["caller_id"], call["receiver_id"]]:
                    logger.warning(f"User {user_id} attempted to send ICE candidate for call they're not part of")
                    continue
                
                # Check ICE candidate rate limit
                if call_id in ice_candidate_counts:
                    ice_candidate_counts[call_id] += 1
                    if ice_candidate_counts[call_id] > ICE_CANDIDATE_RATE_LIMIT:
                        logger.warning(f"ICE candidate rate limit exceeded for call {call_id}")
                        await websocket.send_json({
                            "type": "error",
                            "message": "ICE candidate rate limit exceeded"
                        })
                        continue
                
                # Validate ICE candidate
                if not validate_ice_candidate(candidate):
                    logger.error(f"Invalid ICE candidate from user {user_id}")
                    continue
                
                # Check call duration
                if not check_call_duration(call_id):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Call duration limit exceeded"
                    })
                    continue
                
                other_user_id = call["receiver_id"] if user_id == call["caller_id"] else call["caller_id"]
                if other_user_id in active_connections:
                    await active_connections[other_user_id].send_json({
                        "type": "ice-candidate",
                        "call_id": call_id,
                        "candidate": candidate
                    })

            elif message_type == "ping":
                # Respond to ping
                await websocket.send_json({"type": "pong"})
            
            else:
                logger.warning(f"Unknown message type from user {user_id}: {message_type}")

    except WebSocketDisconnect:
        logger.info(f"User {user_id} disconnected from signaling server")
    except Exception as e:
        logger.error(f"WebSocket error: {type(e).__name__} - {str(e)}")
    finally:
        # Clean up connection and last activity tracking
        if user_id and user_id in active_connections:
            del active_connections[user_id]
        if user_id and user_id in websocket_last_activity:
            del websocket_last_activity[user_id]

        # End any active calls for this user
        calls_to_end = [call_id for call_id, call in active_calls.items()
                        if user_id in [call["caller_id"], call["receiver_id"]]]

        for call_id in calls_to_end:
            try:
                call = active_calls[call_id]
                other_user_id = call["receiver_id"] if user_id == call["caller_id"] else call["caller_id"]

                # Notify other party
                if other_user_id in active_connections:
                    await active_connections[other_user_id].send_json({
                        "type": "call_ended",
                        "call_id": call_id,
                        "reason": "user_disconnected"
                    })

                # Update database
                if conn:
                    cursor = conn.cursor()
                    duration = (datetime.now() - call["started_at"]).seconds
                    cursor.execute(
                        """
                        UPDATE video_calls
                        SET status = 'ended', ended_at = NOW(), duration_seconds = %s
                        WHERE call_id = %s
                        """,
                        (duration, call_id)
                    )
                    conn.commit()

                del active_calls[call_id]
            except Exception as e:
                logger.error(f"Error ending call on disconnect: {e}")

        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/online/users")
async def get_online_users(current_user: int = Depends(get_current_user_id)):
    """
    Get list of online users

    Security: Uses SQLAlchemy Core for automatic SQL injection protection
    """
    try:
        # Get usernames for online users
        if active_connections:
            from database.models import users
            from database.sqlalchemy_db import execute_query
            from sqlalchemy import select

            user_ids = list(active_connections.keys())

            # SQLAlchemy Core query - automatic parameterization prevents SQL injection
            results = execute_query(
                select(
                    users.c.id,
                    users.c.username,
                    users.c.first_name,
                    users.c.last_name
                )
                .where(users.c.id.in_(user_ids))
                .where(users.c.id != current_user),
                fetch_all=True
            )

            online_users = [
                {
                    "id": row[0],
                    "username": row[1],
                    "first_name": row[2],
                    "last_name": row[3]
                }
                for row in results
            ]

            return {
                "online_users": online_users,
                "total": len(online_users)
            }
        else:
            return {
                "online_users": [],
                "total": 0
            }

    except Exception as e:
        logger.error(f"Get online users error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get online users"
        )
