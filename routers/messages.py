"""
routers/messages.py
Secure messaging router for user-to-user communication
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.audit import log_audit_event
from utils.encryption import (
    decrypt_user_key, encrypt_message, decrypt_message,
    encrypt_message_for_users
)
from utils.auth_dependencies import require_auth, require_admin
from utils.input_sanitizer import (
    comprehensive_input_scan,
    log_malicious_input
)
from utils.team_access import verify_team_access

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Pydantic Models

class MessageCreate(BaseModel):
    """Model for creating a new message"""
    receiver_id: int = Field(..., gt=0)
    subject: Optional[str] = Field(None, max_length=255)
    content: str = Field(..., min_length=1, max_length=10000)

    @validator('content')
    def validate_content(cls, v):
        """Basic content validation"""
        # Strip leading/trailing whitespace
        v = v.strip()
        if not v:
            raise ValueError('Message content cannot be empty')
        # Check for excessive special characters (possible spam)
        special_chars = sum(1 for c in v if not c.isalnum() and not c.isspace())
        if len(v) > 0 and special_chars / len(v) > 0.5:
            raise ValueError('Message content appears to be spam')
        return v

    @validator('subject')
    def validate_subject(cls, v):
        """Validate subject if provided"""
        if v:
            v = v.strip()
            if not v:
                return None
        return v


class MessageResponse(BaseModel):
    """Model for message response"""
    id: int
    sender_id: int
    sender_username: str
    receiver_id: int
    receiver_username: str
    subject: Optional[str]
    content: str
    is_read: bool
    read_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class MessageListResponse(BaseModel):
    """Model for message list response"""
    messages: List[MessageResponse]
    total: int
    unread_count: int


# Helper Functions

async def get_current_user_id(current_user: dict = Depends(require_auth)) -> int:
    """Get current user ID from authentication dependency"""
    return current_user["id"]


# Message Endpoints

@router.post("/send", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")
async def send_message(
    message_data: MessageCreate,
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Send a message to another user
    """
    conn = None

    try:
        # Scan message content for malicious input
        is_malicious_content, attack_type_content, pattern_content = comprehensive_input_scan(
            message_data.content
        )
        if is_malicious_content:
            log_malicious_input(
                user_id=current_user,
                input_value="[MESSAGE CONTENT REDACTED]",
                attack_type=attack_type_content,
                pattern=pattern_content,
                ip_address=request.client.host if request.client else None,
                endpoint="/api/v1/messages/send",
                severity="high"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected in message content"
            )

        # Scan subject if provided
        if message_data.subject:
            is_malicious_subject, attack_type_subject, pattern_subject = comprehensive_input_scan(
                message_data.subject
            )
            if is_malicious_subject:
                log_malicious_input(
                    user_id=current_user,
                    input_value=message_data.subject,
                    attack_type=attack_type_subject,
                    pattern=pattern_subject,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/messages/send",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in message subject"
                )

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if receiver exists and is active, get encryption key
        cursor.execute(
            """
            SELECT id, is_active, account_status, encryption_key
            FROM users
            WHERE id = %s
            """,
            (message_data.receiver_id,)
        )

        receiver = cursor.fetchone()

        if not receiver:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Receiver not found"
            )

        receiver_id, is_active, account_status, receiver_encrypted_key = receiver

        if not is_active or account_status != 'active':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot send message to inactive user"
            )

        # Prevent sending message to self
        if current_user == message_data.receiver_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot send message to yourself"
            )

        # TEAM-BASED ACCESS CONTROL: Verify users share at least one team
        if not verify_team_access(current_user, message_data.receiver_id, action="send message to"):
            # Log security event for unauthorized access attempt
            log_audit_event(
                cursor, current_user, "unauthorized_message_attempt", "failed",
                request.client.host if request.client else None,
                {
                    "receiver_id": message_data.receiver_id,
                    "reason": "users_not_in_same_team"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only send messages to members of your teams"
            )

        # Get sender's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (current_user,)
        )
        sender_encrypted_key = cursor.fetchone()[0]

        # Decrypt both user keys using master key
        sender_key = decrypt_user_key(sender_encrypted_key)
        receiver_key = decrypt_user_key(receiver_encrypted_key)

        # Encrypt message for both sender and receiver
        content_sender, content_receiver = encrypt_message_for_users(
            message_data.content,
            sender_key,
            receiver_key
        )

        # Insert encrypted message
        cursor.execute(
            """
            INSERT INTO messages (sender_id, receiver_id, subject, content_sender, content_receiver)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (current_user, message_data.receiver_id, message_data.subject, content_sender, content_receiver)
        )

        message_id, created_at = cursor.fetchone()

        # Log audit event
        log_audit_event(
            cursor, current_user, "message_sent", "success",
            request.client.host if request.client else None,
            {"receiver_id": message_data.receiver_id, "message_id": message_id}
        )

        conn.commit()

        logger.info(f"Message sent from user {current_user} to user {message_data.receiver_id}")

        return {
            "message": "Message sent successfully",
            "message_id": message_id,
            "created_at": created_at
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Send message error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send message"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/inbox")
@limiter.limit("300/hour")  # 5 per minute - allows frontend polling every 15s
async def get_inbox(
    request: Request,
    unread_only: bool = False,
    current_user: int = Depends(get_current_user_id)
):
    """
    Get all messages received by the current user
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's decryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (current_user,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Build query
        query = """
            SELECT m.id, m.sender_id, m.receiver_id, m.subject, m.content_receiver,
                   m.is_read, m.read_at, m.created_at, m.updated_at,
                   s.username as sender_username, r.username as receiver_username
            FROM messages m
            JOIN users s ON m.sender_id = s.id
            JOIN users r ON m.receiver_id = r.id
            WHERE m.receiver_id = %s
              AND m.deleted_by_receiver = FALSE
        """

        params = [current_user]

        if unread_only:
            query += " AND m.is_read = FALSE"

        query += " ORDER BY m.created_at DESC"

        cursor.execute(query, params)
        messages = cursor.fetchall()

        # Get unread count
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM messages
            WHERE receiver_id = %s
              AND is_read = FALSE
              AND deleted_by_receiver = FALSE
            """,
            (current_user,)
        )
        unread_count = cursor.fetchone()[0]

        # Format response - decrypt messages
        message_list = []
        for msg in messages:
            try:
                decrypted_content = decrypt_message(msg[4], user_key)
            except:
                decrypted_content = "[Error: Unable to decrypt message]"

            message_list.append({
                "id": msg[0],
                "sender_id": msg[1],
                "sender_username": msg[9],
                "receiver_id": msg[2],
                "receiver_username": msg[10],
                "subject": msg[3],
                "content": decrypted_content,
                "is_read": msg[5],
                "read_at": msg[6],
                "created_at": msg[7],
                "updated_at": msg[8]
            })

        return {
            "messages": message_list,
            "total": len(message_list),
            "unread_count": unread_count
        }

    except Exception as e:
        logger.error(f"Get inbox error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve messages"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/sent")
@limiter.limit("300/hour")  # 5 per minute - allows frontend polling every 15s
async def get_sent_messages(
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Get all messages sent by the current user
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's decryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (current_user,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        cursor.execute(
            """
            SELECT m.id, m.sender_id, m.receiver_id, m.subject, m.content_sender,
                   m.is_read, m.read_at, m.created_at, m.updated_at,
                   s.username as sender_username, r.username as receiver_username
            FROM messages m
            JOIN users s ON m.sender_id = s.id
            JOIN users r ON m.receiver_id = r.id
            WHERE m.sender_id = %s
              AND m.deleted_by_sender = FALSE
            ORDER BY m.created_at DESC
            """,
            (current_user,)
        )

        messages = cursor.fetchall()

        # Format response - decrypt messages
        message_list = []
        for msg in messages:
            try:
                decrypted_content = decrypt_message(msg[4], user_key)
            except:
                decrypted_content = "[Error: Unable to decrypt message]"

            message_list.append({
                "id": msg[0],
                "sender_id": msg[1],
                "sender_username": msg[9],
                "receiver_id": msg[2],
                "receiver_username": msg[10],
                "subject": msg[3],
                "content": decrypted_content,
                "is_read": msg[5],
                "read_at": msg[6],
                "created_at": msg[7],
                "updated_at": msg[8]
            })

        return {
            "messages": message_list,
            "total": len(message_list)
        }

    except Exception as e:
        logger.error(f"Get sent messages error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve messages"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/{message_id}")
@limiter.limit("100/hour")
async def get_message(
    message_id: int,
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Get a specific message by ID
    Automatically marks as read if user is the receiver
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's decryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (current_user,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get message
        cursor.execute(
            """
            SELECT m.id, m.sender_id, m.receiver_id, m.subject, m.content_sender, m.content_receiver,
                   m.is_read, m.read_at, m.created_at, m.updated_at,
                   s.username as sender_username, r.username as receiver_username
            FROM messages m
            JOIN users s ON m.sender_id = s.id
            JOIN users r ON m.receiver_id = r.id
            WHERE m.id = %s
              AND (m.sender_id = %s OR m.receiver_id = %s)
            """,
            (message_id, current_user, current_user)
        )

        message = cursor.fetchone()

        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )

        # Determine which encrypted content to decrypt (sender or receiver)
        if message[1] == current_user:
            # Current user is sender
            encrypted_content = message[4]
        else:
            # Current user is receiver
            encrypted_content = message[5]

        # Decrypt message
        try:
            decrypted_content = decrypt_message(encrypted_content, user_key)
        except:
            decrypted_content = "[Error: Unable to decrypt message]"

        # Mark as read if user is receiver and not already read
        if message[2] == current_user and not message[6]:
            cursor.execute(
                """
                UPDATE messages
                SET is_read = TRUE, read_at = NOW()
                WHERE id = %s
                RETURNING read_at
                """,
                (message_id,)
            )
            read_at = cursor.fetchone()[0]
            conn.commit()
        else:
            read_at = message[7]

        return {
            "id": message[0],
            "sender_id": message[1],
            "sender_username": message[10],
            "receiver_id": message[2],
            "receiver_username": message[11],
            "subject": message[3],
            "content": decrypted_content,
            "is_read": message[2] == current_user,  # True if current user is receiver
            "read_at": read_at,
            "created_at": message[8],
            "updated_at": message[9]
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Get message error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve message"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.delete("/{message_id}")
@limiter.limit("10/hour")
async def delete_message(
    message_id: int,
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Delete a message (soft delete)
    Users can only delete their own messages (sent or received)
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Soft delete message
        cursor.execute(
            """
            UPDATE messages
            SET deleted_by_sender = CASE WHEN sender_id = %s THEN TRUE ELSE deleted_by_sender END,
                deleted_by_receiver = CASE WHEN receiver_id = %s THEN TRUE ELSE deleted_by_receiver END
            WHERE id = %s AND (sender_id = %s OR receiver_id = %s)
            RETURNING id
            """,
            (current_user, current_user, message_id, current_user, current_user)
        )

        result = cursor.fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )

        conn.commit()

        return {"message": "Message deleted successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Delete message error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete message"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/unread/count")
@limiter.limit("300/hour")  # 5 per minute - allows frequent polling for notifications
async def get_unread_count(
    request: Request,
    current_user: int = Depends(get_current_user_id)
):
    """
    Get count of unread messages for current user
    """
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM messages
            WHERE receiver_id = %s
              AND is_read = FALSE
              AND deleted_by_receiver = FALSE
            """,
            (current_user,)
        )

        count = cursor.fetchone()[0]

        return {"unread_count": count}

    except Exception as e:
        logger.error(f"Get unread count error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get unread count"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)
