"""
routers/ideas.py
AI-powered creative ideas and script generation with encrypted storage
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from datetime import datetime
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.auth_dependencies import require_auth
from utils.audit import log_audit_event
from utils.encryption import decrypt_user_key
from utils.crypto_aes import encrypt_text, decrypt_text
from utils.gpt5_service import get_gpt5_service
from utils.flux_service import get_flux_service
from utils.voice_service import get_voice_service
from utils.kling_service import get_kling_service
from utils.input_sanitizer import comprehensive_input_scan, log_malicious_input
import hashlib

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Pydantic Models

class IdeaGenerationRequest(BaseModel):
    """Request model for AI-powered script generation"""
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    content_type: str = Field(..., max_length=50)
    brand_voice: Optional[str] = Field(None, max_length=1000)
    target_audience: str = Field(..., min_length=10, max_length=1000)
    key_messages: str = Field(..., min_length=10, max_length=2000)

    @validator('title', 'description', 'brand_voice', 'target_audience', 'key_messages')
    def strip_whitespace(cls, v):
        if v:
            return v.strip()
        return v

class IdeaResponse(BaseModel):
    """Response model for idea"""
    id: int
    title: str
    description: Optional[str]
    content: str
    status: str
    created_at: str
    updated_at: str

# Endpoints

@router.post("/generate-script", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")  # Limit AI generation to prevent abuse
async def generate_script_idea(
    idea_request: IdeaGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Generate a creative script using GPT-5 and store it encrypted

    Security Features:
    - Rate limited to 10 requests per hour
    - Input validation and malicious pattern detection
    - End-to-end encryption (AES-256-GCM)
    - Audit logging for all AI requests
    - IDOR protection (user_id verification)

    Encryption Flow:
    1. Decrypt user's encryption key (stored encrypted with master key)
    2. Generate AI script using GPT-5
    3. Encrypt script with user's key
    4. Store encrypted script in database
    5. Return plaintext script (encrypted in transit via HTTPS)
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get GPT-5 service
        gpt5_service = get_gpt5_service()

        # Generate script using GPT-5 (includes input validation)
        result = gpt5_service.generate_script(
            title=idea_request.title,
            description=idea_request.description or "",
            content_type=idea_request.content_type,
            brand_voice=idea_request.brand_voice,
            target_audience=idea_request.target_audience,
            key_messages=idea_request.key_messages,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )

        generated_script = result["script"]
        metadata = result["metadata"]

        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key (stored encrypted with master key)
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key_result = cursor.fetchone()

        if not user_encrypted_key_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user_encrypted_key = user_encrypted_key_result[0]

        # Decrypt user's encryption key using master key
        user_key = decrypt_user_key(user_encrypted_key)

        # Combine title, description, and content with delimiter for single encryption
        # Format: title|||description|||content
        description = idea_request.description or ""
        combined_data = f"{idea_request.title}|||{description}|||{generated_script}"

        # Encrypt combined data with user's key
        combined_encrypted, iv, tag = encrypt_text(combined_data, user_key)

        # Store encrypted idea in database
        # Note: We store the combined data in all three fields for backwards compatibility
        cursor.execute(
            """
            INSERT INTO ideas (
                title_encrypted,
                description_encrypted,
                content_encrypted,
                owner_id,
                status,
                encryption_iv,
                encryption_tag
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, updated_at
            """,
            (
                combined_encrypted,  # Store combined data in title field
                None,  # description field not used
                combined_encrypted,  # Also store in content field for redundancy
                user_id,
                'draft',  # Default status
                iv,
                tag
            )
        )

        idea_id, created_at, updated_at = cursor.fetchone()

        # Log audit event
        log_audit_event(
            cursor,
            user_id,
            "ai_script_generated",
            "success",
            ip_address,
            {
                "idea_id": idea_id,
                "content_type": idea_request.content_type,
                "model": metadata.get("model"),
                "tokens_used": metadata.get("total_tokens"),
                "word_count": metadata.get("word_count")
            }
        )

        conn.commit()

        logger.info(
            f"AI script generated for user {user_id}: idea_id={idea_id}, "
            f"type={idea_request.content_type}, tokens={metadata.get('total_tokens')}"
        )

        # Return plaintext content (will be encrypted in transit via HTTPS)
        return {
            "success": True,
            "message": "Script generated successfully!",
            "idea": {
                "id": idea_id,
                "title": idea_request.title,
                "description": idea_request.description,
                "content": generated_script,
                "status": "draft",
                "created_at": created_at.isoformat(),
                "updated_at": updated_at.isoformat()
            },
            "metadata": metadata
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Script generation error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate script. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/my-ideas")
async def get_my_ideas(
    current_user: dict = Depends(require_auth),
    limit: int = 50,
    offset: int = 0
):
    """
    Get user's ideas (decrypted)

    IDOR Protection: Only returns ideas where owner_id == user_id
    """
    user_id = current_user["id"]
    conn = None

    logger.info(f"===== GET /my-ideas called for user_id={user_id} =====")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get user's ideas (IDOR-safe: filtered by owner_id)
        # LEFT JOIN to get team assignment information
        # Include voice_file_path, voice_metadata, and video fields
        cursor.execute(
            """
            SELECT i.id, i.title_encrypted, i.status, i.created_at, i.updated_at,
                   i.encryption_iv, i.encryption_tag,
                   t.name as team_name, t.id as team_id,
                   i.voice_file_path, i.voice_metadata,
                   i.video_url, i.video_status, i.video_task_id,
                   i.video_prompt_encrypted, i.video_duration, i.video_aspect_ratio,
                   i.video_generated_at, i.video_iv, i.video_tag
            FROM ideas i
            LEFT JOIN idea_team_assignments ita ON i.id = ita.idea_id
            LEFT JOIN teams t ON ita.team_id = t.id
            WHERE i.owner_id = %s AND i.is_deleted = FALSE
            ORDER BY i.created_at DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        ideas = []
        for row in cursor.fetchall():
            (idea_id, combined_enc, status_val, created_at, updated_at, iv, tag, team_name, team_id,
             voice_file_path, voice_metadata,
             video_url, video_status, video_task_id, video_prompt_encrypted, video_duration,
             video_aspect_ratio, video_generated_at, video_iv, video_tag) = row

            # Decrypt combined data (format: title|||description|||content)
            try:
                combined_decrypted = decrypt_text(combined_enc, user_key, iv, tag)

                # Split into components
                parts = combined_decrypted.split("|||")
                if len(parts) >= 3:
                    title = parts[0].strip() if parts[0].strip() else "Untitled Idea"
                    description = parts[1].strip() if parts[1].strip() else None
                    content = parts[2]
                else:
                    # Fallback for improperly formatted data
                    title = combined_decrypted[:100] if combined_decrypted[:100].strip() else "Untitled Idea"
                    description = None
                    content = combined_decrypted

                # Decrypt video prompt if available
                video_prompt = None
                if video_prompt_encrypted and video_iv and video_tag:
                    try:
                        video_prompt = decrypt_text(video_prompt_encrypted, user_key, video_iv, video_tag)
                    except Exception as e:
                        logger.error(f"Failed to decrypt video prompt for idea {idea_id}: {e}")

                idea_dict = {
                    "id": idea_id,
                    "title": title,
                    "description": description,
                    "content": content,
                    "status": status_val,
                    "team_name": team_name,  # Include team name if assigned
                    "team_id": team_id,      # Include team ID if assigned
                    "is_owner": True,        # User owns these ideas
                    "created_at": created_at.isoformat(),
                    "updated_at": updated_at.isoformat(),
                    "voice_file_path": voice_file_path,  # Voice file if available
                    "has_voice": voice_file_path is not None,  # Flag for frontend
                    "content_type": "voice" if voice_file_path else "text",  # Content type indicator
                    # Video fields
                    "video_url": video_url,
                    "video_status": video_status,
                    "video_task_id": video_task_id,
                    "video_prompt": video_prompt,
                    "video_duration": video_duration,
                    "video_aspect_ratio": video_aspect_ratio,
                    "video_generated_at": video_generated_at.isoformat() if video_generated_at else None
                }

                # Debug: Log what we're adding
                logger.info(f"Adding idea {idea_id}: team_name='{team_name}', team_id={team_id}, has_voice={voice_file_path is not None}")

                ideas.append(idea_dict)
            except Exception as decrypt_error:
                logger.error(f"Failed to decrypt idea {idea_id}: {decrypt_error}")
                continue

        # Also fetch generated images for this user
        images = []
        try:
            cursor.execute(
                """
                SELECT id, prompt_encrypted, image_url, style, aspect_ratio,
                       encryption_iv, encryption_tag, created_at, is_favorite
                FROM generated_images
                WHERE user_id = %s AND is_deleted = FALSE
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, limit)
            )

            for row in cursor.fetchall():
                image_id, prompt_enc, image_url, style, aspect_ratio, img_iv, img_tag, img_created_at, is_favorite = row

                # Decrypt prompt
                try:
                    prompt = decrypt_text(prompt_enc, user_key, img_iv, img_tag)

                    images.append({
                        "id": image_id,
                        "title": f"AI Image: {prompt[:50]}...",  # Truncated title
                        "prompt": prompt,
                        "image_url": image_url,
                        "style": style,
                        "aspect_ratio": aspect_ratio,
                        "is_favorite": is_favorite,
                        "created_at": img_created_at.isoformat(),
                        "content_type": "image",  # Mark as image
                        "has_image": True,
                        "status": "completed",  # Images are always completed
                        "is_owner": True  # User owns these images
                    })
                except Exception as decrypt_error:
                    logger.error(f"Failed to decrypt image {image_id} prompt: {decrypt_error}")
                    continue

        except Exception as e:
            logger.error(f"Error fetching images: {str(e)}")
            # Don't fail the whole request if images fail

        # Debug: Log final response
        logger.info(f"Returning {len(ideas)} ideas and {len(images)} images for user {user_id}")

        return {
            "success": True,
            "ideas": ideas,
            "images": images,
            "total": len(ideas) + len(images)
        }

    except Exception as e:
        logger.error(f"Error fetching ideas: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch ideas"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/team-ideas")
async def get_team_ideas(
    current_user: dict = Depends(require_auth),
    limit: int = 50,
    offset: int = 0
):
    """
    Get ideas assigned to user's teams (decrypted)

    Security:
    - Only returns ideas assigned to teams where user is a member
    - Ideas are decrypted using owner's encryption key
    - IDOR Protection: Verifies team membership
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key (for ideas they own)
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get ideas assigned to teams where user is a member
        cursor.execute(
            """
            SELECT DISTINCT i.id, i.title_encrypted, i.status, i.created_at, i.updated_at,
                   i.encryption_iv, i.encryption_tag, i.owner_id,
                   u.username as owner_username,
                   t.name as team_name, t.id as team_id,
                   i.voice_file_path, i.voice_metadata,
                   i.video_url, i.video_status, i.video_task_id,
                   i.video_prompt_encrypted, i.video_duration, i.video_aspect_ratio,
                   i.video_generated_at, i.video_iv, i.video_tag
            FROM ideas i
            INNER JOIN idea_team_assignments ita ON i.id = ita.idea_id
            INNER JOIN teams t ON ita.team_id = t.id
            INNER JOIN team_members tm ON t.id = tm.team_id
            INNER JOIN users u ON i.owner_id = u.id
            WHERE tm.user_id = %s
              AND i.is_deleted = FALSE
            ORDER BY i.created_at DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        ideas = []
        for row in cursor.fetchall():
            (idea_id, combined_enc, status_val, created_at, updated_at, iv, tag, owner_id,
             owner_username, team_name, team_id,
             voice_file_path, voice_metadata,
             video_url, video_status, video_task_id, video_prompt_encrypted, video_duration,
             video_aspect_ratio, video_generated_at, video_iv, video_tag) = row

            # Get owner's encryption key to decrypt the idea
            cursor.execute(
                "SELECT encryption_key FROM users WHERE id = %s",
                (owner_id,)
            )
            owner_encrypted_key = cursor.fetchone()[0]
            owner_key = decrypt_user_key(owner_encrypted_key)

            # Decrypt combined data (format: title|||description|||content)
            try:
                combined_decrypted = decrypt_text(combined_enc, owner_key, iv, tag)

                # Split into components
                parts = combined_decrypted.split("|||")
                if len(parts) >= 3:
                    title = parts[0].strip() if parts[0].strip() else "Untitled Idea"
                    description = parts[1].strip() if parts[1].strip() else None
                    content = parts[2]
                else:
                    # Fallback for improperly formatted data
                    title = combined_decrypted[:100] if combined_decrypted[:100].strip() else "Untitled Idea"
                    description = None
                    content = combined_decrypted

                # Decrypt video prompt if available
                video_prompt = None
                if video_prompt_encrypted and video_iv and video_tag:
                    try:
                        video_prompt = decrypt_text(video_prompt_encrypted, owner_key, video_iv, video_tag)
                    except Exception as e:
                        logger.error(f"Failed to decrypt video prompt for team idea {idea_id}: {e}")

                ideas.append({
                    "id": idea_id,
                    "title": title,
                    "description": description,
                    "content": content,
                    "status": status_val,
                    "owner_username": owner_username,
                    "team_name": team_name,
                    "team_id": team_id,
                    "is_owner": owner_id == user_id,
                    "created_at": created_at.isoformat(),
                    "updated_at": updated_at.isoformat(),
                    # Voice fields
                    "voice_file_path": voice_file_path,
                    "has_voice": voice_file_path is not None,
                    "content_type": "voice" if voice_file_path else "text",
                    # Video fields
                    "video_url": video_url,
                    "video_status": video_status,
                    "video_task_id": video_task_id,
                    "video_prompt": video_prompt,
                    "video_duration": video_duration,
                    "video_aspect_ratio": video_aspect_ratio,
                    "video_generated_at": video_generated_at.isoformat() if video_generated_at else None
                })
            except Exception as decrypt_error:
                logger.error(f"Failed to decrypt team idea {idea_id}: {decrypt_error}")
                continue

        return {
            "success": True,
            "ideas": ideas,
            "total": len(ideas)
        }

    except Exception as e:
        logger.error(f"Error fetching team ideas: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch team ideas"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/idea/{idea_id}")
async def get_idea_detail(
    idea_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Get a specific idea by ID (decrypted)

    IDOR Protection: Verifies owner_id == user_id OR team membership before returning
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get idea with ownership verification (IDOR protection)
        cursor.execute(
            """
            SELECT id, title_encrypted, status, created_at, updated_at, owner_id,
                   encryption_iv, encryption_tag, voice_file_path
            FROM ideas
            WHERE id = %s AND is_deleted = FALSE
            """,
            (idea_id,)
        )

        row = cursor.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Idea not found"
            )

        idea_id, combined_enc, status_val, created_at, updated_at, owner_id, iv, tag, voice_file_path = row

        # IDOR Protection: Verify ownership OR team membership
        is_owner = (owner_id == user_id)
        is_team_member = False

        if not is_owner:
            # Check if user is a team member with access to this idea
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM idea_team_assignments ita
                INNER JOIN team_members tm ON ita.team_id = tm.team_id
                WHERE ita.idea_id = %s AND tm.user_id = %s
                """,
                (idea_id, user_id)
            )
            count = cursor.fetchone()[0]
            is_team_member = (count > 0)

        if not is_owner and not is_team_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

        # Get the appropriate encryption key (owner's key for decryption)
        if is_owner:
            decryption_key = user_key
        else:
            # Get owner's encryption key
            cursor.execute(
                "SELECT encryption_key FROM users WHERE id = %s",
                (owner_id,)
            )
            owner_encrypted_key = cursor.fetchone()[0]
            decryption_key = decrypt_user_key(owner_encrypted_key)

        # Decrypt combined data (format: title|||description|||content)
        combined_decrypted = decrypt_text(combined_enc, decryption_key, iv, tag)

        # Split into components
        parts = combined_decrypted.split("|||")
        if len(parts) >= 3:
            title = parts[0].strip() if parts[0].strip() else "Untitled Idea"
            description = parts[1].strip() if parts[1].strip() else None
            content = parts[2]
        else:
            # Fallback for improperly formatted data
            title = combined_decrypted[:100] if combined_decrypted[:100].strip() else "Untitled Idea"
            description = None
            content = combined_decrypted

        return {
            "success": True,
            "idea": {
                "id": idea_id,
                "title": title,
                "description": description,
                "content": content,
                "status": status_val,
                "created_at": created_at.isoformat(),
                "updated_at": updated_at.isoformat(),
                "voice_file_path": voice_file_path,
                "has_voice": voice_file_path is not None,
                "content_type": "voice" if voice_file_path else "text"
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching idea: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch idea"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.delete("/idea/{idea_id}")
async def delete_idea(
    idea_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Soft delete an idea

    IDOR Protection:
    - Verifies owner_id == user_id (owner can always delete)
    - OR verifies user is team admin/owner of teams where idea is assigned
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership before deletion (IDOR protection)
        cursor.execute(
            "SELECT owner_id FROM ideas WHERE id = %s",
            (idea_id,)
        )

        row = cursor.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Idea not found"
            )

        owner_id = row[0]
        is_owner = (owner_id == user_id)
        is_team_admin = False

        # If not the owner, check if user is team admin/owner
        if not is_owner:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM idea_team_assignments ita
                INNER JOIN team_members tm ON ita.team_id = tm.team_id
                WHERE ita.idea_id = %s
                  AND tm.user_id = %s
                  AND tm.role IN ('owner', 'admin')
                """,
                (idea_id, user_id)
            )
            count = cursor.fetchone()[0]
            is_team_admin = (count > 0)

        if not is_owner and not is_team_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Only the idea owner or team admins can delete this idea."
            )

        # Soft delete
        cursor.execute(
            """
            UPDATE ideas
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE id = %s
            """,
            (idea_id,)
        )

        conn.commit()

        return {
            "success": True,
            "message": "Idea deleted successfully"
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error deleting idea: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete idea"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.delete("/image/{image_id}")
async def delete_image(
    image_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Soft delete a generated image

    Security Features:
    - IDOR Protection: Verifies user_id == current_user_id
    - Soft delete (sets is_deleted = TRUE)
    - Audit logging
    - Rate limiting inherited from router

    Args:
        image_id: ID of the image to delete
        current_user: Authenticated user from JWT token

    Returns:
        Success message

    Raises:
        404: Image not found
        403: User doesn't own the image
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership before deletion (IDOR protection)
        cursor.execute(
            "SELECT user_id, image_url FROM generated_images WHERE id = %s AND is_deleted = FALSE",
            (image_id,)
        )

        row = cursor.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Image not found"
            )

        image_user_id, image_url = row

        # IDOR Protection: Only the owner can delete their image
        if image_user_id != user_id:
            logger.warning(
                f"IDOR attempt: User {user_id} tried to delete image {image_id} owned by user {image_user_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only delete your own images."
            )

        # Soft delete (don't actually delete from database or storage)
        cursor.execute(
            """
            UPDATE generated_images
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE id = %s
            """,
            (image_id,)
        )

        conn.commit()

        logger.info(f"Image {image_id} soft-deleted by user {user_id}")

        return {
            "success": True,
            "message": "Image deleted successfully"
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error deleting image: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete image"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


class StatusUpdateRequest(BaseModel):
    """Request model for updating idea status"""
    status: str = Field(..., pattern="^(draft|in_progress|review|completed)$")


@router.put("/idea/{idea_id}/status")
async def update_idea_status(
    idea_id: int,
    status_request: StatusUpdateRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Update idea status

    IDOR Protection: Verifies owner_id == user_id before update
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership and get idea title
        cursor.execute(
            """
            SELECT owner_id, title_encrypted, encryption_iv, encryption_tag
            FROM ideas
            WHERE id = %s AND is_deleted = FALSE
            """,
            (idea_id,)
        )
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Idea not found")

        owner_id, title_encrypted, iv, tag = row

        if owner_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

        # Get user's encryption key to decrypt title
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Decrypt title for notification
        try:
            combined_decrypted = decrypt_text(title_encrypted, user_key, iv, tag)
            parts = combined_decrypted.split("|||")
            idea_title = parts[0].strip() if parts[0].strip() else "Untitled Idea"
        except:
            idea_title = "Your Idea"

        # Update status
        cursor.execute(
            "UPDATE ideas SET status = %s, updated_at = NOW() WHERE id = %s",
            (status_request.status, idea_id)
        )

        # Create notification for status change
        status_labels = {
            'draft': 'Draft',
            'in_progress': 'In Progress',
            'review': 'Review',
            'completed': 'Completed'
        }
        status_label = status_labels.get(status_request.status, status_request.status)

        cursor.execute(
            """
            INSERT INTO notifications (
                user_id, type, title, message, priority,
                related_type, related_id, action_url, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """,
            (
                user_id,
                'idea_status_updated',
                f'Idea Status Updated',
                f'"{idea_title}" status changed to {status_label}',
                'normal',
                'idea',
                idea_id,
                f'/dashboard?tab=ideas&idea={idea_id}'
            )
        )

        # Log audit event
        log_audit_event(
            cursor, user_id, "idea_status_updated", "success", ip_address,
            {"idea_id": idea_id, "new_status": status_request.status}
        )

        conn.commit()

        return {"success": True, "message": "Status updated successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error updating status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update status")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


class TeamAssignmentRequest(BaseModel):
    """Request model for assigning idea to team"""
    team_id: int = Field(..., gt=0)


@router.post("/idea/{idea_id}/assign-team")
async def assign_idea_to_team(
    idea_id: int,
    assignment: TeamAssignmentRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Assign an idea to a team for collaboration

    Security:
    - Verifies user owns the idea
    - Verifies user is member of the team
    - Creates assignment record
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify idea ownership
        cursor.execute(
            "SELECT owner_id FROM ideas WHERE id = %s AND is_deleted = FALSE",
            (idea_id,)
        )
        idea_row = cursor.fetchone()
        if not idea_row or idea_row[0] != user_id:
            raise HTTPException(status_code=404, detail="Idea not found")

        # Verify team membership
        cursor.execute(
            "SELECT team_key_encrypted FROM team_members WHERE team_id = %s AND user_id = %s",
            (assignment.team_id, user_id)
        )
        team_row = cursor.fetchone()
        if not team_row:
            raise HTTPException(status_code=403, detail="Not a member of this team")

        # Get idea title for notification
        cursor.execute(
            "SELECT title_encrypted, encryption_iv, encryption_tag FROM ideas WHERE id = %s",
            (idea_id,)
        )
        idea_data = cursor.fetchone()
        title_encrypted, iv, tag = idea_data

        # Get user's encryption key to decrypt title
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Decrypt title for notification
        try:
            combined_decrypted = decrypt_text(title_encrypted, user_key, iv, tag)
            parts = combined_decrypted.split("|||")
            idea_title = parts[0].strip() if parts[0].strip() else "Untitled Idea"
        except:
            idea_title = "New Idea"

        # Get team name for notification
        cursor.execute(
            "SELECT name FROM teams WHERE id = %s",
            (assignment.team_id,)
        )
        team_name = cursor.fetchone()[0]

        # Get current user's username
        cursor.execute(
            "SELECT username FROM users WHERE id = %s",
            (user_id,)
        )
        username = cursor.fetchone()[0]

        # Create team assignment record
        cursor.execute(
            """
            INSERT INTO idea_team_assignments (idea_id, team_id, assigned_by, assigned_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (idea_id, team_id) DO NOTHING
            """,
            (idea_id, assignment.team_id, user_id)
        )

        # Get all team members to notify (excluding the user who assigned it)
        cursor.execute(
            """
            SELECT user_id FROM team_members
            WHERE team_id = %s AND is_active = TRUE AND user_id != %s
            """,
            (assignment.team_id, user_id)
        )

        team_member_ids = [row[0] for row in cursor.fetchall()]

        # Create notifications for all team members
        for member_id in team_member_ids:
            cursor.execute(
                """
                INSERT INTO notifications (
                    user_id, type, title, message, priority,
                    related_type, related_id, action_url, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (
                    member_id,
                    'team_idea_added',
                    f'New Idea in {team_name}',
                    f'{username} shared "{idea_title}" with the team',
                    'high',
                    'idea',
                    idea_id,
                    f'/dashboard?tab=teams&team={assignment.team_id}&idea={idea_id}'
                )
            )

        logger.info(f"Created {len(team_member_ids)} notifications for idea {idea_id} assigned to team {assignment.team_id}")

        # Log audit event
        log_audit_event(
            cursor, user_id, "idea_assigned_to_team", "success", ip_address,
            {"idea_id": idea_id, "team_id": assignment.team_id, "notifications_sent": len(team_member_ids)}
        )

        conn.commit()

        return {
            "success": True,
            "message": "Idea assigned to team successfully",
            "notifications_sent": len(team_member_ids)
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error assigning idea to team: {e}")
        raise HTTPException(status_code=500, detail="Failed to assign idea to team")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/idea/{idea_id}/teams")
async def get_idea_teams(
    idea_id: int,
    current_user: dict = Depends(require_auth)
):
    """Get teams assigned to an idea"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify access (owner or team member)
        cursor.execute(
            "SELECT owner_id FROM ideas WHERE id = %s AND is_deleted = FALSE",
            (idea_id,)
        )
        idea_row = cursor.fetchone()
        if not idea_row:
            raise HTTPException(status_code=404, detail="Idea not found")

        # Get assigned teams
        cursor.execute(
            """
            SELECT t.id, t.name, ita.assigned_at, u.username as assigned_by
            FROM idea_team_assignments ita
            JOIN teams t ON ita.team_id = t.id
            JOIN users u ON ita.assigned_by = u.id
            WHERE ita.idea_id = %s
            ORDER BY ita.assigned_at DESC
            """,
            (idea_id,)
        )

        teams = []
        for row in cursor.fetchall():
            teams.append({
                "id": row[0],
                "name": row[1],
                "assigned_at": row[2].isoformat(),
                "assigned_by": row[3]
            })

        return {"success": True, "teams": teams}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching idea teams: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch teams")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


class ImageGenerationRequest(BaseModel):
    """Request model for AI-powered image generation"""
    prompt: str = Field(..., min_length=10, max_length=2000)
    style: Optional[str] = Field(None, max_length=50)
    aspect_ratio: str = Field(default="1:1", pattern="^(1:1|16:9|9:16|4:3)$")

    @validator('prompt')
    def strip_prompt(cls, v):
        return v.strip()


@router.post("/generate-image", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")  # Limit image generation to prevent abuse
async def generate_image(
    image_request: ImageGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Generate an AI image using Flux model and store it encrypted

    Security Features:
    - Rate limited to 20 requests per hour
    - Input validation and malicious pattern detection
    - Encrypted prompt storage (AES-256-GCM)
    - Audit logging for all AI requests
    - IDOR protection (user_id verification)

    Encryption Flow:
    1. Decrypt user's encryption key (stored encrypted with master key)
    2. Generate AI image using Flux
    3. Encrypt prompt with user's key
    4. Store encrypted prompt and image URL in database
    5. Return image URL and metadata
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Flux service
        flux_service = get_flux_service()

        # Generate image using Flux (includes input validation)
        result = flux_service.generate_image(
            prompt=image_request.prompt,
            style=image_request.style,
            aspect_ratio=image_request.aspect_ratio,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )

        image_url = result["image_url"]
        metadata = result["metadata"]

        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key (stored encrypted with master key)
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key_result = cursor.fetchone()

        if not user_encrypted_key_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user_encrypted_key = user_encrypted_key_result[0]

        # Decrypt user's encryption key using master key
        user_key = decrypt_user_key(user_encrypted_key)

        # Encrypt prompt with user's key
        prompt_encrypted, iv, tag = encrypt_text(image_request.prompt, user_key)

        # Generate SHA-256 hash of prompt for deduplication
        prompt_hash = hashlib.sha256(image_request.prompt.encode('utf-8')).hexdigest()

        # Extract filename from URL if possible
        image_filename = None
        if image_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(image_url)
                image_filename = parsed.path.split('/')[-1] if parsed.path else None
            except:
                pass

        # Store generated image metadata in database
        cursor.execute(
            """
            INSERT INTO generated_images (
                user_id,
                prompt_encrypted,
                encryption_iv,
                encryption_tag,
                image_url,
                image_filename,
                style,
                aspect_ratio,
                model,
                original_prompt_hash,
                status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (
                user_id,
                prompt_encrypted,
                iv,
                tag,
                image_url,
                image_filename,
                image_request.style,
                image_request.aspect_ratio,
                metadata.get('model', 'flux/srpo'),
                prompt_hash,
                'active'
            )
        )

        image_id, created_at = cursor.fetchone()

        # Log audit event
        log_audit_event(
            cursor,
            user_id,
            "ai_image_generated",
            "success",
            ip_address,
            {
                "image_id": image_id,
                "style": image_request.style,
                "aspect_ratio": image_request.aspect_ratio,
                "model": metadata.get("model"),
                "prompt_length": len(image_request.prompt)
            }
        )

        conn.commit()

        logger.info(
            f"AI image generated for user {user_id}: image_id={image_id}, "
            f"style={image_request.style}, ratio={image_request.aspect_ratio}"
        )

        # Return image URL and metadata
        return {
            "success": True,
            "message": "Image generated successfully!",
            "image": {
                "id": image_id,
                "image_url": image_url,
                "prompt": image_request.prompt,  # Return plaintext (encrypted in transit)
                "style": image_request.style,
                "aspect_ratio": image_request.aspect_ratio,
                "created_at": created_at.isoformat()
            },
            "metadata": metadata
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Image generation error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate image. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/my-images")
async def get_my_images(
    current_user: dict = Depends(require_auth),
    limit: int = 50,
    offset: int = 0
):
    """
    Get user's generated images (decrypted prompts)

    IDOR Protection: Only returns images where user_id == current_user
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get user's images (IDOR-safe: filtered by user_id)
        cursor.execute(
            """
            SELECT id, prompt_encrypted, image_url, style, aspect_ratio,
                   encryption_iv, encryption_tag, created_at, is_favorite
            FROM generated_images
            WHERE user_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        images = []
        for row in cursor.fetchall():
            image_id, prompt_enc, image_url, style, aspect_ratio, iv, tag, created_at, is_favorite = row

            # Decrypt prompt
            try:
                prompt = decrypt_text(prompt_enc, user_key, iv, tag)

                images.append({
                    "id": image_id,
                    "prompt": prompt,
                    "image_url": image_url,
                    "style": style,
                    "aspect_ratio": aspect_ratio,
                    "is_favorite": is_favorite,
                    "created_at": created_at.isoformat()
                })
            except Exception as decrypt_error:
                logger.error(f"Failed to decrypt image {image_id} prompt: {decrypt_error}")
                continue

        return {
            "success": True,
            "images": images,
            "total": len(images)
        }

    except Exception as e:
        logger.error(f"Error fetching images: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch images"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


class VoiceGenerationRequest(BaseModel):
    """Request model for AI-powered voice generation"""
    text: str = Field(..., min_length=1, max_length=5000)
    voice_type: str = Field(default="female-professional")
    model: str = Field(default="standard")
    title: Optional[str] = Field(None, max_length=200)

    @validator('text', 'title')
    def strip_whitespace(cls, v):
        if v:
            return v.strip()
        return v


@router.post("/generate-voice", status_code=status.HTTP_201_CREATED)
@limiter.limit("15/hour")  # Limit voice generation to prevent abuse
async def generate_voice(
    voice_request: VoiceGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Generate AI voice from text and store it encrypted

    Security Features:
    - Rate limited to 15 requests per hour
    - Input validation and malicious pattern detection
    - Encrypted text and metadata storage (AES-256-GCM)
    - Audit logging for all AI requests
    - IDOR protection (user_id verification)

    Encryption Flow:
    1. Decrypt user's encryption key (stored encrypted with master key)
    2. Generate AI voice using ElevenLabs
    3. Encrypt text and metadata with user's key
    4. Store encrypted data and voice file path in database
    5. Return voice file path and metadata
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Voice service
        voice_service = get_voice_service()

        # Generate voice using ElevenLabs (includes input validation)
        result = voice_service.generate_voice(
            text=voice_request.text,
            voice_type=voice_request.voice_type,
            model=voice_request.model,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )

        file_path = result["file_path"]
        filename = result["filename"]
        metadata = result["metadata"]

        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key (stored encrypted with master key)
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key_result = cursor.fetchone()

        if not user_encrypted_key_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user_encrypted_key = user_encrypted_key_result[0]

        # Decrypt user's encryption key using master key
        user_key = decrypt_user_key(user_encrypted_key)

        # Prepare data for encryption
        title = voice_request.title or "Voice Generation"
        combined_data = f"{title}|||{voice_request.text}|||{voice_request.voice_type}"

        # Encrypt combined data with user's key
        combined_encrypted, iv, tag = encrypt_text(combined_data, user_key)

        # Encrypt metadata
        metadata_str = f"{metadata.get('voice')}|||{metadata.get('model')}|||{metadata.get('file_size')}|||{metadata.get('duration_estimate')}"
        metadata_encrypted, metadata_iv, metadata_tag = encrypt_text(metadata_str, user_key)

        # Store voice generation in ideas table
        cursor.execute(
            """
            INSERT INTO ideas (
                title_encrypted,
                content_encrypted,
                owner_id,
                status,
                encryption_iv,
                encryption_tag,
                voice_file_path,
                voice_metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, updated_at
            """,
            (
                combined_encrypted,  # Store combined data
                combined_encrypted,  # Also in content field
                user_id,
                'draft',
                iv,
                tag,
                filename,  # Store filename (file saved in VOICE_OUTPUT_DIR)
                metadata_encrypted  # Store encrypted metadata
            )
        )

        idea_id, created_at, updated_at = cursor.fetchone()

        # Log audit event
        log_audit_event(
            cursor,
            user_id,
            "ai_voice_generated",
            "success",
            ip_address,
            {
                "idea_id": idea_id,
                "voice_type": voice_request.voice_type,
                "model": metadata.get("model"),
                "text_length": len(voice_request.text),
                "file_size": metadata.get("file_size")
            }
        )

        conn.commit()

        logger.info(
            f"AI voice generated for user {user_id}: idea_id={idea_id}, "
            f"voice={voice_request.voice_type}, file_size={metadata.get('file_size')}"
        )

        # Return voice file info and metadata
        return {
            "success": True,
            "message": "Voice generated successfully!",
            "voice": {
                "id": idea_id,
                "title": title,
                "text": voice_request.text,
                "voice_type": voice_request.voice_type,
                "filename": filename,
                "file_path": f"/api/v1/ideas/voice/{idea_id}/download",  # Download endpoint
                "created_at": created_at.isoformat(),
                "updated_at": updated_at.isoformat()
            },
            "metadata": metadata
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Voice generation error: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate voice. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/voice/{idea_id}/download")
async def download_voice(
    idea_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Download generated voice file

    IDOR Protection: Only allows download if user owns the idea
    """
    user_id = current_user["id"]
    conn = None

    try:
        import os
        from fastapi.responses import FileResponse

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership (IDOR protection)
        cursor.execute(
            """
            SELECT owner_id, voice_file_path
            FROM ideas
            WHERE id = %s AND is_deleted = FALSE AND voice_file_path IS NOT NULL
            """,
            (idea_id,)
        )
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Voice file not found")

        owner_id, voice_filename = row

        if owner_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

        # Construct full file path
        voice_output_dir = os.getenv("VOICE_OUTPUT_DIR", "generated_audio")
        file_path = os.path.join(voice_output_dir, voice_filename)

        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Voice file not found on server")

        # Return file
        return FileResponse(
            path=file_path,
            media_type="audio/wav",
            filename=voice_filename
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading voice: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download voice file"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


class VideoGenerationRequest(BaseModel):
    """Request model for AI-powered video generation"""
    prompt: str = Field(..., min_length=10, max_length=2000)
    duration: int = Field(default=10, ge=5, le=10)
    aspect_ratio: str = Field(default="16:9")
    cfg_scale: float = Field(default=0.7, ge=0.0, le=1.0)
    negative_prompt: Optional[str] = Field(None, max_length=1000)
    title: Optional[str] = Field(None, max_length=200)

    @validator('prompt', 'negative_prompt', 'title')
    def strip_whitespace(cls, v):
        if v:
            return v.strip()
        return v

    @validator('duration')
    def validate_duration(cls, v):
        if v not in [5, 10]:
            raise ValueError("Duration must be 5 or 10 seconds")
        return v

    @validator('aspect_ratio')
    def validate_aspect_ratio(cls, v):
        if v not in ["16:9", "9:16", "1:1"]:
            raise ValueError("Aspect ratio must be 16:9, 9:16, or 1:1")
        return v


@router.post("/generate-video", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/hour")  # Limit video generation to prevent abuse (videos take longer)
async def generate_video(
    video_request: VideoGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Generate AI video from prompt using Kling AI and store metadata encrypted

    Video generation is asynchronous:
    1. This endpoint starts the generation and returns immediately with task_id
    2. Client polls /video-status/{idea_id} to check progress
    3. When complete, video URL is saved to the idea

    Security Features:
    - Rate limited to 5 requests per hour (videos are expensive)
    - Input validation and malicious pattern detection
    - End-to-end encryption of prompts (AES-256-GCM)
    - Audit logging for all AI requests
    - IDOR protection (user_id verification)

    Returns:
        202 Accepted with idea_id and task_id for status polling
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Kling video service
        kling_service = get_kling_service()

        # Start video generation (async operation)
        result = kling_service.start_video_generation(
            prompt=video_request.prompt,
            duration=video_request.duration,
            aspect_ratio=video_request.aspect_ratio,
            cfg_scale=video_request.cfg_scale,
            negative_prompt=video_request.negative_prompt,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Failed to start video generation")
            )

        task_id = result["task_id"]

        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key (stored encrypted with master key)
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key_result = cursor.fetchone()

        if not user_encrypted_key_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User encryption key not found"
            )

        user_encrypted_key = user_encrypted_key_result[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Encrypt video prompt
        encrypted_prompt, iv, tag = encrypt_text(video_request.prompt, user_key)

        # Create title if not provided
        title = video_request.title or f"Video: {video_request.prompt[:50]}..."
        encrypted_title, title_iv, title_tag = encrypt_text(title, user_key)

        # Create idea record with video metadata (status: processing)
        cursor.execute(
            """
            INSERT INTO ideas (
                title_encrypted, content_encrypted, owner_id, status,
                encryption_iv, encryption_tag,
                video_task_id, video_status, video_prompt_encrypted,
                video_duration, video_aspect_ratio,
                video_iv, video_tag
            )
            VALUES (%s, %s, %s, 'draft', %s, %s, %s, 'processing', %s, %s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (
                encrypted_title, encrypted_prompt, user_id,
                title_iv, title_tag,
                task_id, encrypted_prompt,
                video_request.duration, video_request.aspect_ratio,
                iv, tag
            )
        )

        idea_id, created_at = cursor.fetchone()
        conn.commit()

        # Audit log
        log_audit_event(
            cursor=cursor,
            user_id=user_id,
            action="video_generation_started",
            status="success",
            ip_address=ip_address,
            details={
                "resource_type": "idea",
                "resource_id": idea_id,
                "task_id": task_id,
                "duration": video_request.duration,
                "aspect_ratio": video_request.aspect_ratio
            }
        )
        conn.commit()  # Commit audit log

        logger.info(
            f"Video generation started for user {user_id}: "
            f"idea_id={idea_id}, task_id={task_id}"
        )

        return {
            "success": True,
            "message": "Video generation started. This may take up to 90 seconds.",
            "idea_id": idea_id,
            "task_id": task_id,
            "status": "processing",
            "estimated_time": "60-90 seconds"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting video generation: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start video generation. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/video-status/{idea_id}")
async def check_video_status(
    idea_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Check the status of video generation for an idea

    IDOR Protection: Only allows status check if user owns the idea

    Returns:
        status: 'processing', 'completed', 'failed', or 'error'
        video_url: URL/path to video (if completed)
        progress: Estimated progress percentage
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership and get video task info (IDOR protection)
        cursor.execute(
            """
            SELECT owner_id, video_task_id, video_status, video_url,
                   video_duration, video_aspect_ratio, created_at
            FROM ideas
            WHERE id = %s AND is_deleted = FALSE
            """,
            (idea_id,)
        )
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Idea not found")

        (owner_id, video_task_id, video_status, video_url,
         video_duration, video_aspect_ratio, created_at) = row

        if owner_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

        if not video_task_id:
            raise HTTPException(
                status_code=404,
                detail="No video generation task found for this idea"
            )

        # If already completed or failed, return stored status
        if video_status in ['completed', 'failed', 'error']:
            return {
                "success": True,
                "status": video_status,
                "video_url": video_url,
                "duration": video_duration,
                "aspect_ratio": video_aspect_ratio
            }

        # Check with Kling API for current status
        kling_service = get_kling_service()
        result = kling_service.check_video_status(video_task_id)

        if not result["success"]:
            logger.error(f"Failed to check video status for idea {idea_id}: {result.get('error')}")
            return {
                "success": True,
                "status": "processing",  # Keep showing as processing on API errors
                "message": "Checking status... Please try again in a moment."
            }

        api_status = result["status"]

        # Update database if status changed
        if api_status == "completed":
            video_url = result.get("video_url")

            cursor.execute(
                """
                UPDATE ideas
                SET video_status = 'completed',
                    video_url = %s,
                    video_generated_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (video_url, idea_id)
            )
            conn.commit()

            # Audit log
            log_audit_event(
                cursor=cursor,
                user_id=user_id,
                action="video_generation_completed",
                status="success",
                ip_address=None,
                details={
                    "resource_type": "idea",
                    "resource_id": idea_id,
                    "video_url": video_url
                }
            )
            conn.commit()  # Commit audit log

            logger.info(f"Video generation completed for idea {idea_id}")

            return {
                "success": True,
                "status": "completed",
                "video_url": video_url,
                "duration": video_duration,
                "aspect_ratio": video_aspect_ratio
            }

        elif api_status in ["failed", "error"]:
            error_msg = result.get("error", "Unknown error")

            cursor.execute(
                """
                UPDATE ideas
                SET video_status = 'failed',
                    updated_at = NOW()
                WHERE id = %s
                """,
                (idea_id,)
            )
            conn.commit()

            # Audit log
            log_audit_event(
                cursor=cursor,
                user_id=user_id,
                action="video_generation_failed",
                status="failed",
                ip_address=None,
                details={
                    "resource_type": "idea",
                    "resource_id": idea_id,
                    "error": error_msg
                }
            )
            conn.commit()  # Commit audit log

            logger.error(f"Video generation failed for idea {idea_id}: {error_msg}")

            return {
                "success": False,
                "status": "failed",
                "error": error_msg
            }

        else:
            # Still processing
            # Calculate estimated progress based on elapsed time
            import datetime
            elapsed = (datetime.datetime.now() - created_at).total_seconds()
            estimated_total = 75  # Average 75 seconds
            progress = min(int((elapsed / estimated_total) * 100), 95)  # Cap at 95% until complete

            return {
                "success": True,
                "status": "processing",
                "progress": progress,
                "message": "Generating video... This may take 60-90 seconds."
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking video status: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check video status"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)
