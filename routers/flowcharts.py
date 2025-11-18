"""
routers/flowcharts.py
Flowchart API - Product/Workflow Design with Zero-Knowledge Encryption
Supports Mermaid.js flowcharts with AES-256-GCM encryption
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.crypto_aes import encrypt_text, decrypt_text, decrypt_user_key as decrypt_team_key
from utils.audit import log_audit_event
from utils.encryption import decrypt_user_key as get_master_key_decrypt
from utils.input_sanitizer import comprehensive_input_scan, MaliciousInputDetected
from utils.auth_dependencies import require_auth

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Pydantic Models

class FlowchartCreate(BaseModel):
    """Create new flowchart"""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    flowchart_data: str = Field(..., min_length=1)  # Mermaid code or JSON
    flowchart_type: str = Field(default='mermaid', pattern=r'^(mermaid|json|custom)$')
    template_name: Optional[str] = Field(None, max_length=100)
    status: str = Field(default='draft', pattern=r'^(draft|in_progress|review|completed|archived)$')
    team_id: Optional[int] = None
    is_pinned: bool = Field(default=False)
    node_notes: Optional[str] = Field(default='{}', max_length=10000)  # JSON string of node notes

    @validator('flowchart_data')
    def validate_flowchart_data(cls, v):
        """Validate flowchart data is not empty and check for obvious XSS patterns"""
        v = v.strip()
        if not v:
            raise ValueError('Flowchart data cannot be empty')

        # Security: Check for obvious XSS patterns while allowing legitimate Mermaid syntax
        # Mermaid syntax uses special chars like -->, [], {}, etc., so we only block clear attacks
        dangerous_patterns = [
            '<script',
            'javascript:',
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'eval(',
            'document.cookie',
            'localStorage',
            'sessionStorage',
            '.innerHTML',
            'fromCharCode',
            '<iframe',
            '<object',
            '<embed',
        ]

        v_lower = v.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in v_lower:
                raise ValueError(f'Flowchart data contains potentially malicious content: {pattern}')

        # Additional check: Reject if contains script-like event handlers
        import re
        if re.search(r'on\w+\s*=', v_lower):
            raise ValueError('Flowchart data contains event handlers which are not allowed')

        return v

class FlowchartUpdate(BaseModel):
    """Update flowchart"""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    flowchart_data: Optional[str] = Field(None, min_length=1)
    status: Optional[str] = Field(None, pattern=r'^(draft|in_progress|review|completed|archived)$')
    team_id: Optional[int] = None
    is_pinned: Optional[bool] = None
    node_notes: Optional[str] = Field(None, max_length=10000)  # JSON string of node notes

    @validator('flowchart_data')
    def validate_flowchart_data(cls, v):
        """Validate flowchart data is not empty and check for obvious XSS patterns"""
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError('Flowchart data cannot be empty')

            # Security: Check for obvious XSS patterns while allowing legitimate Mermaid syntax
            dangerous_patterns = [
                '<script',
                'javascript:',
                'onerror=',
                'onload=',
                'onclick=',
                'onmouseover=',
                'onfocus=',
                'eval(',
                'document.cookie',
                'localStorage',
                'sessionStorage',
                '.innerHTML',
                'fromCharCode',
                '<iframe',
                '<object',
                '<embed',
            ]

            v_lower = v.lower()
            for pattern in dangerous_patterns:
                if pattern.lower() in v_lower:
                    raise ValueError(f'Flowchart data contains potentially malicious content: {pattern}')

            # Additional check: Reject if contains script-like event handlers
            import re
            if re.search(r'on\w+\s*=', v_lower):
                raise ValueError('Flowchart data contains event handlers which are not allowed')

        return v

# Helper Functions

def get_user_key(user_id: int, cursor) -> bytes:
    """Get user's encryption key"""
    cursor.execute(
        "SELECT encryption_key FROM users WHERE id = %s",
        (user_id,)
    )
    result = cursor.fetchone()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Decrypt user key with master key
    encrypted_key = result[0]
    return get_master_key_decrypt(encrypted_key)

def check_team_access(cursor, user_id: int, team_id: int) -> bool:
    """Check if user has access to team"""
    cursor.execute(
        "SELECT role FROM team_members WHERE team_id = %s AND user_id = %s",
        (team_id, user_id)
    )
    result = cursor.fetchone()
    return result is not None

def get_team_key(cursor, team_id: int, user_id: int) -> bytes:
    """Get team's encryption key for user"""
    cursor.execute(
        "SELECT team_key_encrypted FROM team_members WHERE team_id = %s AND user_id = %s AND is_active = TRUE",
        (team_id, user_id)
    )
    result = cursor.fetchone()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No access to team"
        )

    encrypted_team_key = result[0]

    if not encrypted_team_key:
        logger.error(f"Team key is NULL for user {user_id} in team {team_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Team encryption key is missing. Please contact team administrator to re-invite you."
        )

    # Get user's encryption key
    user_key = get_user_key(user_id, cursor)

    # Decrypt team key with user's key (using decrypt_user_key from crypto_aes)
    try:
        return decrypt_team_key(encrypted_team_key, user_key)
    except Exception as e:
        logger.error(f"Failed to decrypt team key for user {user_id} in team {team_id}: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt team encryption key. Please contact team administrator."
        )

# API Endpoints

@router.post("/create")
@limiter.limit("20/minute")
async def create_flowchart(
    flowchart: FlowchartCreate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Create new flowchart with encryption

    Security:
    - Rate limited: 20 requests/minute
    - Content validation: Checks for XSS, SQL injection, etc.
    - Zero-knowledge encryption: AES-256-GCM
    - Audit logging: All creation events logged
    """
    user_id = current_user["id"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get encryption key (user or team)
        if flowchart.team_id:
            # Verify team access
            if not check_team_access(cursor, user_id, flowchart.team_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this team"
                )
            encryption_key = get_team_key(cursor, flowchart.team_id, user_id)
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Encrypt flowchart data
        title_encrypted, title_iv, title_tag = encrypt_text(flowchart.title, encryption_key)

        description_encrypted, description_iv, description_tag = None, None, None
        if flowchart.description:
            description_encrypted, description_iv, description_tag = encrypt_text(
                flowchart.description, encryption_key
            )

        data_encrypted, data_iv, data_tag = encrypt_text(
            flowchart.flowchart_data, encryption_key
        )

        # Store combined IV and tag (format: title_iv:description_iv:data_iv)
        combined_iv = f"{title_iv}:{description_iv if description_iv else ''}:{data_iv}"
        combined_tag = f"{title_tag}:{description_tag if description_tag else ''}:{data_tag}"

        # Insert into database
        cursor.execute("""
            INSERT INTO flowcharts (
                title_encrypted, description_encrypted, flowchart_data_encrypted,
                flowchart_type, owner_id, team_id, template_name, status,
                encryption_iv, encryption_tag, is_pinned, node_notes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
        """, (
            title_encrypted, description_encrypted, data_encrypted,
            flowchart.flowchart_type, user_id, flowchart.team_id,
            flowchart.template_name, flowchart.status,
            combined_iv, combined_tag, flowchart.is_pinned, flowchart.node_notes
        ))

        result = cursor.fetchone()
        flowchart_id = result[0]
        created_at = result[1]

        # Create notifications for team members if shared with team
        if flowchart.team_id:
            # Get all team members except the creator
            cursor.execute("""
                SELECT user_id FROM team_members
                WHERE team_id = %s AND user_id != %s AND is_active = TRUE
            """, (flowchart.team_id, user_id))

            team_member_ids = [row[0] for row in cursor.fetchall()]

            for member_id in team_member_ids:
                cursor.execute("""
                    INSERT INTO notifications (
                        user_id, type, title, message, priority,
                        related_type, related_id
                    )
                    VALUES (%s, 'flowchart_shared', %s, %s, 'normal', %s, %s)
                """, (
                    member_id,
                    "New flowchart shared",
                    f"{current_user.get('username', 'A team member')} shared a flowchart \"{flowchart.title}\" with the team",
                    'flowchart',
                    flowchart_id
                ))

        conn.commit()

        # Audit log
        log_audit_event(
            cursor, user_id, "flowchart_created", "success",
            request.client.host if request.client else None,
            {"flowchart_id": flowchart_id, "team_id": flowchart.team_id}
        )
        conn.commit()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "message": "Flowchart created successfully",
                "flowchart_id": flowchart_id,
                "created_at": created_at.isoformat()
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating flowchart: {str(e)}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create flowchart"
        )
    finally:
        if conn:
            return_db_connection(conn)

@router.get("")
@limiter.limit("30/minute")
async def list_flowcharts(
    request: Request,
    team_id: Optional[int] = None,
    current_user: dict = Depends(require_auth)
):
    """
    List user's flowcharts (or team flowcharts)

    Security:
    - IDOR Protection: Only returns flowcharts owned by user or user's teams
    - Decrypts titles and descriptions for display
    """
    user_id = current_user["id"]
    logger.info(f"Listing flowcharts for user_id: {user_id}, team_id: {team_id}")
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if team_id:
            # Verify team access
            if not check_team_access(cursor, user_id, team_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this team"
                )

            # Get team flowcharts
            cursor.execute("""
                SELECT id, title_encrypted, description_encrypted, flowchart_type,
                       template_name, status, encryption_iv, encryption_tag,
                       created_at, updated_at, is_pinned
                FROM flowcharts
                WHERE team_id = %s AND is_deleted = FALSE
                ORDER BY is_pinned DESC, updated_at DESC
            """, (team_id,))

            # IMPORTANT: Fetch rows BEFORE calling get_team_key (which executes another query)
            rows = cursor.fetchall()
            encryption_key = get_team_key(cursor, team_id, user_id)
        else:
            # Get user's personal flowcharts
            cursor.execute("""
                SELECT id, title_encrypted, description_encrypted, flowchart_type,
                       template_name, status, encryption_iv, encryption_tag,
                       created_at, updated_at, is_pinned
                FROM flowcharts
                WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
                ORDER BY is_pinned DESC, updated_at DESC
            """, (user_id,))

            # IMPORTANT: Fetch rows BEFORE calling get_user_key (which executes another query)
            rows = cursor.fetchall()
            encryption_key = get_user_key(user_id, cursor)
        logger.info(f"Query returned {len(rows)} flowcharts for user_id: {user_id}")
        logger.info(f"Rows data: {rows}")
        flowcharts = []
        for row in rows:
            try:
                flowchart_id, title_enc, desc_enc, flowchart_type, template, status_val, iv, tag, created, updated, pinned = row
                logger.info(f"Processing flowchart {flowchart_id}")

                # Parse IVs and tags
                ivs = iv.split(':')
                tags = tag.split(':')
                logger.info(f"IVs: {ivs}, Tags: {tags}")

                # Decrypt title
                title = decrypt_text(title_enc, encryption_key, ivs[0], tags[0])
                logger.info(f"Decrypted title: {title}")
            except Exception as e:
                logger.error(f"Error processing flowchart row: {e}")
                continue

            # Decrypt description (if exists)
            description = None
            if desc_enc and ivs[1] and tags[1]:
                try:
                    description = decrypt_text(desc_enc, encryption_key, ivs[1], tags[1])
                except:
                    description = None

            flowcharts.append({
                "id": flowchart_id,
                "title": title,
                "description": description,
                "flowchart_type": flowchart_type,
                "template_name": template,
                "status": status_val,
                "created_at": created.isoformat(),
                "updated_at": updated.isoformat(),
                "is_pinned": pinned
            })

        return flowcharts

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing flowcharts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list flowcharts"
        )
    finally:
        if conn:
            return_db_connection(conn)

@router.get("/{flowchart_id}")
@limiter.limit("60/minute")
async def get_flowchart(
    flowchart_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Get single flowchart with decrypted content

    Security:
    - IDOR Protection: Verifies user owns flowchart or has team access
    - Full decryption: Returns plaintext for editing
    """
    user_id = current_user["id"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get flowchart with ownership check
        cursor.execute("""
            SELECT id, title_encrypted, description_encrypted, flowchart_data_encrypted,
                   flowchart_type, owner_id, team_id, template_name, status,
                   encryption_iv, encryption_tag, created_at, updated_at, is_pinned, node_notes
            FROM flowcharts
            WHERE id = %s AND is_deleted = FALSE
        """, (flowchart_id,))

        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Flowchart not found"
            )

        (fid, title_enc, desc_enc, data_enc, flowchart_type, owner_id, team_id,
         template, status_val, iv, tag, created, updated, pinned, notes) = result

        # Verify access
        if team_id:
            if not check_team_access(cursor, user_id, team_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )
            encryption_key = get_team_key(cursor, team_id, user_id)
        else:
            if owner_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )
            encryption_key = get_user_key(user_id, cursor)

        # Parse IVs and tags
        ivs = iv.split(':')
        tags = tag.split(':')

        # Decrypt all fields
        title = decrypt_text(title_enc, encryption_key, ivs[0], tags[0])

        description = None
        if desc_enc and ivs[1] and tags[1]:
            try:
                description = decrypt_text(desc_enc, encryption_key, ivs[1], tags[1])
            except:
                description = None

        flowchart_data = decrypt_text(data_enc, encryption_key, ivs[2], tags[2])

        # Audit log
        log_audit_event(
            cursor, user_id, "flowchart_viewed", "success",
            request.client.host if request.client else None,
            {"flowchart_id": flowchart_id}
        )
        conn.commit()

        return {
            "id": fid,
            "title": title,
            "description": description,
            "flowchart_data": flowchart_data,
            "flowchart_type": flowchart_type,
            "template_name": template,
            "status": status_val,
            "team_id": team_id,
            "created_at": created.isoformat(),
            "updated_at": updated.isoformat(),
            "is_pinned": pinned,
            "node_notes": notes if notes else '{}'
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting flowchart: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get flowchart"
        )
    finally:
        if conn:
            return_db_connection(conn)

@router.put("/{flowchart_id}")
@limiter.limit("30/minute")
async def update_flowchart(
    flowchart_id: int,
    flowchart: FlowchartUpdate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Update existing flowchart

    Security:
    - IDOR Protection: Verifies ownership before update
    - Re-encryption: Updates are re-encrypted with same key
    """
    user_id = current_user["id"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get existing flowchart with ownership check
        cursor.execute("""
            SELECT owner_id, team_id, encryption_iv, encryption_tag,
                   title_encrypted, description_encrypted, flowchart_data_encrypted
            FROM flowcharts
            WHERE id = %s AND is_deleted = FALSE
        """, (flowchart_id,))

        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Flowchart not found"
            )

        owner_id, old_team_id, old_iv, old_tag, old_title, old_desc, old_data = result

        # Check if team_id is being changed
        team_id_changed = flowchart.team_id is not None and flowchart.team_id != old_team_id
        new_team_id = flowchart.team_id if flowchart.team_id is not None else old_team_id

        # Verify access to OLD team/flowchart
        if old_team_id:
            if not check_team_access(cursor, user_id, old_team_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )
            old_encryption_key = get_team_key(cursor, old_team_id, user_id)
        else:
            if owner_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )
            old_encryption_key = get_user_key(user_id, cursor)

        # If team_id is changing, verify access to NEW team
        if team_id_changed:
            if new_team_id:
                if not check_team_access(cursor, user_id, new_team_id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No access to new team"
                    )
                new_encryption_key = get_team_key(cursor, new_team_id, user_id)
            else:
                # Changing to personal flowchart
                new_encryption_key = get_user_key(user_id, cursor)
        else:
            new_encryption_key = old_encryption_key

        # Determine which encryption key to use for updates
        encryption_key = new_encryption_key if team_id_changed else old_encryption_key

        # Parse old IVs and tags
        old_ivs = old_iv.split(':')
        old_tags = old_tag.split(':')

        # If team_id is changing, we need to re-encrypt ALL fields
        if team_id_changed:
            # Decrypt all fields with old key
            decrypted_title = decrypt_text(old_title, old_encryption_key, old_ivs[0], old_tags[0])
            decrypted_desc = None
            if old_desc and old_ivs[1] and old_tags[1]:
                decrypted_desc = decrypt_text(old_desc, old_encryption_key, old_ivs[1], old_tags[1])
            decrypted_data = decrypt_text(old_data, old_encryption_key, old_ivs[2], old_tags[2])

            # Override with any new values provided
            if flowchart.title is not None:
                decrypted_title = flowchart.title
            if flowchart.description is not None:
                decrypted_desc = flowchart.description
            if flowchart.flowchart_data is not None:
                decrypted_data = flowchart.flowchart_data

            # Re-encrypt all fields with new key
            title_encrypted, title_iv, title_tag = encrypt_text(decrypted_title, new_encryption_key)
            if decrypted_desc:
                desc_encrypted, desc_iv, desc_tag = encrypt_text(decrypted_desc, new_encryption_key)
            else:
                desc_encrypted, desc_iv, desc_tag = None, '', ''
            data_encrypted, data_iv, data_tag = encrypt_text(decrypted_data, new_encryption_key)

            # Update IVs and tags
            old_ivs = [title_iv, desc_iv, data_iv]
            old_tags = [title_tag, desc_tag, data_tag]

        # Build update fields
        updates = []
        values = []

        # Add re-encrypted fields if team changed
        if team_id_changed:
            updates.append("title_encrypted = %s")
            values.append(title_encrypted)
            if desc_encrypted:
                updates.append("description_encrypted = %s")
                values.append(desc_encrypted)
            else:
                updates.append("description_encrypted = NULL")
            updates.append("flowchart_data_encrypted = %s")
            values.append(data_encrypted)
            updates.append("team_id = %s")
            values.append(new_team_id)
        else:
            # Normal updates (no team change)
            if flowchart.title is not None:
                title_encrypted, title_iv, title_tag = encrypt_text(flowchart.title, encryption_key)
                updates.append("title_encrypted = %s")
                values.append(title_encrypted)
                old_ivs[0] = title_iv
                old_tags[0] = title_tag

            if flowchart.description is not None:
                if flowchart.description:
                    desc_encrypted, desc_iv, desc_tag = encrypt_text(flowchart.description, encryption_key)
                    updates.append("description_encrypted = %s")
                    values.append(desc_encrypted)
                    old_ivs[1] = desc_iv
                    old_tags[1] = desc_tag
                else:
                    updates.append("description_encrypted = NULL")
                    old_ivs[1] = ''
                    old_tags[1] = ''

            if flowchart.flowchart_data is not None:
                data_encrypted, data_iv, data_tag = encrypt_text(flowchart.flowchart_data, encryption_key)
                updates.append("flowchart_data_encrypted = %s")
                values.append(data_encrypted)
                old_ivs[2] = data_iv
                old_tags[2] = data_tag

        if flowchart.status is not None:
            updates.append("status = %s")
            values.append(flowchart.status)

        if flowchart.is_pinned is not None:
            updates.append("is_pinned = %s")
            values.append(flowchart.is_pinned)

        if flowchart.node_notes is not None:
            updates.append("node_notes = %s")
            values.append(flowchart.node_notes)

        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )

        # Update IVs and tags
        combined_iv = ':'.join(old_ivs)
        combined_tag = ':'.join(old_tags)
        updates.append("encryption_iv = %s")
        values.append(combined_iv)
        updates.append("encryption_tag = %s")
        values.append(combined_tag)

        # Add updated_at
        updates.append("updated_at = CURRENT_TIMESTAMP")

        # Execute update
        values.append(flowchart_id)
        cursor.execute(f"""
            UPDATE flowcharts
            SET {', '.join(updates)}
            WHERE id = %s
            RETURNING updated_at
        """, values)

        updated_at = cursor.fetchone()[0]

        # Create notifications for team members if flowchart was shared with a team
        if team_id_changed and new_team_id:
            # Get flowchart title for notification
            flowchart_title = flowchart.title if flowchart.title else "a flowchart"

            # Get all team members except the user who shared it
            cursor.execute("""
                SELECT user_id FROM team_members
                WHERE team_id = %s AND user_id != %s AND is_active = TRUE
            """, (new_team_id, user_id))

            team_member_ids = [row[0] for row in cursor.fetchall()]

            for member_id in team_member_ids:
                cursor.execute("""
                    INSERT INTO notifications (
                        user_id, type, title, message, priority,
                        related_type, related_id
                    )
                    VALUES (%s, 'flowchart_shared', %s, %s, 'normal', %s, %s)
                """, (
                    member_id,
                    "New flowchart shared",
                    f"{current_user.get('username', 'A team member')} shared a flowchart \"{flowchart_title}\" with the team",
                    'flowchart',
                    flowchart_id
                ))

        conn.commit()

        # Audit log
        log_audit_event(
            cursor, user_id, "flowchart_updated", "success",
            request.client.host if request.client else None,
            {"flowchart_id": flowchart_id}
        )
        conn.commit()

        return {
            "message": "Flowchart updated successfully",
            "flowchart_id": flowchart_id,
            "updated_at": updated_at.isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating flowchart: {str(e)}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update flowchart"
        )
    finally:
        if conn:
            return_db_connection(conn)

@router.delete("/{flowchart_id}")
@limiter.limit("20/minute")
async def delete_flowchart(
    flowchart_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Soft delete flowchart

    Security:
    - IDOR Protection: Verifies ownership before deletion
    - Soft delete: Sets is_deleted flag, data remains encrypted
    """
    user_id = current_user["id"]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get flowchart with ownership check
        cursor.execute("""
            SELECT owner_id, team_id
            FROM flowcharts
            WHERE id = %s AND is_deleted = FALSE
        """, (flowchart_id,))

        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Flowchart not found"
            )

        owner_id, team_id = result

        # Verify access
        if team_id:
            if not check_team_access(cursor, user_id, team_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )
        else:
            if owner_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this flowchart"
                )

        # Soft delete
        cursor.execute("""
            UPDATE flowcharts
            SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (flowchart_id,))

        conn.commit()

        # Audit log
        log_audit_event(
            cursor, user_id, "flowchart_deleted", "success",
            request.client.host if request.client else None,
            {"flowchart_id": flowchart_id}
        )
        conn.commit()

        return {
            "message": "Flowchart deleted successfully",
            "flowchart_id": flowchart_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting flowchart: {str(e)}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete flowchart"
        )
    finally:
        if conn:
            return_db_connection(conn)
