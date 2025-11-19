"""
routers/drive.py
Encrypted Drive API - Files, Notes, Ideas, and Team Collaboration
Zero-knowledge architecture with AES-256-GCM encryption
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File, Form, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, JSONResponse, Response
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
import secrets
import os
import uuid
import logging
import io
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.security import verify_session_token, hash_password
from utils.crypto_aes import (
    encrypt_text, decrypt_text, encrypt_file_content,
    decrypt_file_content, generate_team_key, encrypt_user_key,
    decrypt_user_key, strip_file_metadata, get_user_encryption_key,
    key_from_base64, key_to_base64
)
from utils.audit import log_audit_event
from utils.encryption import decrypt_user_key as get_master_key_decrypt
from utils.file_validator import (
    comprehensive_file_validation, FileValidationError,
    sanitize_filename as validate_sanitize_filename
)
from utils.input_sanitizer import log_malicious_input
from utils.backup import (
    create_backup_manifest, create_encrypted_backup,
    decrypt_and_extract_backup, collect_user_data,
    collect_team_data, calculate_backup_expiry,
    BackupError
)
from utils.auth_dependencies import require_auth, require_admin

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Storage configuration
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/secure/uploads")
BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file limit
USER_STORAGE_LIMIT = 50 * 1024 * 1024  # 50MB total storage per user

# Pydantic Models

class TeamCreate(BaseModel):
    """Create new team"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

class TeamMemberAdd(BaseModel):
    """Add member to team"""
    user_id: int
    role: str = Field(..., pattern=r'^(admin|member|viewer)$')

class FolderCreate(BaseModel):
    """Create folder"""
    name: str = Field(..., min_length=1, max_length=255)
    parent_folder_id: Optional[int] = None
    team_id: Optional[int] = None

class NoteCreate(BaseModel):
    """Create note"""
    title: str = Field(..., min_length=1, max_length=255)
    content: str = Field(..., min_length=1)
    folder_id: Optional[int] = None
    team_id: Optional[int] = None

class NoteUpdate(BaseModel):
    """Update note"""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    content: Optional[str] = Field(None, min_length=1)
    is_pinned: Optional[bool] = None

class IdeaCreate(BaseModel):
    """Create idea"""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    content: str = Field(..., min_length=1)
    team_id: Optional[int] = None
    status: str = Field(default='draft', pattern=r'^(draft|in_progress|review|completed|archived)$')

class IdeaUpdate(BaseModel):
    """Update idea"""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    content: Optional[str] = None
    status: Optional[str] = Field(None, pattern=r'^(draft|in_progress|review|completed|archived)$')
    change_description: Optional[str] = Field(None, max_length=500)

class IdeaContributorAdd(BaseModel):
    """Add contributor to idea"""
    user_id: int
    role: str = Field(..., pattern=r'^(editor|commenter|viewer)$')

# Helper Functions

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from session token"""
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
            return_db_connection(conn)

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

    # decrypt_user_key gets the master key internally
    return get_master_key_decrypt(encrypted_key)

def check_team_access(cursor, user_id: int, team_id: int, required_role: str = 'viewer') -> bool:
    """
    Check if user has access to team

    IDOR Prevention: Always verify ownership before data access
    """
    cursor.execute(
        """
        SELECT role FROM team_members
        WHERE team_id = %s AND user_id = %s AND is_active = TRUE
        """,
        (team_id, user_id)
    )

    result = cursor.fetchone()
    if not result:
        return False

    role = result[0]
    role_hierarchy = {'viewer': 0, 'member': 1, 'admin': 2, 'owner': 3}

    return role_hierarchy.get(role, 0) >= role_hierarchy.get(required_role, 0)

def get_team_key(cursor, user_id: int, team_id: int) -> bytes:
    """
    Get team encryption key for user

    Raises:
        HTTPException: If user doesn't have access or team key is corrupted
    """
    cursor.execute(
        """
        SELECT team_key_encrypted FROM team_members
        WHERE team_id = %s AND user_id = %s AND is_active = TRUE
        """,
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

    user_key = get_user_key(user_id, cursor)

    try:
        return decrypt_user_key(encrypted_team_key, user_key)
    except Exception as e:
        logger.error(f"Failed to decrypt team key for user {user_id} in team {team_id}: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Team encryption key is corrupted. Please contact team administrator to re-invite you."
        )

def get_user_storage_usage(cursor, user_id: int) -> int:
    """
    Calculate total storage usage for a user (personal files only, excluding team files)
    Returns size in bytes
    """
    cursor.execute("""
        SELECT COALESCE(SUM(file_size), 0)
        FROM drive_files
        WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
    """, (user_id,))

    result = cursor.fetchone()
    return result[0] if result else 0

# Team Management Endpoints

@router.post("/teams", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
async def create_team(
    team_data: TeamCreate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Create a new team for collaboration"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Generate team encryption key
        team_key = generate_team_key()

        # Encrypt team key with owner's key
        user_key = get_user_key(user_id, cursor)
        team_key_encrypted = encrypt_user_key(team_key, user_key)

        # Create team
        cursor.execute(
            """
            INSERT INTO teams (name, description, owner_id, team_key_encrypted)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (team_data.name, team_data.description, user_id, team_key_encrypted)
        )

        team_id = cursor.fetchone()[0]

        # Add owner as team member
        cursor.execute(
            """
            INSERT INTO team_members (team_id, user_id, role, team_key_encrypted, added_by)
            VALUES (%s, %s, 'owner', %s, %s)
            """,
            (team_id, user_id, team_key_encrypted, user_id)
        )

        log_audit_event(cursor, user_id, "team_created", "success",
                       None, {"team_id": team_id, "team_name": team_data.name})

        conn.commit()

        return {
            "message": "Team created successfully",
            "team_id": team_id
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Team creation error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Team creation failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/teams/{team_id}/members")
@limiter.limit("20/hour")
async def add_team_member(
    team_id: int,
    member_data: TeamMemberAdd,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Add member to team (requires admin role)"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user has admin access
        if not check_team_access(cursor, user_id, team_id, 'admin'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        # Check if new member exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (member_data.user_id,))
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Get team key
        team_key = get_team_key(cursor, user_id, team_id)

        # Get new member's key
        new_member_key = get_user_key(member_data.user_id, cursor)

        # Encrypt team key with new member's key
        team_key_for_member = encrypt_user_key(team_key, new_member_key)

        # Add member
        cursor.execute(
            """
            INSERT INTO team_members (team_id, user_id, role, team_key_encrypted, added_by)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (team_id, user_id) DO UPDATE
            SET role = EXCLUDED.role, is_active = TRUE
            """,
            (team_id, member_data.user_id, member_data.role, team_key_for_member, user_id)
        )

        log_audit_event(cursor, user_id, "team_member_added", "success",
                       None, {"team_id": team_id, "new_member_id": member_data.user_id})

        conn.commit()

        return {"message": "Member added successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Add member error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add member"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/teams/{team_id}/members")
@limiter.limit("60/hour")
async def get_team_members(
    team_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Get all members of a team"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user has access to this team
        if not check_team_access(cursor, user_id, team_id, 'member'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

        # Get all team members with user details
        cursor.execute(
            """
            SELECT
                u.id, u.username, u.email, u.first_name, u.last_name,
                tm.role, tm.joined_at, tm.added_by
            FROM team_members tm
            JOIN users u ON tm.user_id = u.id
            WHERE tm.team_id = %s AND tm.is_active = TRUE
            ORDER BY tm.joined_at ASC
            """,
            (team_id,)
        )

        members = []
        for row in cursor.fetchall():
            members.append({
                'user_id': row[0],
                'username': row[1],
                'email': row[2],
                'first_name': row[3],
                'last_name': row[4],
                'role': row[5],
                'joined_at': row[6].isoformat() if row[6] else None,
                'added_by': row[7]
            })

        return {
            'team_id': team_id,
            'members': members,
            'total': len(members)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get team members error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get team members"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/teams")
@limiter.limit("60/hour")
async def list_teams(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """List all teams user is member of"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.id, t.name, t.description, t.owner_id, tm.role, t.created_at
            FROM teams t
            JOIN team_members tm ON t.id = tm.team_id
            WHERE tm.user_id = %s AND tm.is_active = TRUE AND t.is_active = TRUE
            ORDER BY t.created_at DESC
            """,
            (user_id,)
        )

        teams = []
        for row in cursor.fetchall():
            teams.append({
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "owner_id": row[3],
                "user_role": row[4],
                "created_at": row[5].isoformat() if row[5] else None
            })

        return {"teams": teams}

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/teams/{team_id}")
@limiter.limit("10/hour")
async def delete_team(
    team_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Delete a team (soft delete)

    IDOR Protection: Only team owner can delete the team
    ISO 27001 A.9.4.1 - Information access restriction
    OWASP ASVS V4.1 - Access Control
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else "unknown"
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ===== IDOR PROTECTION: Verify user is team owner =====
        cursor.execute(
            """
            SELECT owner_id, name, is_active
            FROM teams
            WHERE id = %s
            """,
            (team_id,)
        )

        team = cursor.fetchone()

        if not team:
            # Don't reveal if team exists - generic error
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )

        owner_id, team_name, is_active = team

        # Critical security check: Only owner can delete
        if owner_id != user_id:
            # Log unauthorized deletion attempt
            log_audit_event(
                cursor, user_id, "team_delete_blocked", "failed",
                None, {
                    "team_id": team_id,
                    "reason": "not_owner",
                    "actual_owner": owner_id,
                    "ip_address": ip_address
                }
            )
            conn.commit()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Only team owner can delete the team."
            )

        # Check if already deleted
        if not is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Team already deleted"
            )

        # ===== SOFT DELETE TEAM =====

        # 1. Mark team as inactive
        cursor.execute(
            """
            UPDATE teams
            SET is_active = FALSE, updated_at = NOW()
            WHERE id = %s
            """,
            (team_id,)
        )

        # 2. Mark all team members as inactive
        cursor.execute(
            """
            UPDATE team_members
            SET is_active = FALSE
            WHERE team_id = %s
            """,
            (team_id,)
        )

        # 3. Get count of affected members for logging
        affected_members = cursor.rowcount

        # 4. Log successful deletion
        log_audit_event(
            cursor, user_id, "team_deleted", "success",
            None, {
                "team_id": team_id,
                "team_name": team_name,
                "affected_members": affected_members,
                "ip_address": ip_address
            }
        )

        conn.commit()

        logger.info(
            f"User {user_id} deleted team {team_id} ('{team_name}') "
            f"with {affected_members} members from IP {ip_address}"
        )

        return {
            "message": "Team deleted successfully",
            "team_id": team_id,
            "team_name": team_name
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Delete team error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete team"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# Folder Endpoints

@router.post("/folders", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/hour")
async def create_folder(
    request: Request,
    folder_data: FolderCreate,
    current_user: dict = Depends(require_auth)
):
    """
    Create a new folder in encrypted drive
    Supports personal and team folders with parent folder hierarchy
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Get user's encryption key
        cursor.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        # Decrypt user's encryption key
        user_key = get_master_key_decrypt(user_row[0])

        # Determine which encryption key to use (user or team)
        encryption_key = user_key
        if folder_data.team_id:
            # Verify user is a member of the team
            cursor.execute(
                "SELECT team_key_encrypted FROM team_members WHERE team_id = %s AND user_id = %s AND is_active = TRUE",
                (folder_data.team_id, user_id)
            )
            team_member = cursor.fetchone()
            if not team_member:
                raise HTTPException(status_code=403, detail="Not a member of this team")

            # Decrypt team key
            encryption_key = decrypt_user_key(team_member[0])

        # Verify parent folder exists and user has access
        if folder_data.parent_folder_id:
            cursor.execute(
                "SELECT id FROM drive_folders WHERE id = %s AND (owner_id = %s OR team_id = %s) AND is_deleted = FALSE",
                (folder_data.parent_folder_id, user_id, folder_data.team_id)
            )
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Parent folder not found or access denied")

        # Encrypt folder name
        encrypted_name, iv, tag = encrypt_text(folder_data.name, encryption_key)

        # Insert folder with encryption tag
        cursor.execute("""
            INSERT INTO drive_folders (name_encrypted, owner_id, team_id, parent_folder_id, encryption_iv, encryption_tag, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
            RETURNING id, created_at
        """, (encrypted_name, user_id, folder_data.team_id, folder_data.parent_folder_id, iv, tag))

        result = cursor.fetchone()
        folder_id = result[0]
        created_at = result[1]
        conn.commit()

        # Log audit event
        log_audit_event(
            cursor,
            user_id,
            "folder_created",
            "success",
            request.client.host if request.client else None,
            {"folder_id": folder_id, "name": folder_data.name}
        )

        return {
            "folder_id": folder_id,
            "name": folder_data.name,
            "parent_folder_id": folder_data.parent_folder_id,
            "team_id": folder_data.team_id,
            "created_at": created_at.isoformat()
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Folder creation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create folder")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/folders")
async def list_folders(
    current_user: dict = Depends(require_auth),
    team_id: Optional[int] = None
):
    """
    List all folders (personal or team)
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Get user's encryption key
        cursor.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        user_key = get_master_key_decrypt(user_row[0])

        if team_id:
            # Get team folders (with encryption_tag)
            cursor.execute("""
                SELECT f.id, f.name_encrypted, f.parent_folder_id, f.encryption_iv, f.encryption_tag, f.created_at
                FROM drive_folders f
                JOIN team_members tm ON tm.team_id = f.team_id
                WHERE f.team_id = %s AND tm.user_id = %s AND f.is_deleted = FALSE
                ORDER BY f.created_at DESC
            """, (team_id, user_id))

            # Get team key for decryption
            try:
                encryption_key = get_team_key(cursor, user_id, team_id)
            except HTTPException as e:
                # Team key is corrupted or missing - return empty list with warning
                logger.warning(f"Cannot load team folders for team {team_id}: {e.detail}")
                return {"folders": [], "warning": e.detail}
        else:
            # Get personal folders (with encryption_tag)
            cursor.execute("""
                SELECT id, name_encrypted, parent_folder_id, encryption_iv, encryption_tag, created_at
                FROM drive_folders
                WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
                ORDER BY created_at DESC
            """, (user_id,))
            encryption_key = user_key

        folders = []
        for row in cursor.fetchall():
            try:
                # Decrypt folder name with iv and tag
                decrypted_name = decrypt_text(row[1], encryption_key, row[3], row[4])
                folders.append({
                    "id": row[0],
                    "name": decrypted_name,
                    "parent_folder_id": row[2],
                    "created_at": row[5].isoformat() if row[5] else None
                })
            except Exception as e:
                logger.error(f"Failed to decrypt folder {row[0]}: {str(e)}")
                # Skip folders that can't be decrypted (old format or corrupted)
                continue

        return {"folders": folders}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List folders error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list folders")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/folders/{folder_id}")
async def delete_folder(
    folder_id: int,
    current_user: dict = Depends(require_auth)
):
    """Delete a folder (soft delete)"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Check if folder exists and user has access
        cursor.execute("""
            SELECT owner_id, team_id FROM drive_folders
            WHERE id = %s AND is_deleted = FALSE
        """, (folder_id,))

        folder = cursor.fetchone()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")

        owner_id, team_id = folder

        # Check permissions
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'member'):
                raise HTTPException(status_code=403, detail="No access to this folder")
        elif owner_id != user_id:
            raise HTTPException(status_code=403, detail="No access to this folder")

        # Soft delete folder
        cursor.execute("""
            UPDATE drive_folders
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE id = %s
        """, (folder_id,))

        conn.commit()

        return {"message": "Folder deleted successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Delete folder error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete folder")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/folders/{folder_id}/contents")
async def get_folder_contents(
    folder_id: int,
    current_user: dict = Depends(require_auth)
):
    """Get contents of a folder (files and subfolders)"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Check if folder exists and user has access
        cursor.execute("""
            SELECT owner_id, team_id, name_encrypted, encryption_iv, encryption_tag
            FROM drive_folders
            WHERE id = %s AND is_deleted = FALSE
        """, (folder_id,))

        folder = cursor.fetchone()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")

        owner_id, team_id, name_enc, iv, tag = folder

        # Check permissions and get encryption key
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(status_code=403, detail="No access to this folder")
            encryption_key = get_team_key(cursor, user_id, team_id)
        elif owner_id != user_id:
            raise HTTPException(status_code=403, detail="No access to this folder")
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Decrypt folder name
        folder_name = decrypt_text(name_enc, encryption_key, iv, tag)

        # Get subfolders
        cursor.execute("""
            SELECT id, name_encrypted, encryption_iv, encryption_tag, created_at
            FROM drive_folders
            WHERE parent_folder_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
        """, (folder_id,))

        subfolders = []
        for row in cursor.fetchall():
            try:
                subfolder_name = decrypt_text(row[1], encryption_key, row[2], row[3])
                subfolders.append({
                    "id": row[0],
                    "name": subfolder_name,
                    "type": "folder",
                    "created_at": row[4].isoformat() if row[4] else None
                })
            except Exception as e:
                logger.error(f"Failed to decrypt subfolder {row[0]}: {e}")
                continue

        # Get files in this folder
        cursor.execute("""
            SELECT id, filename_encrypted, file_size, encryption_iv, encryption_tag, created_at
            FROM drive_files
            WHERE folder_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
        """, (folder_id,))

        files = []
        for row in cursor.fetchall():
            try:
                filename_encrypted = row[1]
                file_iv = row[3]
                file_tag = row[4]

                # Decrypt filename - check if it's in combined format "iv:tag:ciphertext"
                if ':' in filename_encrypted and len(filename_encrypted.split(':')) == 3:
                    # New format: "iv:tag:ciphertext"
                    parts = filename_encrypted.split(':')
                    f_iv, f_tag, f_cipher = parts[0], parts[1], parts[2]
                    filename_decrypted = decrypt_text(f_cipher, encryption_key, f_iv, f_tag)
                else:
                    # Old format - use file's content IV/TAG
                    filename_decrypted = decrypt_text(filename_encrypted, encryption_key, file_iv, file_tag)

                files.append({
                    "id": row[0],
                    "name": filename_decrypted,
                    "type": "file",
                    "size": row[2],
                    "created_at": row[5].isoformat() if row[5] else None
                })
            except Exception as e:
                logger.error(f"Failed to process file {row[0]}: {e}")
                continue

        # Get notes in this folder
        cursor.execute("""
            SELECT id, title_encrypted, encryption_iv, encryption_tag, created_at
            FROM notes
            WHERE folder_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
        """, (folder_id,))

        notes = []
        for row in cursor.fetchall():
            try:
                # Decrypt combined data and extract title
                combined_decrypted = decrypt_text(row[1], encryption_key, row[2], row[3])
                if '|||' in combined_decrypted:
                    note_title = combined_decrypted.split('|||', 1)[0]
                else:
                    note_title = "Untitled Note"

                notes.append({
                    "id": row[0],
                    "name": note_title,
                    "type": "note",
                    "created_at": row[4].isoformat() if row[4] else None
                })
            except Exception as e:
                logger.error(f"Failed to decrypt note {row[0]}: {e}")
                continue

        return {
            "folder_name": folder_name,
            "folder_id": folder_id,
            "contents": subfolders + files + notes
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get folder contents error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get folder contents")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/folders/{folder_id}/download")
async def download_folder_as_zip(
    folder_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Download folder contents as encrypted ZIP archive

    Security:
    - IDOR protection: Verifies user ownership/team access
    - All files remain encrypted in memory during processing
    - Files decrypted only when adding to ZIP
    - ZIP created in memory (no temporary files)
    """
    import zipfile

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Check if folder exists and user has access (IDOR protection)
        cursor.execute("""
            SELECT owner_id, team_id, name_encrypted, encryption_iv, encryption_tag
            FROM drive_folders
            WHERE id = %s AND is_deleted = FALSE
        """, (folder_id,))

        folder = cursor.fetchone()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")

        owner_id, team_id, name_enc, iv, tag = folder

        # Check permissions and get encryption key
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(status_code=403, detail="No access to this folder")
            encryption_key = get_team_key(cursor, user_id, team_id)
        elif owner_id != user_id:
            raise HTTPException(status_code=403, detail="No access to this folder")
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Decrypt folder name
        folder_name = decrypt_text(name_enc, encryption_key, iv, tag)

        # Get all files in this folder (recursively get subfolders too if needed)
        cursor.execute("""
            SELECT id, filename_encrypted, file_path, encryption_iv, encryption_tag
            FROM drive_files
            WHERE folder_id = %s AND is_deleted = FALSE
            ORDER BY id
        """, (folder_id,))

        files_data = cursor.fetchall()

        if not files_data:
            raise HTTPException(status_code=404, detail="Folder is empty")

        # Create ZIP in memory
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_row in files_data:
                file_id, filename_enc, file_path, file_iv, file_tag = file_row

                try:
                    # Decrypt filename
                    # Check if filename is in combined format "iv:tag:ciphertext"
                    if ':' in filename_enc and len(filename_enc.split(':')) == 3:
                        parts = filename_enc.split(':')
                        f_iv, f_tag, f_cipher = parts[0], parts[1], parts[2]
                        filename_decrypted = decrypt_text(f_cipher, encryption_key, f_iv, f_tag)
                    else:
                        # Old format - use file's own IV/TAG
                        filename_decrypted = decrypt_text(filename_enc, encryption_key, file_iv, file_tag)

                    # Read encrypted file from disk
                    if not os.path.exists(file_path):
                        logger.warning(f"File not found on disk: {file_path}")
                        continue

                    with open(file_path, 'rb') as f:
                        encrypted_content = f.read()

                    # Decrypt file content
                    file_iv_bytes = key_from_base64(file_iv)
                    file_tag_bytes = key_from_base64(file_tag)
                    decrypted_content = decrypt_file_content(
                        encrypted_content,
                        encryption_key,
                        file_iv_bytes,
                        file_tag_bytes
                    )

                    # Add to ZIP with original filename
                    zip_file.writestr(filename_decrypted, decrypted_content)

                except Exception as e:
                    logger.error(f"Failed to add file {file_id} to ZIP: {str(e)}")
                    # Continue with other files even if one fails
                    continue

        # Prepare ZIP for download
        zip_buffer.seek(0)

        # Sanitize folder name for filename
        safe_folder_name = "".join(c for c in folder_name if c.isalnum() or c in (' ', '_', '-')).strip()
        zip_filename = f"{safe_folder_name}.zip"

        # Log audit event
        log_audit_event(
            cursor,
            user_id,
            "folder_downloaded",
            "success",
            None,
            {"folder_id": folder_id, "folder_name": folder_name, "file_count": len(files_data)}
        )
        conn.commit()

        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{zip_filename}"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download folder error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download folder")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# File Upload/Download Endpoints

@router.post("/files/upload")
@limiter.limit("20/hour")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    folder_id: Optional[int] = Form(None),
    team_id: Optional[int] = Form(None),
    current_user: dict = Depends(require_auth)
):
    """
    Upload encrypted file with comprehensive security validation

    Security features:
    - File size limit: 10MB
    - Allowed extensions: jpg, png, txt, pdf, docx, csv
    - Magic bytes verification (MIME type validation)
    - Double extension detection
    - Polyglot file detection
    - ImageMagick exploit protection
    - PDF malware scanning
    - AES-256-GCM encryption
    - EXIF/metadata stripping
    - UUID-based filenames (prevents path traversal)
    - Malicious input logging
    """
    conn = None

    # Extract user_id early for error handling
    user_id = current_user["id"]

    try:
        # Sanitize filename
        original_filename = validate_sanitize_filename(file.filename or "unknown")

        # Read file content
        file_content = await file.read()

        # Get client IP for logging
        client_ip = request.client.host if request.client else None

        # Comprehensive file validation
        try:
            validation_result = comprehensive_file_validation(
                file_content=file_content,
                filename=original_filename,
                mime_type=file.content_type or 'application/octet-stream'
            )
        except FileValidationError as e:
            # Log malicious file upload attempt
            log_malicious_input(
                user_id=user_id,
                input_value=f"File: {original_filename}, MIME: {file.content_type}",
                attack_type="malicious_file_upload",
                pattern=str(e),
                ip_address=client_ip,
                endpoint="/api/v1/files/upload"
            )

            # Track malicious upload for alerting
            from utils.security_monitor import track_malicious_file_upload, send_alert_notification

            alert = track_malicious_file_upload(
                user_id=user_id,
                ip_address=client_ip,
                filename=original_filename,
                attack_type="malicious_file_upload",
                pattern=str(e)
            )

            if alert:
                logger.critical(
                    f"MALICIOUS FILE UPLOAD ALERT: {alert.description} "
                    f"[user_id={user_id}, ip={client_ip}]"
                )

                # Send notification
                send_alert_notification(alert)

            logger.warning(f"File validation failed for user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File validation failed: {str(e)}"
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        # Log received parameters for debugging
        logger.info(f"Upload parameters: folder_id={folder_id}, team_id={team_id}, user_id={user_id}")

        # Check storage limit (50MB per user for personal files)
        if not team_id:  # Only check for personal uploads, not team uploads
            current_usage = get_user_storage_usage(cursor, user_id)
            file_size = len(file_content)

            if current_usage + file_size > USER_STORAGE_LIMIT:
                used_mb = current_usage / (1024 * 1024)
                file_mb = file_size / (1024 * 1024)
                limit_mb = USER_STORAGE_LIMIT / (1024 * 1024)

                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Storage limit exceeded. You are using {used_mb:.1f}MB of {limit_mb}MB. This file ({file_mb:.1f}MB) would exceed your limit."
                )

        # Validate folder_id if provided
        if folder_id:
            cursor.execute(
                "SELECT owner_id, team_id FROM drive_folders WHERE id = %s AND is_deleted = FALSE",
                (folder_id,)
            )
            folder = cursor.fetchone()
            if not folder:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Folder not found"
                )

            folder_owner_id, folder_team_id = folder

            # Check if user has access to the folder
            if folder_team_id:
                if not check_team_access(cursor, user_id, folder_team_id, 'member'):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No access to this folder"
                    )
            elif folder_owner_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this folder"
                )

        # Determine encryption key (user or team)
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'member'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team"
                )
            encryption_key = get_team_key(cursor, user_id, team_id)
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Strip metadata (EXIF, document properties, etc.)
        mime_type = validation_result['mime_type']
        file_content_clean = strip_file_metadata(file_content, mime_type)

        # Encrypt file content
        ciphertext, iv, tag = encrypt_file_content(file_content_clean, encryption_key)

        # Encrypt filename and MIME type (returns base64 strings already)
        filename_enc, filename_iv, filename_tag = encrypt_text(original_filename, encryption_key)
        mime_enc, mime_iv, mime_tag = encrypt_text(mime_type, encryption_key)

        # Combine filename parts into single string: "iv:tag:ciphertext"
        filename_combined = f"{filename_iv}:{filename_tag}:{filename_enc}"
        mime_combined = f"{mime_iv}:{mime_tag}:{mime_enc}"
        logger.info(f"Storing filename_combined: {len(filename_combined)} chars, {len(filename_combined.split(':'))} parts")

        # Generate unique file path
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(UPLOAD_DIR, file_uuid)

        # Ensure upload directory exists
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Write encrypted file to disk
        with open(file_path, 'wb') as f:
            f.write(ciphertext)

        # Calculate checksum
        checksum = hash_password(ciphertext.hex())  # Argon2id hash

        # Store in database
        cursor.execute(
            """
            INSERT INTO drive_files (
                filename_encrypted, file_path, file_size, mime_type_encrypted,
                owner_id, team_id, folder_id, encryption_iv, encryption_tag,
                checksum, metadata_stripped
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            RETURNING id
            """,
            (
                filename_combined, file_path, len(file_content), mime_combined,
                user_id, team_id, folder_id,
                key_to_base64(iv), key_to_base64(tag), checksum  # iv and tag are from encrypt_file_content (bytes)
            )
        )

        file_id = cursor.fetchone()[0]

        log_audit_event(cursor, user_id, "file_uploaded", "success",
                       client_ip, {
                           "file_id": file_id,
                           "size": len(file_content),
                           "original_filename": original_filename,
                           "mime_type": mime_type,
                           "sha256": validation_result.get('sha256', 'unknown')
                       })

        conn.commit()

        return {
            "message": "File uploaded successfully",
            "file_id": file_id,
            "sha256": validation_result.get('sha256')
        }

    except HTTPException:
        if conn:
            conn.rollback()
        # Clean up file if database insert failed
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)
        logger.error(f"File upload error: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File upload failed: {str(e)}"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/share")
async def share_item_to_team(
    request: Request,
    item_id: int = Body(...),
    item_type: str = Body(...),  # 'file', 'folder', or 'note'
    team_id: int = Body(...),
    permission: str = Body(default='write'),  # 'read' or 'write'
    message: Optional[str] = Body(None),
    current_user: dict = Depends(require_auth)
):
    """
    Share a file, folder, or note to a team by copying and re-encrypting with team key.

    - Validates user owns the item
    - Validates user is member of target team
    - Decrypts item with user key
    - Re-encrypts with team key
    - Creates copy in team drive
    - Sets appropriate permissions
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Validate team access
        if not check_team_access(cursor, user_id, team_id, 'member'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a member of this team"
            )

        # Get user's encryption key and team's encryption key
        user_key = get_user_key(user_id, cursor)
        team_key = get_team_key(cursor, user_id, team_id)

        shared_item_id = None
        item_name = ""

        if item_type == 'file':
            # Get file details
            cursor.execute("""
                SELECT filename_encrypted, file_path, file_size, mime_type_encrypted,
                       encryption_iv, encryption_tag, owner_id, checksum
                FROM drive_files
                WHERE id = %s AND is_deleted = FALSE
            """, (item_id,))

            file_data = cursor.fetchone()
            if not file_data:
                raise HTTPException(status_code=404, detail="File not found")

            filename_enc, file_path, file_size, mime_enc, iv_b64, tag_b64, owner_id, checksum = file_data

            # Verify ownership
            if owner_id != user_id:
                raise HTTPException(status_code=403, detail="You don't own this file")

            # Decrypt filename and MIME type with user key
            filename_parts = filename_enc.split(':')
            mime_parts = mime_enc.split(':')

            filename_decrypted = decrypt_text(filename_parts[2], user_key, filename_parts[0], filename_parts[1])
            mime_decrypted = decrypt_text(mime_parts[2], user_key, mime_parts[0], mime_parts[1])
            item_name = filename_decrypted

            # Read and decrypt file content with user key
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()

            iv = key_from_base64(iv_b64)
            tag = key_from_base64(tag_b64)
            decrypted_content = decrypt_file_content(encrypted_content, user_key, iv, tag)

            # Re-encrypt with team key
            new_ciphertext, new_iv, new_tag = encrypt_file_content(decrypted_content, team_key)
            new_filename_enc, new_filename_iv, new_filename_tag = encrypt_text(filename_decrypted, team_key)
            new_mime_enc, new_mime_iv, new_mime_tag = encrypt_text(mime_decrypted, team_key)

            # Combine encrypted parts
            filename_combined = f"{new_filename_iv}:{new_filename_tag}:{new_filename_enc}"
            mime_combined = f"{new_mime_iv}:{new_mime_tag}:{new_mime_enc}"

            # Generate new file path for team copy
            file_uuid = str(uuid.uuid4())
            new_file_path = os.path.join(UPLOAD_DIR, file_uuid)

            # Write re-encrypted file
            with open(new_file_path, 'wb') as f:
                f.write(new_ciphertext)

            # Calculate new checksum
            new_checksum = hash_password(new_ciphertext.hex())

            # Insert team file
            cursor.execute("""
                INSERT INTO drive_files (
                    filename_encrypted, file_path, file_size, mime_type_encrypted,
                    owner_id, team_id, encryption_iv, encryption_tag,
                    checksum, metadata_stripped
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                RETURNING id
            """, (
                filename_combined, new_file_path, file_size, mime_combined,
                user_id, team_id,
                key_to_base64(new_iv), key_to_base64(new_tag),
                new_checksum
            ))

            shared_item_id = cursor.fetchone()[0]
            logger.info(f"File shared to team successfully. New file ID: {shared_item_id}, Team ID: {team_id}")

        elif item_type == 'note':
            # Get note details
            cursor.execute("""
                SELECT title_encrypted, owner_id, encryption_iv, encryption_tag
                FROM notes
                WHERE id = %s AND is_deleted = FALSE
            """, (item_id,))

            note_data = cursor.fetchone()
            if not note_data:
                raise HTTPException(status_code=404, detail="Note not found")

            combined_enc, owner_id, iv, tag = note_data

            # Verify ownership
            if owner_id != user_id:
                raise HTTPException(status_code=403, detail="You don't own this note")

            # Decrypt combined data (title|||content) with user key
            combined_decrypted = decrypt_text(combined_enc, user_key, iv, tag)

            # Extract title for display
            if '|||' in combined_decrypted:
                item_name = combined_decrypted.split('|||', 1)[0]
            else:
                item_name = "Untitled Note"

            # Re-encrypt with team key
            new_combined_enc, new_iv, new_tag = encrypt_text(combined_decrypted, team_key)

            # Insert team note
            cursor.execute("""
                INSERT INTO notes (
                    title_encrypted, content_encrypted, owner_id, team_id,
                    encryption_iv, encryption_tag
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (new_combined_enc, new_combined_enc, user_id, team_id, new_iv, new_tag))

            shared_item_id = cursor.fetchone()[0]

        elif item_type == 'folder':
            # Get folder details
            cursor.execute("""
                SELECT name_encrypted, owner_id, encryption_iv, encryption_tag
                FROM drive_folders
                WHERE id = %s AND is_deleted = FALSE
            """, (item_id,))

            folder_data = cursor.fetchone()
            if not folder_data:
                raise HTTPException(status_code=404, detail="Folder not found")

            name_enc, owner_id, iv, tag = folder_data

            # Verify ownership
            if owner_id != user_id:
                raise HTTPException(status_code=403, detail="You don't own this folder")

            # Decrypt folder name with user key
            name_decrypted = decrypt_text(name_enc, user_key, iv, tag)
            item_name = name_decrypted

            # Re-encrypt with team key
            new_name_enc, new_iv, new_tag = encrypt_text(name_decrypted, team_key)

            # Insert team folder
            cursor.execute("""
                INSERT INTO drive_folders (
                    name_encrypted, owner_id, team_id, encryption_iv, encryption_tag
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (new_name_enc, user_id, team_id, new_iv, new_tag))

            shared_item_id = cursor.fetchone()[0]

        else:
            raise HTTPException(status_code=400, detail="Invalid item type")

        # Create notification for team members
        cursor.execute("""
            SELECT user_id FROM team_members
            WHERE team_id = %s AND user_id != %s
        """, (team_id, user_id))

        team_member_ids = [row[0] for row in cursor.fetchall()]

        for member_id in team_member_ids:
            cursor.execute("""
                INSERT INTO notifications (
                    user_id, type, title, message, priority,
                    related_type, related_id
                )
                VALUES (%s, 'file_shared', %s, %s, 'normal', %s, %s)
            """, (
                member_id,
                f"New {item_type} shared",
                f"{current_user.get('username', 'A team member')} shared \"{item_name}\" with the team" + (f": {message}" if message else ""),
                item_type,
                shared_item_id
            ))

        # Log audit event
        log_audit_event(
            cursor, user_id, f"{item_type}_shared_to_team",
            "success", request.client.host if request.client else None,
            {
                "item_id": item_id,
                "shared_item_id": shared_item_id,
                "team_id": team_id,
                "item_type": item_type,
                "permission": permission,
                "message": message
            }
        )

        conn.commit()

        return {
            "message": f"{item_type.capitalize()} shared successfully",
            "shared_item_id": shared_item_id,
            "team_id": team_id,
            "permission": permission
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Share error: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to share item: {str(e)}"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/files")
async def list_files(
    current_user: dict = Depends(require_auth),
    team_id: Optional[int] = None
):
    """
    List all files (personal or team)
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Get user's encryption key
        cursor.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        user_key = get_master_key_decrypt(user_row[0])

        if team_id:
            # Get team files
            cursor.execute("""
                SELECT f.id, f.filename_encrypted, f.file_size, f.mime_type_encrypted,
                       f.encryption_iv, f.encryption_tag, f.created_at
                FROM drive_files f
                JOIN team_members tm ON tm.team_id = f.team_id
                WHERE f.team_id = %s AND tm.user_id = %s AND tm.is_active = TRUE AND f.is_deleted = FALSE
                ORDER BY f.created_at DESC
            """, (team_id, user_id))

            team_files_count = cursor.rowcount
            logger.info(f"Loading team files for team_id={team_id}, user_id={user_id}, found {team_files_count} files")

            # IMPORTANT: Fetch rows BEFORE calling get_team_key() which uses the same cursor
            rows_fetched = cursor.fetchall()
            logger.info(f"Fetched {len(rows_fetched)} rows from database for processing")

            # Get team key for decryption
            try:
                encryption_key = get_team_key(cursor, user_id, team_id)
            except HTTPException as e:
                # Team key is corrupted or missing - return empty list with warning
                logger.warning(f"Cannot load team files for team {team_id}: {e.detail}")
                return {"files": [], "warning": e.detail}
        else:
            # Get personal files
            cursor.execute("""
                SELECT id, filename_encrypted, file_size, mime_type_encrypted,
                       encryption_iv, encryption_tag, created_at
                FROM drive_files
                WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
                ORDER BY created_at DESC
            """, (user_id,))
            encryption_key = user_key
            rows_fetched = cursor.fetchall()
            logger.info(f"Fetched {len(rows_fetched)} rows from database for processing")

        files = []
        for row in rows_fetched:
            try:
                # Decrypt filename (stored as "iv:tag:ciphertext")
                filename_combined = row[1]
                logger.info(f"Processing file {row[0]}, filename_combined length: {len(filename_combined)}, parts: {len(filename_combined.split(':'))}")
                parts = filename_combined.split(':')
                if len(parts) == 3:
                    filename_iv, filename_tag, filename_enc = parts
                    decrypted_filename = decrypt_text(filename_enc, encryption_key, filename_iv, filename_tag)
                else:
                    # Legacy format - skip
                    logger.warning(f"File {row[0]} has invalid filename format: {len(parts)} parts instead of 3")
                    continue

                files.append({
                    "id": row[0],
                    "filename": decrypted_filename,
                    "size": row[2],
                    "created_at": row[6].isoformat() if row[6] else None
                })
            except Exception as e:
                logger.error(f"Failed to decrypt file {row[0]}: {str(e)}", exc_info=True)
                logger.error(f"File {row[0]} metadata: filename_combined='{filename_combined}', size={row[2]}")
                continue

        return {"files": files}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List files error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list files")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/files/{file_id}")
async def delete_file(
    file_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Soft delete a file (mark as deleted)
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = current_user['id']

        # Verify ownership or team access
        cursor.execute(
            "SELECT id, owner_id, team_id FROM drive_files WHERE id = %s AND is_deleted = FALSE",
            (file_id,)
        )
        file_row = cursor.fetchone()

        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")

        file_id_db, owner_id, team_id = file_row

        # Check if user has permission to delete
        can_delete = False
        if owner_id == user_id:
            # User owns the file
            can_delete = True
        elif team_id:
            # File belongs to a team - check if user is a team member with appropriate role
            if check_team_access(cursor, user_id, team_id, 'member'):
                # Team members can delete team files
                can_delete = True

        if not can_delete:
            raise HTTPException(status_code=403, detail="Access denied")

        # Soft delete
        cursor.execute(
            "UPDATE drive_files SET is_deleted = TRUE, updated_at = NOW() WHERE id = %s",
            (file_id,)
        )
        conn.commit()

        log_audit_event(cursor, user_id, "file_deleted", "success", None, {"file_id": file_id})

        return {"message": "File deleted successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Delete file error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete file")
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/storage/usage")
async def get_storage_usage(
    current_user: dict = Depends(require_auth)
):
    """
    Get current storage usage for the user
    Returns usage in bytes and percentage of limit
    """
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get current usage
        usage_bytes = get_user_storage_usage(cursor, user_id)
        limit_bytes = USER_STORAGE_LIMIT

        # Calculate percentage
        usage_percentage = (usage_bytes / limit_bytes) * 100 if limit_bytes > 0 else 0

        # Convert to MB for display
        usage_mb = usage_bytes / (1024 * 1024)
        limit_mb = limit_bytes / (1024 * 1024)

        return {
            "usage_bytes": usage_bytes,
            "limit_bytes": limit_bytes,
            "usage_mb": round(usage_mb, 2),
            "limit_mb": round(limit_mb, 2),
            "usage_percentage": round(usage_percentage, 1),
            "remaining_bytes": limit_bytes - usage_bytes,
            "remaining_mb": round((limit_bytes - usage_bytes) / (1024 * 1024), 2)
        }

    except Exception as e:
        logger.error(f"Storage usage error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get storage usage"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/files/{file_id}/download")
@limiter.limit("60/hour")
async def download_file(
    file_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Download and decrypt file"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get file metadata (IDOR check)
        cursor.execute(
            """
            SELECT file_path, encryption_iv, encryption_tag, filename_encrypted,
                   mime_type_encrypted, owner_id, team_id
            FROM drive_files
            WHERE id = %s AND is_deleted = FALSE
            """,
            (file_id,)
        )

        file_data = cursor.fetchone()

        if not file_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )

        file_path, iv_b64, tag_b64, filename_enc, mime_enc, owner_id, team_id = file_data

        # Check access (IDOR prevention)
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to file"
                )
            encryption_key = get_team_key(cursor, user_id, team_id)
        elif owner_id == user_id:
            encryption_key = get_user_key(user_id, cursor)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No access to file"
            )

        # Read encrypted file
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found on disk"
            )

        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        # Decrypt file
        iv = key_from_base64(iv_b64)
        tag = key_from_base64(tag_b64)
        plaintext = decrypt_file_content(ciphertext, encryption_key, iv, tag)

        # Decrypt filename for header
        # Note: filename_enc is already base64, need to parse it
        # For simplicity, use generic filename
        filename = f"download_{file_id}"

        log_audit_event(cursor, user_id, "file_downloaded", "success",
                       None, {"file_id": file_id})

        conn.commit()

        # Return as streaming response
        return StreamingResponse(
            io.BytesIO(plaintext),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# Notes Endpoints

@router.post("/notes", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/hour")
async def create_note(
    note_data: NoteCreate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Create encrypted note"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Determine encryption key
        if note_data.team_id:
            if not check_team_access(cursor, user_id, note_data.team_id, 'member'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team"
                )
            encryption_key = get_team_key(cursor, user_id, note_data.team_id)
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Encrypt title and content together with a delimiter
        # This ensures they share the same IV and TAG (as table only has one set)
        combined_data = f"{note_data.title}|||{note_data.content}"
        combined_enc, combined_iv, combined_tag = encrypt_text(combined_data, encryption_key)

        # Store encrypted data (split not needed - will decrypt together)
        cursor.execute(
            """
            INSERT INTO notes (
                title_encrypted, content_encrypted, owner_id, team_id, folder_id,
                encryption_iv, encryption_tag
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                combined_enc, combined_enc, user_id, note_data.team_id,
                note_data.folder_id, combined_iv, combined_tag
            )
        )

        note_id = cursor.fetchone()[0]

        log_audit_event(cursor, user_id, "note_created", "success",
                       None, {"note_id": note_id})

        conn.commit()

        return {
            "message": "Note created successfully",
            "note_id": note_id
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Note creation error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Note creation failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/notes")
@limiter.limit("60/hour")
async def list_notes(
    request: Request,
    team_id: Optional[int] = None,
    folder_id: Optional[int] = None,
    current_user: dict = Depends(require_auth)
):
    """List user's notes (decrypted titles)"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Build query based on filters and get encryption key
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team"
                )
            decryption_key = get_team_key(cursor, user_id, team_id)
        else:
            # Get user's encryption key
            decryption_key = get_user_key(user_id, cursor)

        # Fetch notes with IV and TAG for decryption
        cursor.execute(
            """
            SELECT id, title_encrypted, encryption_iv, encryption_tag,
                   created_at, updated_at, is_pinned
            FROM notes
            WHERE {}
            ORDER BY is_pinned DESC, updated_at DESC
            """.format(
                "team_id = %s AND is_deleted = FALSE" if team_id
                else "owner_id = %s AND team_id IS NULL AND is_deleted = FALSE"
            ),
            (team_id if team_id else user_id,)
        )

        notes = []
        for row in cursor.fetchall():
            # Decrypt title for display (from combined encrypted data)
            try:
                # Decrypt combined data
                combined_decrypted = decrypt_text(row[1], decryption_key, row[2], row[3])

                # Extract just the title (before delimiter)
                if '|||' in combined_decrypted:
                    title_decrypted = combined_decrypted.split('|||', 1)[0]
                else:
                    # Fallback for old format
                    title_decrypted = "Untitled Note"
            except Exception as e:
                logger.warning(f"Failed to decrypt note title for note {row[0]}: {e}")
                title_decrypted = "Untitled Note"

            notes.append({
                "id": row[0],
                "title": title_decrypted,
                "created_at": row[4].isoformat() if row[4] else None,
                "updated_at": row[5].isoformat() if row[5] else None,
                "is_pinned": row[6]
            })

        return {"notes": notes}

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/notes/{note_id}")
@limiter.limit("60/hour")
async def get_note(
    note_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Get note details (decrypted)"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get note (IDOR check)
        cursor.execute(
            """
            SELECT title_encrypted, content_encrypted, owner_id, team_id,
                   encryption_iv, encryption_tag, created_at, updated_at, is_pinned
            FROM notes
            WHERE id = %s AND is_deleted = FALSE
            """,
            (note_id,)
        )

        note_data = cursor.fetchone()

        if not note_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Note not found"
            )

        title_enc, content_enc, owner_id, team_id, iv, tag, created, updated, pinned = note_data

        # Check access (IDOR prevention) and get decryption key
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to note"
                )
            decryption_key = get_team_key(cursor, user_id, team_id)
        else:
            # Check ownership for personal notes
            if owner_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to note"
                )
            # Use user's encryption key
            decryption_key = get_user_key(user_id, cursor)

        # Decrypt combined data and split into title and content
        try:
            # Decrypt the combined encrypted data (title and content stored together)
            combined_decrypted = decrypt_text(title_enc, decryption_key, iv, tag)

            # Split back into title and content using delimiter
            if '|||' in combined_decrypted:
                parts = combined_decrypted.split('|||', 1)
                title_decrypted = parts[0]
                content_decrypted = parts[1] if len(parts) > 1 else ''
            else:
                # Fallback for old format (legacy notes)
                title_decrypted = "Untitled Note"
                content_decrypted = combined_decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt note {note_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt note"
            )

        return {
            "id": note_id,
            "title": title_decrypted,
            "content": content_decrypted,
            "created_at": created.isoformat() if created else None,
            "updated_at": updated.isoformat() if updated else None,
            "is_pinned": pinned
        }

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.put("/notes/{note_id}")
@limiter.limit("30/hour")
async def update_note(
    note_id: int,
    note_update: NoteUpdate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Update note"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get note and check ownership
        cursor.execute(
            """
            SELECT owner_id, team_id FROM notes
            WHERE id = %s AND is_deleted = FALSE
            """,
            (note_id,)
        )

        note_data = cursor.fetchone()

        if not note_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Note not found"
            )

        owner_id, team_id = note_data

        # Check permissions (IDOR prevention)
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'member'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No edit access"
                )
            encryption_key = get_team_key(cursor, user_id, team_id)
        elif owner_id == user_id:
            encryption_key = get_user_key(user_id, cursor)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No edit access"
            )

        # Update fields
        if note_update.title and note_update.content:
            # Combine title and content with delimiter before encryption
            combined_data = f"{note_update.title}|||{note_update.content}"
            combined_enc, combined_iv, combined_tag = encrypt_text(combined_data, encryption_key)

            cursor.execute(
                """
                UPDATE notes
                SET title_encrypted = %s, content_encrypted = %s,
                    encryption_iv = %s, encryption_tag = %s
                WHERE id = %s
                """,
                (combined_enc, combined_enc, combined_iv, combined_tag, note_id)
            )
        elif note_update.is_pinned is not None:
            cursor.execute(
                "UPDATE notes SET is_pinned = %s WHERE id = %s",
                (note_update.is_pinned, note_id)
            )

        log_audit_event(cursor, user_id, "note_updated", "success",
                       None, {"note_id": note_id})

        conn.commit()

        return {"message": "Note updated successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Note update error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Note update failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

# Ideas (Collaboration) Endpoints

@router.post("/ideas", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")
async def create_idea(
    idea_data: IdeaCreate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Create collaborative idea"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Determine encryption key
        if idea_data.team_id:
            if not check_team_access(cursor, user_id, idea_data.team_id, 'member'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team"
                )
            encryption_key = get_team_key(cursor, user_id, idea_data.team_id)
        else:
            encryption_key = get_user_key(user_id, cursor)

        # Encrypt data
        title_enc, title_iv, title_tag = encrypt_text(idea_data.title, encryption_key)
        content_enc, content_iv, content_tag = encrypt_text(idea_data.content, encryption_key)

        desc_enc = None
        if idea_data.description:
            desc_enc, _, _ = encrypt_text(idea_data.description, encryption_key)

        # Create idea
        cursor.execute(
            """
            INSERT INTO ideas (
                title_encrypted, description_encrypted, content_encrypted,
                owner_id, team_id, status, encryption_iv, encryption_tag
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                title_enc, desc_enc, content_enc, user_id,
                idea_data.team_id, idea_data.status, content_iv, content_tag
            )
        )

        idea_id = cursor.fetchone()[0]

        # Create initial version
        cursor.execute(
            """
            INSERT INTO idea_versions (
                idea_id, content_encrypted, encryption_iv, encryption_tag,
                version_number, created_by, change_description_encrypted
            )
            VALUES (%s, %s, %s, %s, 1, %s, %s)
            """,
            (idea_id, content_enc, content_iv, content_tag, user_id, None)
        )

        log_audit_event(cursor, user_id, "idea_created", "success",
                       None, {"idea_id": idea_id})

        conn.commit()

        return {
            "message": "Idea created successfully",
            "idea_id": idea_id
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Idea creation error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Idea creation failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/ideas/{idea_id}/contributors")
@limiter.limit("20/hour")
async def add_idea_contributor(
    idea_id: int,
    contributor_data: IdeaContributorAdd,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Add contributor to idea"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the idea
        cursor.execute(
            "SELECT owner_id, team_id FROM ideas WHERE id = %s AND is_deleted = FALSE",
            (idea_id,)
        )

        idea_data = cursor.fetchone()

        if not idea_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Idea not found"
            )

        owner_id, team_id = idea_data

        # Only owner or team admin can add contributors
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'admin'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
        elif owner_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owner can add contributors"
            )

        # Add contributor
        cursor.execute(
            """
            INSERT INTO idea_contributors (idea_id, user_id, role, added_by)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (idea_id, user_id) DO UPDATE SET role = EXCLUDED.role
            """,
            (idea_id, contributor_data.user_id, contributor_data.role, user_id)
        )

        log_audit_event(cursor, user_id, "idea_contributor_added", "success",
                       None, {"idea_id": idea_id, "contributor_id": contributor_data.user_id})

        conn.commit()

        return {"message": "Contributor added successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Add contributor error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add contributor"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/ideas")
@limiter.limit("60/hour")
async def list_ideas(
    request: Request,
    team_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    current_user: dict = Depends(require_auth)
):
    """List ideas user has access to"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team"
                )

            query = """
                SELECT id, title_encrypted, status, owner_id, created_at, updated_at
                FROM ideas
                WHERE team_id = %s AND is_deleted = FALSE
            """
            params = [team_id]
        else:
            query = """
                SELECT DISTINCT i.id, i.title_encrypted, i.status, i.owner_id, i.created_at, i.updated_at
                FROM ideas i
                LEFT JOIN idea_contributors ic ON i.id = ic.idea_id
                WHERE (i.owner_id = %s OR ic.user_id = %s) AND i.is_deleted = FALSE
            """
            params = [user_id, user_id]

        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)

        query += " ORDER BY updated_at DESC"

        cursor.execute(query, params)

        ideas = []
        for row in cursor.fetchall():
            ideas.append({
                "id": row[0],
                "title_encrypted": row[1],
                "status": row[2],
                "owner_id": row[3],
                "created_at": row[4].isoformat() if row[4] else None,
                "updated_at": row[5].isoformat() if row[5] else None
            })

        return {"ideas": ideas}

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/notes/{note_id}")
@limiter.limit("30/hour")
async def delete_note(
    note_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Soft delete note"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check ownership
        cursor.execute(
            "SELECT owner_id FROM notes WHERE id = %s AND is_deleted = FALSE",
            (note_id,)
        )

        result = cursor.fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Note not found"
            )

        if result[0] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No permission to delete"
            )

        # Soft delete
        cursor.execute(
            "UPDATE notes SET is_deleted = TRUE WHERE id = %s",
            (note_id,)
        )

        log_audit_event(cursor, user_id, "note_deleted", "success",
                       None, {"note_id": note_id})

        conn.commit()

        return {"message": "Note deleted successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


# Encrypted Backup Endpoints

class BackupCreate(BaseModel):
    """Create backup model"""
    backup_name: str = Field(..., min_length=3, max_length=255)
    team_id: Optional[int] = None
    retention_days: int = Field(default=30, ge=1, le=365)

@router.post("/backups/create", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def create_backup(
    backup_data: BackupCreate,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Create encrypted backup of user's or team's data

    Features:
    - Zero-knowledge encryption (encrypted with user/team key)
    - Gzip compression (typically 70-90% reduction)
    - Includes files, notes, and ideas
    - Configurable retention period
    - Checksum verification

    NOTE: This feature has been disabled
    """
    raise HTTPException(status_code=404, detail="Backup feature is not available")

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Determine if user backup or team backup
        if backup_data.team_id:
            # Verify team access
            if not check_team_access(cursor, user_id, backup_data.team_id, 'admin'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only team admins can create backups"
                )

            encryption_key = get_team_key(cursor, user_id, backup_data.team_id)
            files, notes, ideas = collect_team_data(cursor, backup_data.team_id, encryption_key)
            backup_type = "team"
            owner_context = f"team_{backup_data.team_id}"
        else:
            encryption_key = get_user_key(user_id, cursor)
            files, notes, ideas = collect_user_data(cursor, user_id, encryption_key)
            backup_type = "user"
            owner_context = f"user_{user_id}"

        # Create manifest
        manifest = create_backup_manifest(
            files=files,
            notes=notes,
            ideas=ideas,
            owner_id=user_id,
            team_id=backup_data.team_id
        )

        # Create encrypted backup
        try:
            encrypted_data, iv, tag, checksum, original_size, compressed_size = create_encrypted_backup(
                manifest, encryption_key
            )
        except BackupError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

        # Generate unique backup path
        backup_uuid = str(uuid.uuid4())
        backup_filename = f"{owner_context}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{backup_uuid}.backup"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)

        # Ensure backup directory exists
        os.makedirs(BACKUP_DIR, exist_ok=True)

        # Write encrypted backup to disk
        with open(backup_path, 'wb') as f:
            f.write(encrypted_data)

        # Calculate expiry
        expires_at = calculate_backup_expiry(backup_data.retention_days)

        # Store backup metadata in database
        cursor.execute(
            """
            INSERT INTO drive_backups (
                backup_name, backup_type, owner_id, team_id, backup_path,
                backup_size, compressed_size, encryption_iv, encryption_tag,
                checksum, file_count, note_count, idea_count,
                status, expires_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                backup_data.backup_name, 'full', user_id, backup_data.team_id,
                backup_path, original_size, compressed_size, iv, tag, checksum,
                len(files), len(notes), len(ideas), 'completed', expires_at
            )
        )

        backup_id = cursor.fetchone()[0]

        log_audit_event(
            cursor, user_id, "backup_created", "success",
            request.client.host if request.client else None,
            {
                "backup_id": backup_id,
                "backup_type": backup_type,
                "team_id": backup_data.team_id,
                "items": len(files) + len(notes) + len(ideas),
                "compressed_size": compressed_size
            }
        )

        conn.commit()

        return {
            "message": "Backup created successfully",
            "backup_id": backup_id,
            "backup_name": backup_data.backup_name,
            "stats": {
                "files": len(files),
                "notes": len(notes),
                "ideas": len(ideas),
                "total_items": len(files) + len(notes) + len(ideas),
                "original_size": original_size,
                "compressed_size": compressed_size,
                "compression_ratio": f"{compressed_size/original_size*100:.1f}%"
            },
            "expires_at": expires_at.isoformat()
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Backup creation error: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Backup creation failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/backups")
@limiter.limit("30/hour")
async def list_backups(
    request: Request,
    team_id: Optional[int] = None,
    current_user: dict = Depends(require_auth)
):
    """List all backups for user or team

    NOTE: This feature has been disabled
    """
    raise HTTPException(status_code=404, detail="Backup feature is not available")

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if team_id:
            # Verify team access
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to team backups"
                )

            cursor.execute(
                """
                SELECT id, backup_name, backup_type, backup_size, compressed_size,
                       file_count, note_count, idea_count, status,
                       created_at, expires_at
                FROM drive_backups
                WHERE team_id = %s AND is_deleted = FALSE
                ORDER BY created_at DESC
                """,
                (team_id,)
            )
        else:
            cursor.execute(
                """
                SELECT id, backup_name, backup_type, backup_size, compressed_size,
                       file_count, note_count, idea_count, status,
                       created_at, expires_at
                FROM drive_backups
                WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
                ORDER BY created_at DESC
                """,
                (user_id,)
            )

        backups = []
        for row in cursor.fetchall():
            backups.append({
                "id": row[0],
                "backup_name": row[1],
                "backup_type": row[2],
                "backup_size": row[3],
                "compressed_size": row[4],
                "file_count": row[5],
                "note_count": row[6],
                "idea_count": row[7],
                "status": row[8],
                "created_at": row[9].isoformat() if row[9] else None,
                "expires_at": row[10].isoformat() if row[10] else None,
                "compression_ratio": f"{row[4]/row[3]*100:.1f}%" if row[3] > 0 else "0%"
            })

        return {"backups": backups, "count": len(backups)}

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/backups/{backup_id}/download")
@limiter.limit("10/hour")
async def download_backup(
    backup_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Download encrypted backup file

    NOTE: This feature has been disabled
    """
    raise HTTPException(status_code=404, detail="Backup feature is not available")

    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get backup metadata (IDOR check)
        cursor.execute(
            """
            SELECT backup_name, backup_path, owner_id, team_id, status, is_deleted
            FROM drive_backups
            WHERE id = %s
            """,
            (backup_id,)
        )

        backup_data = cursor.fetchone()

        if not backup_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        backup_name, backup_path, owner_id, team_id, backup_status, is_deleted = backup_data

        if is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup has been deleted"
            )

        if backup_status != 'completed':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Backup status is '{backup_status}'"
            )

        # Check access (IDOR prevention)
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'viewer'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access to this backup"
                )
        elif owner_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No access to this backup"
            )

        # Read backup file
        if not os.path.exists(backup_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup file not found on disk"
            )

        with open(backup_path, 'rb') as f:
            backup_content = f.read()

        log_audit_event(
            cursor, user_id, "backup_downloaded", "success",
            request.client.host if request.client else None,
            {"backup_id": backup_id}
        )

        conn.commit()

        # Return as streaming response
        return StreamingResponse(
            io.BytesIO(backup_content),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={backup_name}.backup"}
        )

    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.delete("/backups/{backup_id}")
@limiter.limit("20/hour")
async def delete_backup(
    backup_id: int,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Delete backup (soft delete)"""
    user_id = current_user["id"]
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check ownership
        cursor.execute(
            "SELECT owner_id, team_id FROM drive_backups WHERE id = %s AND is_deleted = FALSE",
            (backup_id,)
        )

        result = cursor.fetchone()

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup not found"
            )

        owner_id, team_id = result

        # Verify permissions
        if team_id:
            if not check_team_access(cursor, user_id, team_id, 'admin'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only team admins can delete backups"
                )
        elif owner_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No permission to delete this backup"
            )

        # Soft delete
        cursor.execute(
            "UPDATE drive_backups SET is_deleted = TRUE WHERE id = %s",
            (backup_id,)
        )

        log_audit_event(
            cursor, user_id, "backup_deleted", "success",
            request.client.host if request.client else None,
            {"backup_id": backup_id}
        )

        conn.commit()

        return {"message": "Backup deleted successfully"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


# ========================================
# Scheduled Backup Endpoints
# ========================================

class ScheduledBackupCreate(BaseModel):
    """Create scheduled backup configuration"""
    team_id: Optional[int] = None
    schedule_name: str = Field(..., min_length=1, max_length=255)
    frequency: str = Field(..., pattern="^(daily|weekly|monthly)$")
    retention_days: int = Field(default=30, ge=1, le=365)


class ScheduledBackupUpdate(BaseModel):
    """Update scheduled backup configuration"""
    schedule_name: Optional[str] = Field(None, min_length=1, max_length=255)
    frequency: Optional[str] = Field(None, pattern="^(daily|weekly|monthly)$")
    retention_days: Optional[int] = Field(None, ge=1, le=365)
    is_active: Optional[bool] = None


@router.post("/schedules/create", status_code=201)
@limiter.limit("10/minute")
async def create_backup_schedule(
    request: Request,
    schedule: ScheduledBackupCreate,
    current_user: dict = Depends(require_auth)
):
    """
    Create a scheduled backup configuration
    
    Supports:
    - Individual user backups (team_id=None)
    - Team backups (team_id specified, requires admin/owner role)
    
    Frequencies:
    - daily: Runs every 24 hours
    - weekly: Runs every 7 days
    - monthly: Runs every 30 days
    """
    user_id = current_user["id"]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Verify team ownership if team backup
        if schedule.team_id:
            cursor.execute(
                """
                SELECT role FROM team_members
                WHERE team_id = %s AND user_id = %s AND is_active = TRUE
                """,
                (schedule.team_id, user_id)
            )
            
            member = cursor.fetchone()
            if not member:
                raise HTTPException(403, detail="Not a member of this team")
            
            if member[0] not in ['admin', 'owner']:
                raise HTTPException(403, detail="Only team admins/owners can schedule backups")
        
        # Calculate next backup time
        from datetime import datetime, timedelta
        next_backup = datetime.now()
        
        if schedule.frequency == "daily":
            next_backup += timedelta(days=1)
        elif schedule.frequency == "weekly":
            next_backup += timedelta(days=7)
        elif schedule.frequency == "monthly":
            next_backup += timedelta(days=30)
        
        # Create schedule
        cursor.execute(
            """
            INSERT INTO backup_schedules (
                user_id, team_id, schedule_name, backup_type, frequency,
                retention_days, next_backup_at
            )
            VALUES (%s, %s, %s, 'full', %s, %s, %s)
            RETURNING id
            """,
            (
                user_id if not schedule.team_id else None,
                schedule.team_id,
                schedule.schedule_name,
                schedule.frequency,
                schedule.retention_days,
                next_backup
            )
        )
        
        schedule_id = cursor.fetchone()[0]
        conn.commit()
        
        log_audit_event(
            user_id=user_id,
            action="backup_schedule_created",
            resource_type="backup_schedule",
            resource_id=schedule_id,
            ip_address=request.client.host,
            status="success",
            details={
                "team_id": schedule.team_id,
                "frequency": schedule.frequency
            }
        )
        
        return {
            "schedule_id": schedule_id,
            "message": "Backup schedule created successfully",
            "next_backup_at": next_backup.isoformat()
        }


@router.get("/schedules")
@limiter.limit("30/minute")
async def list_backup_schedules(
    request: Request,
    team_id: Optional[int] = None,
    current_user: dict = Depends(require_auth)
):
    """
    List user's or team's backup schedules
    """
    user_id = current_user["id"]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if team_id:
            # Verify team membership
            cursor.execute(
                """
                SELECT 1 FROM team_members
                WHERE team_id = %s AND user_id = %s AND is_active = TRUE
                """,
                (team_id, user_id)
            )
            
            if not cursor.fetchone():
                raise HTTPException(403, detail="Not a member of this team")
            
            # Get team schedules
            cursor.execute(
                """
                SELECT id, schedule_name, backup_type, frequency, retention_days,
                       is_active, last_backup_at, next_backup_at, created_at
                FROM backup_schedules
                WHERE team_id = %s
                ORDER BY created_at DESC
                """,
                (team_id,)
            )
        else:
            # Get user schedules
            cursor.execute(
                """
                SELECT id, schedule_name, backup_type, frequency, retention_days,
                       is_active, last_backup_at, next_backup_at, created_at
                FROM backup_schedules
                WHERE user_id = %s AND team_id IS NULL
                ORDER BY created_at DESC
                """,
                (user_id,)
            )
        
        schedules = []
        for row in cursor.fetchall():
            schedules.append({
                "id": row[0],
                "schedule_name": row[1],
                "backup_type": row[2],
                "frequency": row[3],
                "retention_days": row[4],
                "is_active": row[5],
                "last_backup_at": row[6].isoformat() if row[6] else None,
                "next_backup_at": row[7].isoformat() if row[7] else None,
                "created_at": row[8].isoformat() if row[8] else None
            })
        
        return {"schedules": schedules, "count": len(schedules)}


@router.put("/schedules/{schedule_id}")
@limiter.limit("20/minute")
async def update_backup_schedule(
    request: Request,
    schedule_id: int,
    update: ScheduledBackupUpdate,
    current_user: dict = Depends(require_auth)
):
    """
    Update backup schedule configuration
    """
    user_id = current_user["id"]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute(
            """
            SELECT user_id, team_id FROM backup_schedules WHERE id = %s
            """,
            (schedule_id,)
        )
        
        schedule = cursor.fetchone()
        if not schedule:
            raise HTTPException(404, detail="Schedule not found")
        
        owner_id, team_id = schedule
        
        # Check ownership
        if team_id:
            cursor.execute(
                """
                SELECT role FROM team_members
                WHERE team_id = %s AND user_id = %s AND is_active = TRUE
                """,
                (team_id, user_id)
            )
            
            member = cursor.fetchone()
            if not member or member[0] not in ['admin', 'owner']:
                raise HTTPException(403, detail="Insufficient permissions")
        else:
            if owner_id != user_id:
                raise HTTPException(403, detail="Not your schedule")
        
        # Build update query dynamically
        updates = []
        params = []
        
        if update.schedule_name is not None:
            updates.append("schedule_name = %s")
            params.append(update.schedule_name)
        
        if update.frequency is not None:
            updates.append("frequency = %s")
            params.append(update.frequency)
        
        if update.retention_days is not None:
            updates.append("retention_days = %s")
            params.append(update.retention_days)
        
        if update.is_active is not None:
            updates.append("is_active = %s")
            params.append(update.is_active)
        
        if not updates:
            raise HTTPException(400, detail="No updates provided")
        
        updates.append("updated_at = NOW()")
        params.append(schedule_id)
        
        query = f"UPDATE backup_schedules SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(query, tuple(params))
        conn.commit()
        
        log_audit_event(
            user_id=user_id,
            action="backup_schedule_updated",
            resource_type="backup_schedule",
            resource_id=schedule_id,
            ip_address=request.client.host,
            status="success"
        )
        
        return {"message": "Schedule updated successfully"}


@router.delete("/schedules/{schedule_id}")
@limiter.limit("20/minute")
async def delete_backup_schedule(
    request: Request,
    schedule_id: int,
    current_user: dict = Depends(require_auth)
):
    """
    Delete backup schedule
    """
    user_id = current_user["id"]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute(
            """
            SELECT user_id, team_id FROM backup_schedules WHERE id = %s
            """,
            (schedule_id,)
        )
        
        schedule = cursor.fetchone()
        if not schedule:
            raise HTTPException(404, detail="Schedule not found")
        
        owner_id, team_id = schedule
        
        # Check ownership
        if team_id:
            cursor.execute(
                """
                SELECT role FROM team_members
                WHERE team_id = %s AND user_id = %s AND is_active = TRUE
                """,
                (team_id, user_id)
            )
            
            member = cursor.fetchone()
            if not member or member[0] not in ['admin', 'owner']:
                raise HTTPException(403, detail="Insufficient permissions")
        else:
            if owner_id != user_id:
                raise HTTPException(403, detail="Not your schedule")
        
        # Delete schedule
        cursor.execute("DELETE FROM backup_schedules WHERE id = %s", (schedule_id,))
        conn.commit()
        
        log_audit_event(
            user_id=user_id,
            action="backup_schedule_deleted",
            resource_type="backup_schedule",
            resource_id=schedule_id,
            ip_address=request.client.host,
            status="success"
        )
        
        return {"message": "Schedule deleted successfully"}


# ========================================
# Data Export Endpoints
# ========================================

class DataExportRequest(BaseModel):
    """Data export request"""
    export_format: str = Field(..., pattern="^(json|csv)$")
    include_files: bool = Field(default=True)
    include_notes: bool = Field(default=True)
    include_ideas: bool = Field(default=True)
    team_id: Optional[int] = None


@router.post("/export")
@limiter.limit("5/minute")
async def export_data(
    request: Request,
    export_req: DataExportRequest,
    current_user: dict = Depends(require_auth)
):
    """
    Export user's or team's data in JSON or CSV format

    Returns encrypted data that can be decrypted client-side
    or plaintext exports for data portability

    NOTE: This feature has been disabled
    """
    raise HTTPException(status_code=404, detail="Data export feature is not available")

    user_id = current_user["id"]
    from utils.backup import collect_user_data, collect_team_data
    from utils.encryption import decrypt_user_key
    import csv
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(404, detail="User not found")
        
        encryption_key = decrypt_user_key(user_row[0])
        
        # Collect data
        if export_req.team_id:
            # Verify team membership
            cursor.execute(
                """
                SELECT team_key_encrypted FROM team_members
                WHERE team_id = %s AND user_id = %s AND is_active = TRUE
                """,
                (export_req.team_id, user_id)
            )
            
            member = cursor.fetchone()
            if not member:
                raise HTTPException(403, detail="Not a member of this team")
            
            # Decrypt team key
            team_key = decrypt_user_key(member[0])
            
            files, notes, ideas = collect_team_data(cursor, export_req.team_id, team_key)
        else:
            files, notes, ideas = collect_user_data(cursor, user_id, encryption_key)
        
        # Filter based on request
        export_data = {}
        
        if export_req.include_files:
            export_data["files"] = files
        
        if export_req.include_notes:
            export_data["notes"] = notes
        
        if export_req.include_ideas:
            export_data["ideas"] = ideas
        
        export_data["exported_at"] = datetime.now().isoformat()
        export_data["user_id"] = user_id
        export_data["team_id"] = export_req.team_id
        
        # Log export
        log_audit_event(
            user_id=user_id,
            action="data_exported",
            resource_type="export",
            ip_address=request.client.host,
            status="success",
            details={
                "format": export_req.export_format,
                "team_id": export_req.team_id,
                "file_count": len(files) if export_req.include_files else 0,
                "note_count": len(notes) if export_req.include_notes else 0,
                "idea_count": len(ideas) if export_req.include_ideas else 0
            }
        )
        
        # Return based on format
        if export_req.export_format == "json":
            return JSONResponse(
                content=export_data,
                headers={
                    "Content-Disposition": f"attachment; filename=export_{user_id}_{int(datetime.now().timestamp())}.json"
                }
            )
        
        elif export_req.export_format == "csv":
            # Create CSV with multiple sheets (combined into one file with sections)
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Files section
            if export_req.include_files and files:
                writer.writerow(["=== FILES ==="])
                writer.writerow(["ID", "Filename (Encrypted)", "File Size", "Created At", "Updated At"])
                for f in files:
                    writer.writerow([
                        f.get("id"),
                        f.get("filename_encrypted"),
                        f.get("file_size"),
                        f.get("created_at"),
                        f.get("updated_at")
                    ])
                writer.writerow([])
            
            # Notes section
            if export_req.include_notes and notes:
                writer.writerow(["=== NOTES ==="])
                writer.writerow(["ID", "Title (Encrypted)", "Created At", "Updated At", "Is Pinned"])
                for n in notes:
                    writer.writerow([
                        n.get("id"),
                        n.get("title_encrypted"),
                        n.get("created_at"),
                        n.get("updated_at"),
                        n.get("is_pinned")
                    ])
                writer.writerow([])
            
            # Ideas section
            if export_req.include_ideas and ideas:
                writer.writerow(["=== IDEAS ==="])
                writer.writerow(["ID", "Title (Encrypted)", "Status", "Created At", "Updated At"])
                for i in ideas:
                    writer.writerow([
                        i.get("id"),
                        i.get("title_encrypted"),
                        i.get("status"),
                        i.get("created_at"),
                        i.get("updated_at")
                    ])
            
            csv_content = output.getvalue()
            output.close()
            
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=export_{user_id}_{int(datetime.now().timestamp())}.csv"
                }
            )
