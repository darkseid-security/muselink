"""
utils/backup.py
Encrypted backup and archive utilities for Encrypted Drive
Supports individual and team backups with compression and encryption
"""

import os
import io
import json
import gzip
import tarfile
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import hashlib

from utils.crypto_aes import (
    encrypt_file_content, decrypt_file_content,
    key_to_base64, key_from_base64
)

logger = logging.getLogger(__name__)

BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")
MAX_BACKUP_SIZE = 500 * 1024 * 1024  # 500MB


class BackupError(Exception):
    """Custom exception for backup operations"""
    pass


def create_backup_manifest(
    files: List[Dict],
    notes: List[Dict],
    ideas: List[Dict],
    owner_id: int,
    team_id: Optional[int] = None
) -> Dict:
    """
    Create backup manifest with metadata

    Args:
        files: List of file metadata dicts
        notes: List of note metadata dicts
        ideas: List of idea metadata dicts
        owner_id: User ID creating backup
        team_id: Team ID (if team backup)

    Returns:
        Manifest dictionary
    """
    manifest = {
        "backup_version": "1.0",
        "created_at": datetime.now().isoformat(),
        "owner_id": owner_id,
        "team_id": team_id,
        "counts": {
            "files": len(files),
            "notes": len(notes),
            "ideas": len(ideas),
            "total_items": len(files) + len(notes) + len(ideas)
        },
        "files": files,
        "notes": notes,
        "ideas": ideas
    }

    return manifest


def compress_data(data: bytes) -> bytes:
    """
    Compress data using gzip

    Args:
        data: Raw bytes to compress

    Returns:
        Compressed bytes
    """
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=9) as gz:
        gz.write(data)
    return buffer.getvalue()


def decompress_data(compressed_data: bytes) -> bytes:
    """
    Decompress gzip data

    Args:
        compressed_data: Compressed bytes

    Returns:
        Decompressed bytes
    """
    buffer = io.BytesIO(compressed_data)
    with gzip.GzipFile(fileobj=buffer, mode='rb') as gz:
        return gz.read()


def create_encrypted_backup(
    manifest: Dict,
    encryption_key: bytes
) -> Tuple[bytes, str, str, str, int, int]:
    """
    Create encrypted and compressed backup from manifest

    Args:
        manifest: Backup manifest dictionary
        encryption_key: AES-256 key for encryption

    Returns:
        Tuple of (encrypted_data, iv, tag, checksum, original_size, compressed_size)
    """
    # Convert manifest to JSON
    manifest_json = json.dumps(manifest, indent=2).encode('utf-8')
    original_size = len(manifest_json)

    logger.info(f"Creating backup: {manifest['counts']['total_items']} items, {original_size} bytes")

    # Compress data
    compressed_data = compress_data(manifest_json)
    compressed_size = len(compressed_data)

    logger.info(f"Compressed: {original_size} -> {compressed_size} bytes ({compressed_size/original_size*100:.1f}%)")

    # Check size limit
    if compressed_size > MAX_BACKUP_SIZE:
        raise BackupError(f"Backup size {compressed_size} exceeds limit of {MAX_BACKUP_SIZE} bytes")

    # Encrypt compressed data
    ciphertext, iv, tag = encrypt_file_content(compressed_data, encryption_key)

    # Calculate checksum of encrypted data
    checksum = hashlib.sha256(ciphertext).hexdigest()

    return ciphertext, key_to_base64(iv), key_to_base64(tag), checksum, original_size, compressed_size


def decrypt_and_extract_backup(
    encrypted_data: bytes,
    encryption_key: bytes,
    iv: str,
    tag: str
) -> Dict:
    """
    Decrypt and extract backup manifest

    Args:
        encrypted_data: Encrypted backup bytes
        encryption_key: AES-256 decryption key
        iv: Initialization vector (base64)
        tag: Authentication tag (base64)

    Returns:
        Manifest dictionary

    Raises:
        BackupError: If decryption or decompression fails
    """
    try:
        # Decrypt data
        iv_bytes = key_from_base64(iv)
        tag_bytes = key_from_base64(tag)
        compressed_data = decrypt_file_content(encrypted_data, encryption_key, iv_bytes, tag_bytes)

        # Decompress data
        manifest_json = decompress_data(compressed_data)

        # Parse JSON
        manifest = json.loads(manifest_json.decode('utf-8'))

        logger.info(f"Extracted backup: {manifest['counts']['total_items']} items")

        return manifest

    except Exception as e:
        logger.error(f"Backup extraction failed: {e}")
        raise BackupError(f"Failed to extract backup: {str(e)}")


def collect_user_data(cursor, user_id: int, encryption_key: bytes) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Collect all user's files, notes, and ideas for backup

    Args:
        cursor: Database cursor
        user_id: User ID
        encryption_key: User's encryption key

    Returns:
        Tuple of (files, notes, ideas) lists
    """
    files = []
    notes = []
    ideas = []

    # Collect files
    cursor.execute(
        """
        SELECT id, filename_encrypted, file_path, file_size, mime_type_encrypted,
               encryption_iv, encryption_tag, created_at, updated_at, folder_id
        FROM drive_files
        WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (user_id,)
    )

    for row in cursor.fetchall():
        files.append({
            "id": row[0],
            "filename_encrypted": row[1],
            "file_path": row[2],
            "file_size": row[3],
            "mime_type_encrypted": row[4],
            "encryption_iv": row[5],
            "encryption_tag": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "updated_at": row[8].isoformat() if row[8] else None,
            "folder_id": row[9]
        })

    # Collect notes
    cursor.execute(
        """
        SELECT id, title_encrypted, content_encrypted, encryption_iv, encryption_tag,
               created_at, updated_at, folder_id, is_pinned
        FROM notes
        WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (user_id,)
    )

    for row in cursor.fetchall():
        notes.append({
            "id": row[0],
            "title_encrypted": row[1],
            "content_encrypted": row[2],
            "encryption_iv": row[3],
            "encryption_tag": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
            "updated_at": row[6].isoformat() if row[6] else None,
            "folder_id": row[7],
            "is_pinned": row[8]
        })

    # Collect ideas
    cursor.execute(
        """
        SELECT id, title_encrypted, description_encrypted, content_encrypted,
               encryption_iv, encryption_tag, status, created_at, updated_at
        FROM ideas
        WHERE owner_id = %s AND team_id IS NULL AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (user_id,)
    )

    for row in cursor.fetchall():
        ideas.append({
            "id": row[0],
            "title_encrypted": row[1],
            "description_encrypted": row[2],
            "content_encrypted": row[3],
            "encryption_iv": row[4],
            "encryption_tag": row[5],
            "status": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "updated_at": row[8].isoformat() if row[8] else None
        })

    logger.info(f"Collected user data: {len(files)} files, {len(notes)} notes, {len(ideas)} ideas")

    return files, notes, ideas


def collect_team_data(cursor, team_id: int, encryption_key: bytes) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Collect all team's files, notes, and ideas for backup

    Args:
        cursor: Database cursor
        team_id: Team ID
        encryption_key: Team's encryption key

    Returns:
        Tuple of (files, notes, ideas) lists
    """
    files = []
    notes = []
    ideas = []

    # Collect team files
    cursor.execute(
        """
        SELECT id, filename_encrypted, file_path, file_size, mime_type_encrypted,
               encryption_iv, encryption_tag, created_at, updated_at, folder_id, owner_id
        FROM drive_files
        WHERE team_id = %s AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (team_id,)
    )

    for row in cursor.fetchall():
        files.append({
            "id": row[0],
            "filename_encrypted": row[1],
            "file_path": row[2],
            "file_size": row[3],
            "mime_type_encrypted": row[4],
            "encryption_iv": row[5],
            "encryption_tag": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "updated_at": row[8].isoformat() if row[8] else None,
            "folder_id": row[9],
            "owner_id": row[10]
        })

    # Collect team notes
    cursor.execute(
        """
        SELECT id, title_encrypted, content_encrypted, encryption_iv, encryption_tag,
               created_at, updated_at, folder_id, is_pinned, owner_id
        FROM notes
        WHERE team_id = %s AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (team_id,)
    )

    for row in cursor.fetchall():
        notes.append({
            "id": row[0],
            "title_encrypted": row[1],
            "content_encrypted": row[2],
            "encryption_iv": row[3],
            "encryption_tag": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
            "updated_at": row[6].isoformat() if row[6] else None,
            "folder_id": row[7],
            "is_pinned": row[8],
            "owner_id": row[9]
        })

    # Collect team ideas
    cursor.execute(
        """
        SELECT id, title_encrypted, description_encrypted, content_encrypted,
               encryption_iv, encryption_tag, status, created_at, updated_at, owner_id
        FROM ideas
        WHERE team_id = %s AND is_deleted = FALSE
        ORDER BY created_at
        """,
        (team_id,)
    )

    for row in cursor.fetchall():
        ideas.append({
            "id": row[0],
            "title_encrypted": row[1],
            "description_encrypted": row[2],
            "content_encrypted": row[3],
            "encryption_iv": row[4],
            "encryption_tag": row[5],
            "status": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "updated_at": row[8].isoformat() if row[8] else None,
            "owner_id": row[9]
        })

    logger.info(f"Collected team data: {len(files)} files, {len(notes)} notes, {len(ideas)} ideas")

    return files, notes, ideas


def calculate_backup_expiry(retention_days: int = 30) -> datetime:
    """
    Calculate backup expiration date

    Args:
        retention_days: Number of days to retain backup

    Returns:
        Expiration datetime
    """
    return datetime.now() + timedelta(days=retention_days)


def cleanup_expired_backups(cursor) -> int:
    """
    Delete expired backups from database and filesystem

    Args:
        cursor: Database cursor

    Returns:
        Number of backups deleted
    """
    # Get expired backups
    cursor.execute(
        """
        SELECT id, backup_path
        FROM drive_backups
        WHERE expires_at < NOW() AND status = 'completed'
        """
    )

    expired = cursor.fetchall()
    deleted_count = 0

    for backup_id, backup_path in expired:
        try:
            # Delete file from disk
            if os.path.exists(backup_path):
                os.remove(backup_path)
                logger.info(f"Deleted expired backup file: {backup_path}")

            # Mark as deleted in database
            cursor.execute(
                """
                UPDATE drive_backups
                SET is_deleted = TRUE, status = 'expired'
                WHERE id = %s
                """,
                (backup_id,)
            )

            deleted_count += 1

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")

    logger.info(f"Cleaned up {deleted_count} expired backups")

    return deleted_count
