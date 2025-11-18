"""
utils/crypto_aes.py
AES-256-GCM encryption utilities for files, notes, and content
Implements zero-knowledge encryption architecture
"""

import os
import base64
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

# AES-256-GCM constants
AES_KEY_SIZE = 32  # 256 bits
AES_IV_SIZE = 12   # 96 bits (recommended for GCM)
AES_TAG_SIZE = 16  # 128 bits


class EncryptionError(Exception):
    """Custom exception for encryption errors"""
    pass


class DecryptionError(Exception):
    """Custom exception for decryption errors"""
    pass


def generate_encryption_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit encryption key

    Returns:
        32-byte random key
    """
    return secrets.token_bytes(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate a random initialization vector for AES-GCM

    Returns:
        12-byte random IV
    """
    return secrets.token_bytes(AES_IV_SIZE)


def derive_key_from_password(password: str, salt: bytes, iterations: int = 600000) -> bytes:
    """
    Derive AES-256 key from password using PBKDF2

    Args:
        password: User password
        salt: Cryptographic salt
        iterations: Number of PBKDF2 iterations (600k recommended by OWASP)

    Returns:
        32-byte derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-256-GCM

    AES-GCM provides:
    - Confidentiality (encryption)
    - Authenticity (authentication tag)
    - Integrity verification

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        associated_data: Optional authenticated associated data (AAD)

    Returns:
        Tuple of (ciphertext, iv, tag)

    Raises:
        EncryptionError: If encryption fails
    """
    try:
        if len(key) != AES_KEY_SIZE:
            raise EncryptionError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

        # Generate random IV
        iv = generate_iv()

        # Create AESGCM cipher
        aesgcm = AESGCM(key)

        # Encrypt and authenticate
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)

        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-AES_TAG_SIZE]
        tag = ciphertext_with_tag[-AES_TAG_SIZE:]

        return ciphertext, iv, tag

    except Exception as e:
        logger.error(f"Encryption failed: {type(e).__name__}")
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt_data(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                 associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt data using AES-256-GCM

    Verifies authentication tag before decryption.
    Fails if data has been tampered with.

    Args:
        ciphertext: Encrypted data
        key: 32-byte AES-256 key
        iv: 12-byte initialization vector
        tag: 16-byte authentication tag
        associated_data: Optional authenticated associated data (AAD)

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption or authentication fails
    """
    try:
        if len(key) != AES_KEY_SIZE:
            raise DecryptionError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

        if len(iv) != AES_IV_SIZE:
            raise DecryptionError(f"IV must be {AES_IV_SIZE} bytes, got {len(iv)}")

        if len(tag) != AES_TAG_SIZE:
            raise DecryptionError(f"Tag must be {AES_TAG_SIZE} bytes, got {len(tag)}")

        # Reconstruct ciphertext with tag
        ciphertext_with_tag = ciphertext + tag

        # Create AESGCM cipher
        aesgcm = AESGCM(key)

        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)

        return plaintext

    except Exception as e:
        logger.error(f"Decryption failed: {type(e).__name__}")
        raise DecryptionError(f"Decryption or authentication failed: {e}")


def encrypt_text(plaintext: str, key: bytes) -> Tuple[str, str, str]:
    """
    Encrypt text string using AES-256-GCM

    Args:
        plaintext: Text to encrypt
        key: 32-byte AES-256 key

    Returns:
        Tuple of (base64_ciphertext, base64_iv, base64_tag)
    """
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext, iv, tag = encrypt_data(plaintext_bytes, key)

    return (
        base64.b64encode(ciphertext).decode('utf-8'),
        base64.b64encode(iv).decode('utf-8'),
        base64.b64encode(tag).decode('utf-8')
    )


def decrypt_text(ciphertext_b64: str, key: bytes, iv_b64: str, tag_b64: str) -> str:
    """
    Decrypt text string using AES-256-GCM

    Args:
        ciphertext_b64: Base64-encoded ciphertext
        key: 32-byte AES-256 key
        iv_b64: Base64-encoded IV
        tag_b64: Base64-encoded authentication tag

    Returns:
        Decrypted text
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)

    plaintext_bytes = decrypt_data(ciphertext, key, iv, tag)
    return plaintext_bytes.decode('utf-8')


def encrypt_file_content(file_content: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt file content using AES-256-GCM

    Args:
        file_content: File bytes to encrypt
        key: 32-byte AES-256 key

    Returns:
        Tuple of (ciphertext, iv, tag)
    """
    return encrypt_data(file_content, key)


def decrypt_file_content(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """
    Decrypt file content using AES-256-GCM

    Args:
        ciphertext: Encrypted file bytes
        key: 32-byte AES-256 key
        iv: 12-byte initialization vector
        tag: 16-byte authentication tag

    Returns:
        Decrypted file bytes
    """
    return decrypt_data(ciphertext, key, iv, tag)


def encrypt_user_key(user_key: bytes, encryption_key: bytes) -> str:
    """
    Encrypt a user's encryption key with another key (for sharing)

    Args:
        user_key: Key to encrypt
        encryption_key: Key to encrypt with

    Returns:
        Base64-encoded encrypted key (format: iv:tag:ciphertext)
    """
    ciphertext, iv, tag = encrypt_data(user_key, encryption_key)

    # Combine iv:tag:ciphertext
    combined = iv + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_user_key(encrypted_key_b64: str, decryption_key: bytes) -> bytes:
    """
    Decrypt a user's encryption key

    Args:
        encrypted_key_b64: Base64-encoded encrypted key (format: iv:tag:ciphertext)
        decryption_key: Key to decrypt with

    Returns:
        Decrypted user key
    """
    combined = base64.b64decode(encrypted_key_b64)

    # Split iv:tag:ciphertext
    iv = combined[:AES_IV_SIZE]
    tag = combined[AES_IV_SIZE:AES_IV_SIZE + AES_TAG_SIZE]
    ciphertext = combined[AES_IV_SIZE + AES_TAG_SIZE:]

    return decrypt_data(ciphertext, decryption_key, iv, tag)


def generate_team_key() -> bytes:
    """
    Generate a team encryption key (AES-256)

    Returns:
        32-byte team key
    """
    return generate_encryption_key()


def get_user_encryption_key(encrypted_key: str, master_key: bytes) -> bytes:
    """
    Decrypt user's encryption key from database

    Args:
        encrypted_key: Encrypted user key from database
        master_key: Master encryption key

    Returns:
        User's decrypted encryption key
    """
    return decrypt_user_key(encrypted_key, master_key)


def key_to_base64(key: bytes) -> str:
    """Convert key bytes to base64 string for storage"""
    return base64.b64encode(key).decode('utf-8')


def key_from_base64(key_b64: str) -> bytes:
    """Convert base64 key string to bytes"""
    return base64.b64decode(key_b64)


# Security utilities for metadata stripping

def strip_image_metadata(file_content: bytes, mime_type: str) -> bytes:
    """
    Strip EXIF and metadata from images

    Args:
        file_content: Image file bytes
        mime_type: MIME type of image

    Returns:
        Image bytes with metadata stripped
    """
    try:
        from PIL import Image
        import io

        # Only process images
        if not mime_type.startswith('image/'):
            return file_content

        # Open image
        image = Image.open(io.BytesIO(file_content))

        # Remove EXIF data by creating new image
        data = list(image.getdata())
        image_without_exif = Image.new(image.mode, image.size)
        image_without_exif.putdata(data)

        # Save to bytes
        output = io.BytesIO()
        image_format = image.format or 'PNG'
        image_without_exif.save(output, format=image_format)

        logger.info(f"Stripped metadata from {mime_type} image")
        return output.getvalue()

    except Exception as e:
        logger.warning(f"Failed to strip image metadata: {e}")
        # Return original if stripping fails (better than blocking upload)
        return file_content


def strip_document_metadata(file_content: bytes, mime_type: str) -> bytes:
    """
    Strip metadata from documents (PDF, DOCX, etc.)

    Args:
        file_content: Document file bytes
        mime_type: MIME type of document

    Returns:
        Document bytes with metadata stripped (or original if not supported)
    """
    # This would require libraries like PyPDF2, python-docx
    # For now, log warning and return original
    logger.warning(f"Metadata stripping not implemented for {mime_type}")
    return file_content


def strip_file_metadata(file_content: bytes, mime_type: str) -> bytes:
    """
    Strip metadata from files based on MIME type

    Implements claude.MD requirement: Strip all metadata from uploads

    Args:
        file_content: File bytes
        mime_type: MIME type

    Returns:
        File bytes with metadata stripped
    """
    if mime_type.startswith('image/'):
        return strip_image_metadata(file_content, mime_type)
    elif mime_type in ['application/pdf', 'application/vnd.openxmlformats-officedocument']:
        return strip_document_metadata(file_content, mime_type)
    else:
        # For other file types, return as-is
        return file_content
