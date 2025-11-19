"""
MFA Cryptography Utilities
Double encryption for TOTP secrets using MASTER_ENCRYPTION_KEY
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import pyotp
import qrcode
from io import BytesIO
import secrets
import logging

logger = logging.getLogger(__name__)

def get_master_key() -> bytes:
    """
    Get the master encryption key from environment

    Returns:
        32-byte master key

    Raises:
        ValueError: If master key is not configured
    """
    master_key_b64 = os.getenv('MASTER_ENCRYPTION_KEY')

    if not master_key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY not configured in .env")

    try:
        master_key = base64.urlsafe_b64decode(master_key_b64)

        if len(master_key) != 32:
            raise ValueError("MASTER_ENCRYPTION_KEY must be 32 bytes")

        return master_key

    except Exception as e:
        logger.error(f"Failed to load MASTER_ENCRYPTION_KEY: {e}")
        raise ValueError("Invalid MASTER_ENCRYPTION_KEY format")


def generate_totp_secret() -> str:
    """
    Generate a cryptographically secure TOTP secret

    Returns:
        Base32-encoded secret (32 characters)
    """
    # Generate 20 random bytes (160 bits)
    random_bytes = secrets.token_bytes(20)

    # Encode as base32 (standard for TOTP)
    secret = base64.b32encode(random_bytes).decode('utf-8')

    logger.info("Generated new TOTP secret")

    return secret


def double_encrypt_totp_secret(totp_secret: str) -> tuple:
    """
    Double encrypt TOTP secret using AES-256-GCM

    Layer 1: Encrypt secret with random key
    Layer 2: Encrypt layer 1 key with MASTER_ENCRYPTION_KEY

    Args:
        totp_secret: The TOTP secret to encrypt (base32)

    Returns:
        Tuple of (encrypted_secret, encrypted_key, iv1, tag1, iv2, tag2)

    Security:
    - Uses AES-256-GCM for authenticated encryption
    - Generates unique IV for each encryption
    - Provides integrity protection via authentication tags
    - Master key never exposed
    """
    try:
        # Get master key
        master_key = get_master_key()

        # Layer 1: Generate random encryption key for secret
        layer1_key = secrets.token_bytes(32)  # 256-bit key

        # Encrypt TOTP secret with layer 1 key
        aesgcm1 = AESGCM(layer1_key)
        iv1 = secrets.token_bytes(12)  # 96-bit IV for GCM
        secret_bytes = totp_secret.encode('utf-8')
        encrypted_secret = aesgcm1.encrypt(iv1, secret_bytes, None)

        # Extract ciphertext and tag
        ciphertext1 = encrypted_secret[:-16]
        tag1 = encrypted_secret[-16:]

        # Layer 2: Encrypt layer 1 key with master key
        aesgcm2 = AESGCM(master_key)
        iv2 = secrets.token_bytes(12)  # New IV for layer 2
        encrypted_key = aesgcm2.encrypt(iv2, layer1_key, None)

        # Extract ciphertext and tag
        ciphertext2 = encrypted_key[:-16]
        tag2 = encrypted_key[-16:]

        logger.info("TOTP secret double-encrypted successfully")

        return (
            base64.b64encode(ciphertext1).decode('utf-8'),  # encrypted_secret
            base64.b64encode(ciphertext2).decode('utf-8'),  # encrypted_key
            base64.b64encode(iv1).decode('utf-8'),         # iv1
            base64.b64encode(tag1).decode('utf-8'),        # tag1
            base64.b64encode(iv2).decode('utf-8'),         # iv2
            base64.b64encode(tag2).decode('utf-8')         # tag2
        )

    except Exception as e:
        logger.error(f"Failed to double encrypt TOTP secret: {e}")
        raise


def double_decrypt_totp_secret(
    encrypted_secret: str,
    encrypted_key: str,
    iv1: str,
    tag1: str,
    iv2: str,
    tag2: str
) -> str:
    """
    Double decrypt TOTP secret

    Layer 1: Decrypt layer 1 key using MASTER_ENCRYPTION_KEY
    Layer 2: Decrypt secret using layer 1 key

    Args:
        encrypted_secret: Base64-encoded encrypted secret
        encrypted_key: Base64-encoded encrypted key
        iv1: Base64-encoded IV for layer 1
        tag1: Base64-encoded authentication tag for layer 1
        iv2: Base64-encoded IV for layer 2
        tag2: Base64-encoded authentication tag for layer 2

    Returns:
        Decrypted TOTP secret (base32)

    Raises:
        ValueError: If decryption fails (integrity check failed)
    """
    try:
        # Get master key
        master_key = get_master_key()

        # Decode all base64 values
        ciphertext1 = base64.b64decode(encrypted_secret)
        ciphertext2 = base64.b64decode(encrypted_key)
        iv1_bytes = base64.b64decode(iv1)
        tag1_bytes = base64.b64decode(tag1)
        iv2_bytes = base64.b64decode(iv2)
        tag2_bytes = base64.b64decode(tag2)

        # Layer 2: Decrypt layer 1 key using master key
        aesgcm2 = AESGCM(master_key)
        encrypted_key_full = ciphertext2 + tag2_bytes
        layer1_key = aesgcm2.decrypt(iv2_bytes, encrypted_key_full, None)

        # Layer 1: Decrypt TOTP secret using layer 1 key
        aesgcm1 = AESGCM(layer1_key)
        encrypted_secret_full = ciphertext1 + tag1_bytes
        secret_bytes = aesgcm1.decrypt(iv1_bytes, encrypted_secret_full, None)

        totp_secret = secret_bytes.decode('utf-8')

        logger.info("TOTP secret double-decrypted successfully")

        return totp_secret

    except Exception as e:
        logger.error(f"Failed to double decrypt TOTP secret: {e}")
        raise ValueError("Decryption failed - data may be corrupted or tampered with")


def verify_totp_code(totp_secret: str, code: str) -> bool:
    """
    Verify TOTP code against secret

    Args:
        totp_secret: The TOTP secret (base32)
        code: The 6-digit code to verify

    Returns:
        True if code is valid, False otherwise

    Security:
    - Uses time-based one-time password algorithm (RFC 6238)
    - Accepts codes within ±1 time window (30 seconds each)
    - Prevents replay attacks through time-based expiration
    """
    try:
        # Validate code format
        from middleware.mfa_validation import validate_mfa_code_format

        if not validate_mfa_code_format(code):
            logger.warning(f"Invalid MFA code format: {code}")
            return False

        # Create TOTP instance
        totp = pyotp.TOTP(totp_secret)

        # Verify code (with ±1 window for clock skew tolerance)
        is_valid = totp.verify(code, valid_window=1)

        if is_valid:
            logger.info("TOTP code verified successfully")
        else:
            logger.warning("TOTP code verification failed")

        return is_valid

    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False


def generate_qr_code(totp_secret: str, username: str, issuer: str = "Genesis") -> str:
    """
    Generate QR code for TOTP setup in authenticator apps

    Args:
        totp_secret: The TOTP secret (base32)
        username: User's username or email
        issuer: Application name (default: "Genesis")

    Returns:
        Base64-encoded PNG image of QR code

    Format:
        otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}
    """
    try:
        # Create TOTP URI
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=username, issuer_name=issuer)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')

        logger.info(f"Generated QR code for user: {username}")

        return img_str

    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        raise


def generate_backup_codes(count: int = 10) -> list:
    """
    Generate backup codes for MFA recovery

    Args:
        count: Number of backup codes to generate (default: 10)

    Returns:
        List of backup codes (8 characters each)

    Security:
    - Cryptographically secure random generation
    - Each code is 8 alphanumeric characters
    - Used for account recovery when TOTP device is unavailable
    """
    backup_codes = []

    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_urlsafe(6)[:8].upper()
        backup_codes.append(code)

    logger.info(f"Generated {count} backup codes")

    return backup_codes


def hash_backup_code(code: str) -> str:
    """
    Hash backup code using Argon2id

    Args:
        code: The backup code to hash

    Returns:
        Hashed backup code

    Security:
    - Uses Argon2id (same as passwords)
    - Prevents backup code database leakage
    """
    from utils.security import hash_password

    return hash_password(code)


def verify_backup_code(code: str, hashed_code: str) -> bool:
    """
    Verify backup code against hash

    Args:
        code: The backup code to verify
        hashed_code: The stored hash

    Returns:
        True if code matches, False otherwise
    """
    from utils.security import verify_password

    return verify_password(code, hashed_code)
