"""
utils/encryption.py
End-to-End Encryption Module using AES-256-GCM

This module provides:
- AES-256-GCM encryption/decryption for messages
- User encryption key management (encrypted with master key)
- Secure key derivation and storage
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


def get_master_key() -> bytes:
    """
    Get the master encryption key from environment
    This key is used to encrypt/decrypt user encryption keys

    Returns:
        32-byte master key

    Raises:
        ValueError: If MASTER_ENCRYPTION_KEY not set or invalid
    """
    master_key_b64 = os.getenv('MASTER_ENCRYPTION_KEY')

    if not master_key_b64:
        raise ValueError(
            "MASTER_ENCRYPTION_KEY not set in environment. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )

    try:
        master_key = base64.urlsafe_b64decode(master_key_b64)
        if len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes")
        return master_key
    except Exception as e:
        raise ValueError(f"Invalid MASTER_ENCRYPTION_KEY: {e}")


def generate_user_encryption_key() -> bytes:
    """
    Generate a new random 256-bit encryption key for a user

    Returns:
        32-byte random key
    """
    return secrets.token_bytes(32)


def encrypt_user_key(user_key: bytes) -> str:
    """
    Encrypt a user's encryption key with the master key
    Uses AES-256-GCM for authenticated encryption

    Args:
        user_key: User's 32-byte encryption key

    Returns:
        Base64-encoded string: nonce + ciphertext + tag

    Format: base64(nonce[12] + ciphertext[32] + tag[16])
    """
    try:
        master_key = get_master_key()
        aesgcm = AESGCM(master_key)

        # Generate random 96-bit nonce (12 bytes)
        nonce = secrets.token_bytes(12)

        # Encrypt the user key (produces ciphertext + 16-byte auth tag)
        ciphertext = aesgcm.encrypt(nonce, user_key, None)

        # Combine: nonce + ciphertext+tag
        encrypted = nonce + ciphertext

        # Encode to base64 for storage
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    except Exception as e:
        logger.error(f"Failed to encrypt user key: {e}")
        raise


def decrypt_user_key(encrypted_key: str) -> bytes:
    """
    Decrypt a user's encryption key using the master key

    Args:
        encrypted_key: Base64-encoded encrypted key

    Returns:
        32-byte decrypted user key

    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, etc.)
    """
    try:
        master_key = get_master_key()
        aesgcm = AESGCM(master_key)

        # Decode from base64
        encrypted = base64.urlsafe_b64decode(encrypted_key)

        # Split: nonce (12 bytes) + ciphertext+tag
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        # Decrypt and verify
        user_key = aesgcm.decrypt(nonce, ciphertext, None)

        if len(user_key) != 32:
            raise ValueError("Decrypted key has invalid length")

        return user_key

    except Exception as e:
        logger.error(f"Failed to decrypt user key: {e}")
        raise ValueError("Failed to decrypt user encryption key")


def encrypt_message(plaintext: str, user_key: bytes) -> str:
    """
    Encrypt a message using AES-256-GCM with user's encryption key

    Args:
        plaintext: Message content to encrypt
        user_key: User's 32-byte encryption key

    Returns:
        Base64-encoded encrypted message: nonce + ciphertext + tag

    Format: base64(nonce[12] + ciphertext[variable] + tag[16])
    """
    try:
        aesgcm = AESGCM(user_key)

        # Generate random nonce
        nonce = secrets.token_bytes(12)

        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')

        # Encrypt (produces ciphertext + auth tag)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

        # Combine nonce + ciphertext+tag
        encrypted = nonce + ciphertext

        # Encode to base64
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    except Exception as e:
        logger.error(f"Failed to encrypt message: {e}")
        raise


def decrypt_message(encrypted_text: str, user_key: bytes) -> str:
    """
    Decrypt a message using AES-256-GCM with user's encryption key

    Args:
        encrypted_text: Base64-encoded encrypted message
        user_key: User's 32-byte encryption key

    Returns:
        Decrypted plaintext message

    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, tampered)
    """
    try:
        aesgcm = AESGCM(user_key)

        # Decode from base64
        encrypted = base64.urlsafe_b64decode(encrypted_text)

        # Split nonce and ciphertext+tag
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        # Decrypt and verify authentication tag
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        # Convert back to string
        return plaintext_bytes.decode('utf-8')

    except Exception as e:
        logger.error(f"Failed to decrypt message: {e}")
        raise ValueError("Failed to decrypt message - invalid key or corrupted data")


def encrypt_message_for_users(plaintext: str, sender_key: bytes, receiver_key: bytes) -> Tuple[str, str]:
    """
    Encrypt a message for both sender and receiver
    Each user gets a copy encrypted with their own key

    Args:
        plaintext: Message content
        sender_key: Sender's encryption key
        receiver_key: Receiver's encryption key

    Returns:
        Tuple of (sender_encrypted, receiver_encrypted)
    """
    sender_encrypted = encrypt_message(plaintext, sender_key)
    receiver_encrypted = encrypt_message(plaintext, receiver_key)
    return sender_encrypted, receiver_encrypted


def verify_message_integrity(encrypted_text: str, user_key: bytes) -> bool:
    """
    Verify message hasn't been tampered with (checks auth tag)

    Args:
        encrypted_text: Base64-encoded encrypted message
        user_key: User's encryption key

    Returns:
        True if message is authentic, False otherwise
    """
    try:
        decrypt_message(encrypted_text, user_key)
        return True
    except:
        return False


def generate_master_key_command() -> str:
    """
    Generate a new master encryption key
    This should be run ONCE during initial setup

    Returns:
        Command to generate and display a new master key
    """
    new_key = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(new_key).decode('utf-8')

    return f"""
# Add this to your .env file:
MASTER_ENCRYPTION_KEY={encoded}

# Keep this key SECRET and SECURE!
# - Never commit to version control
# - Back up securely (encrypted backup)
# - If lost, all encrypted messages are UNRECOVERABLE
# - Rotating this key requires re-encrypting all user keys
"""


def rotate_user_encryption_key(old_encrypted_key: str) -> Tuple[bytes, str]:
    """
    Rotate a user's encryption key
    Used if key compromise is suspected

    Args:
        old_encrypted_key: Current encrypted user key

    Returns:
        Tuple of (new_user_key, new_encrypted_key)

    Note: All messages encrypted with old key need to be re-encrypted
    """
    # Generate new key
    new_user_key = generate_user_encryption_key()

    # Encrypt with master key
    new_encrypted_key = encrypt_user_key(new_user_key)

    return new_user_key, new_encrypted_key


# Key derivation for password-based encryption (optional future use)
def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a 32-byte key from a password using PBKDF2
    Can be used for additional user-specific encryption

    Args:
        password: User's password
        salt: Random salt (at least 16 bytes)
        iterations: PBKDF2 iterations (higher = more secure but slower)

    Returns:
        32-byte derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


# Utility functions for testing
def test_encryption_system():
    """
    Test the encryption system end-to-end
    Returns True if all tests pass
    """
    try:
        print("Testing encryption system...")

        # Generate user key
        print("1. Generating user encryption key...")
        user_key = generate_user_encryption_key()
        assert len(user_key) == 32
        print("   ✓ User key generated (32 bytes)")

        # Encrypt user key with master key
        print("2. Encrypting user key with master key...")
        encrypted_user_key = encrypt_user_key(user_key)
        print(f"   ✓ User key encrypted (length: {len(encrypted_user_key)})")

        # Decrypt user key
        print("3. Decrypting user key...")
        decrypted_user_key = decrypt_user_key(encrypted_user_key)
        assert decrypted_user_key == user_key
        print("   ✓ User key decrypted successfully")

        # Encrypt message
        print("4. Encrypting test message...")
        message = "This is a secret message! 🔒"
        encrypted_message = encrypt_message(message, user_key)
        print(f"   ✓ Message encrypted (length: {len(encrypted_message)})")

        # Decrypt message
        print("5. Decrypting message...")
        decrypted_message = decrypt_message(encrypted_message, user_key)
        assert decrypted_message == message
        print(f"   ✓ Message decrypted: '{decrypted_message}'")

        # Test integrity verification
        print("6. Testing integrity verification...")
        is_valid = verify_message_integrity(encrypted_message, user_key)
        assert is_valid == True
        print("   ✓ Message integrity verified")

        # Test tampered message detection
        print("7. Testing tampered message detection...")
        tampered = encrypted_message[:-10] + "XXXXXXXXXX"
        is_valid = verify_message_integrity(tampered, user_key)
        assert is_valid == False
        print("   ✓ Tampered message detected")

        print("\n✅ All encryption tests passed!")
        return True

    except Exception as e:
        print(f"\n❌ Encryption test failed: {e}")
        return False


if __name__ == "__main__":
    # If run directly, generate a new master key
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "generate-key":
        print(generate_master_key_command())
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        test_encryption_system()
    else:
        print("Usage:")
        print("  python encryption.py generate-key  # Generate new master key")
        print("  python encryption.py test          # Test encryption system")
