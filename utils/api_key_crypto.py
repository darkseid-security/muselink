"""
API Key Cryptography Utilities
Double encryption for user API keys (GEMINI_API_KEY and AIMLAPI_KEY)
Uses same security pattern as MFA TOTP secrets
"""

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import logging
from typing import Tuple, Optional
from database.connection import get_db_connection, return_db_connection
from utils.encryption import decrypt_user_key

logger = logging.getLogger(__name__)


def double_encrypt_api_key(api_key: str, user_encryption_key: bytes) -> Tuple[str, str, str, str, str, str]:
    """
    Double encrypt API key using AES-256-GCM

    Layer 1: Encrypt API key with random key
    Layer 2: Encrypt layer 1 key with user's encryption key

    Args:
        api_key: The API key to encrypt (plaintext)
        user_encryption_key: User's 32-byte encryption key (already decrypted)

    Returns:
        Tuple of (encrypted_key, encrypted_key_key, iv1, tag1, iv2, tag2)

    Security:
    - Uses AES-256-GCM for authenticated encryption
    - Generates unique IV for each encryption
    - Provides integrity protection via authentication tags
    - User's encryption key derived from master key + user ID
    """
    try:
        # Layer 1: Generate random encryption key for API key
        layer1_key = secrets.token_bytes(32)  # 256-bit key

        # Encrypt API key with layer 1 key
        aesgcm1 = AESGCM(layer1_key)
        iv1 = secrets.token_bytes(12)  # 96-bit IV for GCM
        key_bytes = api_key.encode('utf-8')
        encrypted_api_key = aesgcm1.encrypt(iv1, key_bytes, None)

        # Extract ciphertext and tag
        ciphertext1 = encrypted_api_key[:-16]
        tag1 = encrypted_api_key[-16:]

        # Layer 2: Encrypt layer 1 key with user's encryption key
        aesgcm2 = AESGCM(user_encryption_key)
        iv2 = secrets.token_bytes(12)  # New IV for layer 2
        encrypted_key_key = aesgcm2.encrypt(iv2, layer1_key, None)

        # Extract ciphertext and tag
        ciphertext2 = encrypted_key_key[:-16]
        tag2 = encrypted_key_key[-16:]

        logger.info("API key double-encrypted successfully")

        return (
            base64.b64encode(ciphertext1).decode('utf-8'),  # encrypted_key
            base64.b64encode(ciphertext2).decode('utf-8'),  # encrypted_key_key
            base64.b64encode(iv1).decode('utf-8'),         # iv1
            base64.b64encode(tag1).decode('utf-8'),        # tag1
            base64.b64encode(iv2).decode('utf-8'),         # iv2
            base64.b64encode(tag2).decode('utf-8')         # tag2
        )

    except Exception as e:
        logger.error(f"Failed to double encrypt API key: {e}")
        raise


def double_decrypt_api_key(
    encrypted_key: str,
    encrypted_key_key: str,
    iv1: str,
    tag1: str,
    iv2: str,
    tag2: str,
    user_encryption_key: bytes
) -> str:
    """
    Double decrypt API key

    Layer 1: Decrypt layer 1 key using user's encryption key
    Layer 2: Decrypt API key using layer 1 key

    Args:
        encrypted_key: Base64-encoded encrypted API key
        encrypted_key_key: Base64-encoded encrypted layer 1 key
        iv1: Base64-encoded IV for layer 1
        tag1: Base64-encoded authentication tag for layer 1
        iv2: Base64-encoded IV for layer 2
        tag2: Base64-encoded authentication tag for layer 2
        user_encryption_key: User's 32-byte encryption key (already decrypted)

    Returns:
        Decrypted API key (plaintext)

    Raises:
        ValueError: If decryption fails (integrity check failed)
    """
    try:
        # Decode all base64 values
        ciphertext1 = base64.b64decode(encrypted_key)
        ciphertext2 = base64.b64decode(encrypted_key_key)
        iv1_bytes = base64.b64decode(iv1)
        tag1_bytes = base64.b64decode(tag1)
        iv2_bytes = base64.b64decode(iv2)
        tag2_bytes = base64.b64decode(tag2)

        # Layer 2: Decrypt layer 1 key using user's encryption key
        aesgcm2 = AESGCM(user_encryption_key)
        encrypted_key_key_full = ciphertext2 + tag2_bytes
        layer1_key = aesgcm2.decrypt(iv2_bytes, encrypted_key_key_full, None)

        # Layer 1: Decrypt API key using layer 1 key
        aesgcm1 = AESGCM(layer1_key)
        encrypted_key_full = ciphertext1 + tag1_bytes
        key_bytes = aesgcm1.decrypt(iv1_bytes, encrypted_key_full, None)

        api_key = key_bytes.decode('utf-8')

        logger.info("API key double-decrypted successfully")

        return api_key

    except Exception as e:
        logger.error(f"Failed to double decrypt API key: {e}")
        raise ValueError("Decryption failed - data may be corrupted or tampered with")


def save_user_api_key(user_id: int, api_key_type: str, api_key: str, user_encrypted_key: str) -> bool:
    """
    Save user's API key to database with double encryption

    Args:
        user_id: User's ID
        api_key_type: Type of API key ('gemini' or 'aimlapi')
        api_key: The API key to save (plaintext)
        user_encrypted_key: User's encrypted encryption key from database

    Returns:
        True if successful, False otherwise

    Security:
    - Decrypts user's encryption key from master key
    - Double-encrypts API key with user's encryption key
    - Stores encrypted values in database
    """
    conn = get_db_connection()
    try:
        # Debug logging
        logger.info(f"Saving API key type: {api_key_type} for user: {user_id}")
        logger.info(f"User encrypted key type: {type(user_encrypted_key)}, value length: {len(user_encrypted_key) if user_encrypted_key else 0}")

        # Decrypt user's encryption key
        from utils.encryption import decrypt_user_key as decrypt_master_user_key
        user_encryption_key = decrypt_master_user_key(user_encrypted_key)
        logger.info(f"Successfully decrypted user encryption key")

        # Double encrypt the API key
        encrypted_key, encrypted_key_key, iv1, tag1, iv2, tag2 = double_encrypt_api_key(
            api_key, user_encryption_key
        )

        cursor = conn.cursor()

        # Insert or update API key
        query = """
            INSERT INTO user_api_keys
                (user_id, api_key_type, encrypted_key, iv1, tag1, encrypted_key_key, iv2, tag2, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            ON CONFLICT (user_id, api_key_type)
            DO UPDATE SET
                encrypted_key = EXCLUDED.encrypted_key,
                iv1 = EXCLUDED.iv1,
                tag1 = EXCLUDED.tag1,
                encrypted_key_key = EXCLUDED.encrypted_key_key,
                iv2 = EXCLUDED.iv2,
                tag2 = EXCLUDED.tag2,
                updated_at = CURRENT_TIMESTAMP,
                is_active = TRUE
        """

        cursor.execute(query, (
            user_id, api_key_type, encrypted_key, iv1, tag1,
            encrypted_key_key, iv2, tag2
        ))

        conn.commit()
        cursor.close()

        logger.info(f"Saved {api_key_type} API key for user {user_id}")
        return True

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to save API key: {e}")
        return False

    finally:
        return_db_connection(conn)


def get_user_api_key(user_id: int, api_key_type: str, user_encrypted_key: str) -> Optional[str]:
    """
    Retrieve and decrypt user's API key from database

    Args:
        user_id: User's ID
        api_key_type: Type of API key ('gemini' or 'aimlapi')
        user_encrypted_key: User's encrypted encryption key from database

    Returns:
        Decrypted API key (plaintext) or None if not found

    Security:
    - Retrieves double-encrypted API key from database
    - Decrypts user's encryption key from master key
    - Double-decrypts API key
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        query = """
            SELECT encrypted_key, encrypted_key_key, iv1, tag1, iv2, tag2
            FROM user_api_keys
            WHERE user_id = %s AND api_key_type = %s AND is_active = TRUE
        """

        cursor.execute(query, (user_id, api_key_type))
        result = cursor.fetchone()
        cursor.close()

        if not result:
            logger.info(f"No {api_key_type} API key found for user {user_id}")
            return None

        encrypted_key, encrypted_key_key, iv1, tag1, iv2, tag2 = result

        # Decrypt user's encryption key
        from utils.encryption import decrypt_user_key as decrypt_master_user_key
        user_encryption_key = decrypt_master_user_key(user_encrypted_key)

        # Double decrypt the API key
        api_key = double_decrypt_api_key(
            encrypted_key, encrypted_key_key, iv1, tag1, iv2, tag2,
            user_encryption_key
        )

        logger.info(f"Retrieved {api_key_type} API key for user {user_id}")
        return api_key

    except Exception as e:
        logger.error(f"Failed to retrieve API key: {e}")
        return None

    finally:
        return_db_connection(conn)


def delete_user_api_key(user_id: int, api_key_type: str) -> bool:
    """
    Delete (deactivate) user's API key from database

    Args:
        user_id: User's ID
        api_key_type: Type of API key ('gemini' or 'aimlapi')

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        query = """
            UPDATE user_api_keys
            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = %s AND api_key_type = %s
        """

        cursor.execute(query, (user_id, api_key_type))
        conn.commit()
        cursor.close()

        logger.info(f"Deleted {api_key_type} API key for user {user_id}")
        return True

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to delete API key: {e}")
        return False

    finally:
        return_db_connection(conn)


def check_user_has_api_keys(user_id: int) -> dict:
    """
    Check which API keys the user has configured

    Args:
        user_id: User's ID

    Returns:
        Dictionary with 'gemini' and 'aimlapi' boolean values
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        query = """
            SELECT api_key_type
            FROM user_api_keys
            WHERE user_id = %s AND is_active = TRUE
        """

        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        cursor.close()

        # Create result dictionary
        api_keys_status = {
            'gemini': False,
            'aimlapi': False
        }

        for (api_key_type,) in results:
            if api_key_type in api_keys_status:
                api_keys_status[api_key_type] = True

        return api_keys_status

    except Exception as e:
        logger.error(f"Failed to check API keys: {e}")
        return {'gemini': False, 'aimlapi': False}

    finally:
        return_db_connection(conn)
