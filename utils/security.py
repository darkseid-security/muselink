"""
utils/security.py
Security utility functions for password hashing, token generation, etc.
"""

import secrets
from datetime import datetime
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError, HashingError
import logging

logger = logging.getLogger(__name__)

# Initialize Argon2 password hasher with secure parameters
ph = PasswordHasher(
    time_cost=3,        # Number of iterations (increased for security)
    memory_cost=65536,  # Memory usage in KiB (64 MB)
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of the hash in bytes
    salt_len=16         # Length of random salt in bytes
)

def hash_password(password: str) -> str:
    """
    Hash password using Argon2id algorithm
    
    Argon2id combines:
    - Memory hardness (resistant to GPU attacks)
    - Data-dependent memory access (resistant to side-channel attacks)
    - Optimal for password hashing
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
        
    Raises:
        ValueError: If hashing fails
    """
    try:
        return ph.hash(password)
    except HashingError as e:
        logger.error(f"Password hashing failed: {e}")
        raise ValueError("Password hashing failed")

def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify password against Argon2id hash
    
    Args:
        password: Plain text password to verify
        password_hash: Stored hash to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        ph.verify(password_hash, password)
        
        # Check if rehash is needed (parameters changed)
        if ph.check_needs_rehash(password_hash):
            logger.info("Password hash needs rehashing with new parameters")
            # In production, trigger a password hash update
        
        return True
    except (VerifyMismatchError, InvalidHash, VerificationError):
        return False
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def generate_session_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token
    
    Args:
        length: Number of random bytes (will be base64 encoded)
        
    Returns:
        URL-safe base64 encoded token
    """
    return secrets.token_urlsafe(length)

def hash_token(token: str) -> str:
    """
    Hash token using Argon2id for secure storage

    Args:
        token: Token to hash

    Returns:
        Argon2id hash string
    """
    try:
        return ph.hash(token)
    except HashingError as e:
        logger.error(f"Token hashing failed: {e}")
        raise ValueError("Token hashing failed")

def verify_token_hash(token: str, token_hash: str) -> bool:
    """
    Verify token against Argon2id hash

    Args:
        token: Plain token to verify
        token_hash: Stored Argon2id hash

    Returns:
        True if token matches, False otherwise
    """
    try:
        ph.verify(token_hash, token)
        return True
    except (VerifyMismatchError, InvalidHash, VerificationError):
        return False
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return False

def verify_session_token(cursor, token: str) -> Optional[int]:
    """
    Verify session token and return user_id if valid
    
    Args:
        cursor: Database cursor
        token: Session token to verify
        
    Returns:
        user_id if valid, None otherwise
    """
    try:
        cursor.execute(
            """
            SELECT user_id, expires_at, is_active
            FROM user_sessions
            WHERE session_token = %s
            """,
            (token,)
        )
        
        result = cursor.fetchone()
        
        if not result:
            return None
        
        user_id, expires_at, is_active = result
        
        # Check if session is active and not expired
        if not is_active:
            return None
        
        if datetime.now() > expires_at:
            # Invalidate expired session
            cursor.execute(
                """
                UPDATE user_sessions
                SET is_active = FALSE
                WHERE session_token = %s
                """,
                (token,)
            )
            return None
        
        # Update last activity
        cursor.execute(
            """
            UPDATE user_sessions
            SET last_activity = NOW()
            WHERE session_token = %s
            """,
            (token,)
        )
        
        return user_id
        
    except Exception as e:
        logger.error(f"Session verification error: {e}")
        return None

def generate_csrf_token() -> str:
    """
    Generate CSRF token
    
    Returns:
        URL-safe random token
    """
    return secrets.token_urlsafe(32)

def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
    """
    return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input by removing potentially dangerous characters
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Truncate to max length
    text = text[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text

def generate_backup_codes(count: int = 10) -> list:
    """
    Generate MFA backup codes
    
    Args:
        count: Number of backup codes to generate
        
    Returns:
        List of backup codes
    """
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        codes.append(f"{code[:4]}-{code[4:]}")
    
    return codes

def hash_backup_code(code: str) -> str:
    """
    Hash backup code for secure storage using Argon2id

    Args:
        code: Backup code to hash

    Returns:
        Argon2id hashed code
    """
    try:
        return ph.hash(code)
    except HashingError as e:
        logger.error(f"Backup code hashing failed: {e}")
        raise ValueError("Backup code hashing failed")

def validate_email_format(email: str) -> bool:
    """
    Basic email format validation
    
    Args:
        email: Email address to validate
        
    Returns:
        True if format is valid, False otherwise
    """
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def check_password_strength(password: str) -> dict:
    """
    Check password strength and return detailed analysis
    
    Args:
        password: Password to check
        
    Returns:
        Dictionary with strength analysis
    """
    analysis = {
        'length': len(password),
        'has_uppercase': any(c.isupper() for c in password),
        'has_lowercase': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password),
        'is_strong': False
    }
    
    # Determine if password is strong
    analysis['is_strong'] = (
        analysis['length'] >= 12 and
        analysis['has_uppercase'] and
        analysis['has_lowercase'] and
        analysis['has_digit'] and
        analysis['has_special']
    )
    
    return analysis