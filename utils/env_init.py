"""
utils/env_init.py
Automatic environment variable initialization
Generates secure random keys if dev placeholders are detected
"""

import os
import secrets
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_FILE = Path(__file__).parent.parent / ".env"

# Dev placeholder patterns to detect
DEV_PLACEHOLDERS = [
    "dev_secret_key",
    "dev_jwt_secret",
    "dev_session_secret",
    "change_in_production",
    "your_secret_key_here",
    "your_jwt_secret_key_here"
]


def generate_secure_key(length: int = 32) -> str:
    """
    Generate a cryptographically secure random key

    Args:
        length: Length of key in bytes (default 32 = 256 bits)

    Returns:
        URL-safe base64 encoded key
    """
    return secrets.token_urlsafe(length)


def is_dev_placeholder(value: str) -> bool:
    """
    Check if an environment variable contains a dev placeholder

    Args:
        value: Environment variable value

    Returns:
        True if it's a placeholder, False otherwise
    """
    if not value:
        return True

    value_lower = value.lower()
    return any(placeholder in value_lower for placeholder in DEV_PLACEHOLDERS)


def update_env_file(updates: dict) -> bool:
    """
    Update .env file with new values

    Args:
        updates: Dictionary of key-value pairs to update

    Returns:
        True if successful, False otherwise
    """
    try:
        if not ENV_FILE.exists():
            logger.warning(f".env file not found at {ENV_FILE}")
            return False

        # Read existing .env file
        with open(ENV_FILE, 'r') as f:
            lines = f.readlines()

        # Update lines
        updated_lines = []
        updated_keys = set()

        for line in lines:
            line_stripped = line.strip()

            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                updated_lines.append(line)
                continue

            # Parse key=value
            if '=' in line_stripped:
                key = line_stripped.split('=')[0].strip()

                if key in updates:
                    updated_lines.append(f"{key}={updates[key]}\n")
                    updated_keys.add(key)
                    logger.info(f"Updated {key} in .env")
                else:
                    updated_lines.append(line)
            else:
                updated_lines.append(line)

        # Write back to .env
        with open(ENV_FILE, 'w') as f:
            f.writelines(updated_lines)

        logger.info(f"Successfully updated {len(updated_keys)} keys in .env")
        return True

    except Exception as e:
        logger.error(f"Failed to update .env file: {e}")
        return False


def initialize_env_secrets() -> dict:
    """
    Initialize environment secrets if dev placeholders are detected

    Checks for dev placeholder values and generates secure keys.
    Updates .env file automatically.

    Returns:
        Dictionary of updated keys
    """
    logger.info("Checking environment variables for dev placeholders...")

    # Keys to check and generate
    secret_keys = {
        "SECRET_KEY": os.getenv("SECRET_KEY"),
        "JWT_SECRET_KEY": os.getenv("JWT_SECRET_KEY"),
        "SESSION_SECRET": os.getenv("SESSION_SECRET"),
        "CSRF_SECRET": os.getenv("CSRF_SECRET"),
    }

    updates = {}
    needs_update = False

    for key, value in secret_keys.items():
        if is_dev_placeholder(value):
            new_key = generate_secure_key(32)
            updates[key] = new_key
            needs_update = True
            logger.warning(f"🔑 {key} contains dev placeholder - generating secure key")

            # Update in current environment
            os.environ[key] = new_key
        else:
            logger.info(f"✅ {key} is already set with a secure value")

    if needs_update:
        logger.info("=" * 60)
        logger.info("🔐 SECURITY: Dev placeholders detected!")
        logger.info("=" * 60)
        logger.info("Generating secure random keys and updating .env file...")

        if update_env_file(updates):
            logger.info("✅ .env file updated successfully")
            logger.info("")
            logger.info("⚠️  IMPORTANT: New keys have been generated!")
            logger.info("   - Existing user sessions will be invalidated")
            logger.info("   - Existing JWT tokens will be invalid")
            logger.info("   - Users will need to re-login")
            logger.info("")
            logger.info("📝 Backup your .env file if you need to preserve sessions")
            logger.info("=" * 60)
        else:
            logger.error("❌ Failed to update .env file - using generated keys in memory only")
            logger.error("   Keys will be lost on application restart!")

        return updates
    else:
        logger.info("✅ All secret keys are properly configured")
        return {}


def validate_required_env_vars() -> bool:
    """
    Validate that all required environment variables are set

    Returns:
        True if all required vars are set, False otherwise
    """
    required_vars = [
        "SECRET_KEY",
        "JWT_SECRET_KEY",
        "SESSION_SECRET",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "MASTER_ENCRYPTION_KEY"
    ]

    missing = []

    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing.append(var)

    if missing:
        logger.error("❌ Missing required environment variables:")
        for var in missing:
            logger.error(f"   - {var}")
        return False

    logger.info("✅ All required environment variables are set")
    return True


def check_master_encryption_key() -> bool:
    """
    Check if MASTER_ENCRYPTION_KEY is properly set

    Returns:
        True if key is valid, False otherwise
    """
    key = os.getenv("MASTER_ENCRYPTION_KEY")

    if not key:
        logger.error("❌ MASTER_ENCRYPTION_KEY is not set!")
        logger.error("   Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
        return False

    if is_dev_placeholder(key):
        logger.error("❌ MASTER_ENCRYPTION_KEY contains a dev placeholder!")
        logger.error("   This key is used to encrypt user encryption keys")
        logger.error("   Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
        return False

    if len(key) < 32:
        logger.warning("⚠️  MASTER_ENCRYPTION_KEY is shorter than recommended (32 chars)")

    logger.info("✅ MASTER_ENCRYPTION_KEY is properly configured")
    return True


def display_security_checklist():
    """
    Display security checklist on startup
    """
    env = os.getenv("ENV", "development")

    if env == "production":
        logger.info("")
        logger.info("=" * 60)
        logger.info("🔒 PRODUCTION MODE SECURITY CHECKLIST")
        logger.info("=" * 60)

        checks = {
            "DEBUG=False": os.getenv("DEBUG", "True").lower() == "false",
            "ENV=production": env == "production",
            "SSL_CERT_FILE set": bool(os.getenv("SSL_CERT_FILE")),
            "SSL_KEY_FILE set": bool(os.getenv("SSL_KEY_FILE")),
            "CORS_ORIGINS configured": not is_dev_placeholder(os.getenv("CORS_ORIGINS", "")),
            "ALLOWED_HOSTS configured": not is_dev_placeholder(os.getenv("ALLOWED_HOSTS", "")),
            "REDIS_URL configured": os.getenv("REDIS_URL", "memory://") != "memory://",
        }

        all_passed = True

        for check, passed in checks.items():
            status = "✅" if passed else "❌"
            logger.info(f"{status} {check}")
            if not passed:
                all_passed = False

        if all_passed:
            logger.info("")
            logger.info("✅ All production security checks passed!")
        else:
            logger.warning("")
            logger.warning("⚠️  Some production security checks failed!")
            logger.warning("   Review your .env configuration")

        logger.info("=" * 60)
        logger.info("")


if __name__ == "__main__":
    """Test the initialization"""
    logging.basicConfig(level=logging.INFO)

    print("\n🔐 Testing Environment Initialization\n")

    # Initialize secrets
    updates = initialize_env_secrets()

    if updates:
        print("\n📋 Generated Keys:")
        for key, value in updates.items():
            print(f"   {key}={value}")

    # Validate
    validate_required_env_vars()
    check_master_encryption_key()
    display_security_checklist()
