"""
utils/captcha.py
CAPTCHA generation utility with in-memory image creation
"""

import io
import base64
import random
import string
import secrets
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from typing import Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
import logging

logger = logging.getLogger(__name__)

# Configurable CAPTCHA settings
CAPTCHA_LENGTH = 6
CAPTCHA_WIDTH = 200
CAPTCHA_HEIGHT = 80
CAPTCHA_FONT_SIZE = 36
CAPTCHA_EXPIRY_MINUTES = 5

# Initialize Argon2 hasher (same parameters as security.py)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

def generate_captcha_text(length: int = CAPTCHA_LENGTH) -> str:
    """
    Generate random CAPTCHA text

    Args:
        length: Length of CAPTCHA text

    Returns:
        Random alphanumeric string (excluding confusing characters)
    """
    # Exclude confusing characters: 0, O, 1, I, l
    chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
    return ''.join(random.choice(chars) for _ in range(length))

def hash_captcha_text(text: str, token: str) -> str:
    """
    Hash CAPTCHA text with token for secure storage using Argon2id

    Args:
        text: CAPTCHA text to hash
        token: Session token to salt the hash

    Returns:
        Argon2id hash of captcha text + token
    """
    combined = f"{text.upper()}:{token}"
    try:
        return ph.hash(combined)
    except Exception as e:
        logger.error(f"CAPTCHA hash failed: {e}")
        raise

def generate_captcha_image(text: str) -> Image.Image:
    """
    Generate CAPTCHA image with text

    Args:
        text: Text to render in CAPTCHA

    Returns:
        PIL Image object
    """
    # Create image with white background
    image = Image.new('RGB', (CAPTCHA_WIDTH, CAPTCHA_HEIGHT), color='white')
    draw = ImageDraw.Draw(image)

    # Add background noise (lines)
    for _ in range(5):
        x1 = random.randint(0, CAPTCHA_WIDTH)
        y1 = random.randint(0, CAPTCHA_HEIGHT)
        x2 = random.randint(0, CAPTCHA_WIDTH)
        y2 = random.randint(0, CAPTCHA_HEIGHT)
        draw.line([(x1, y1), (x2, y2)], fill='lightgray', width=1)

    # Add dots
    for _ in range(100):
        x = random.randint(0, CAPTCHA_WIDTH)
        y = random.randint(0, CAPTCHA_HEIGHT)
        draw.point((x, y), fill='gray')

    # Try to load a font, fall back to default if not available
    try:
        # Try to use a system font
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", CAPTCHA_FONT_SIZE)
    except:
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", CAPTCHA_FONT_SIZE)
        except:
            # Fall back to default font
            font = ImageFont.load_default()

    # Calculate text position to center it
    # Get bounding box for better positioning
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
    except:
        # Fallback for older PIL versions
        text_width, text_height = draw.textsize(text, font=font)

    # Draw each character with random offset
    x_start = (CAPTCHA_WIDTH - text_width) // 2
    y_start = (CAPTCHA_HEIGHT - text_height) // 2

    for i, char in enumerate(text):
        # Random offset for each character
        x_offset = random.randint(-3, 3)
        y_offset = random.randint(-5, 5)

        # Random color (dark colors)
        color = (
            random.randint(0, 100),
            random.randint(0, 100),
            random.randint(0, 100)
        )

        char_x = x_start + (i * (text_width // len(text))) + x_offset
        char_y = y_start + y_offset

        draw.text((char_x, char_y), char, font=font, fill=color)

    # Apply slight blur
    image = image.filter(ImageFilter.SMOOTH)

    return image

def create_captcha() -> Tuple[str, str, str]:
    """
    Create a complete CAPTCHA challenge

    Returns:
        Tuple of (captcha_token, captcha_hash, base64_image)
        - captcha_token: Unique token for this CAPTCHA
        - captcha_hash: Hash of the text for verification
        - base64_image: Base64-encoded PNG image
    """
    try:
        # Generate CAPTCHA text
        text = generate_captcha_text()

        # Generate unique token for this CAPTCHA
        captcha_token = secrets.token_urlsafe(32)

        # Hash the text with token
        captcha_hash = hash_captcha_text(text, captcha_token)

        # Generate image
        image = generate_captcha_image(text)

        # Convert to base64
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        logger.info(f"CAPTCHA created with token: {captcha_token[:8]}...")

        return captcha_token, captcha_hash, img_base64

    except Exception as e:
        logger.error(f"CAPTCHA generation failed: {e}")
        raise

def verify_captcha(user_input: str, captcha_hash: str, captcha_token: str) -> bool:
    """
    Verify user's CAPTCHA input using Argon2id verification

    Args:
        user_input: User's CAPTCHA input
        captcha_hash: Stored Argon2id hash from CAPTCHA creation
        captcha_token: Token associated with this CAPTCHA

    Returns:
        True if CAPTCHA is valid, False otherwise
    """
    try:
        # Normalize input (uppercase, strip whitespace)
        user_input = user_input.upper().strip()

        # Combine input with token (same as hashing)
        combined = f"{user_input}:{captcha_token}"

        # Verify with Argon2id
        ph.verify(captcha_hash, combined)
        return True

    except (VerifyMismatchError, InvalidHash, VerificationError):
        return False
    except Exception as e:
        logger.error(f"CAPTCHA verification error: {e}")
        return False

def generate_audio_captcha_placeholder() -> str:
    """
    Placeholder for audio CAPTCHA generation (accessibility)
    This would require additional dependencies like pydub/gTTS

    Returns:
        Message indicating audio CAPTCHA not implemented
    """
    return "Audio CAPTCHA not yet implemented. Please use visual CAPTCHA or contact support."
