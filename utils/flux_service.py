"""
utils/flux_service.py
Flux AI Image Generation Service (via aimlapi.com)
"""

import requests
import logging
import os
from typing import Dict, Optional, Tuple
from datetime import datetime
from utils.input_sanitizer import comprehensive_input_scan, log_malicious_input

logger = logging.getLogger(__name__)


class FluxImageService:
    """Flux AI image generation service via aimlapi.com"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.aimlapi.com/v1"
        self.model = "flux/srpo"  # Flux SRPO model

    def generate_image(
        self,
        prompt: str,
        style: Optional[str] = None,
        aspect_ratio: str = "1:1",
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict:
        """
        Generate an image using Flux AI model

        Args:
            prompt: Image generation prompt
            style: Art style (realistic, digital-art, oil-painting, etc.)
            aspect_ratio: Image aspect ratio (1:1, 16:9, 9:16, 4:3)
            user_id: User ID for audit logging
            ip_address: IP address for security logging

        Returns:
            Dict with success status, image_url, and metadata
        """
        try:
            # Light validation for creative content - only check for script injection
            # SQL keywords like CREATE, DROP, etc. are perfectly valid in creative prompts
            # Only block actual script/XSS patterns that could be dangerous if displayed
            from utils.input_sanitizer import detect_xss, has_control_characters

            # Check for XSS (script injection) - this matters if prompt is displayed in HTML
            xss_pattern = detect_xss(prompt)
            if xss_pattern:
                logger.warning(f"XSS detected in image prompt")
                log_malicious_input(
                    user_id=user_id,
                    input_value=prompt[:500],
                    attack_type='xss',
                    pattern=xss_pattern,
                    ip_address=ip_address,
                    endpoint="/api/v1/images/generate"
                )
                return {
                    "success": False,
                    "error": "Invalid characters detected in prompt"
                }

            # Check for control characters (null bytes, etc.)
            if has_control_characters(prompt):
                logger.warning(f"Control characters detected in image prompt")
                return {
                    "success": False,
                    "error": "Invalid characters detected in prompt"
                }

            # Validate prompt length
            if len(prompt) < 10:
                return {
                    "success": False,
                    "error": "Prompt must be at least 10 characters long"
                }

            if len(prompt) > 2000:
                return {
                    "success": False,
                    "error": "Prompt must be less than 2000 characters"
                }

            # Enhance prompt with style if provided
            enhanced_prompt = prompt
            if style and style != "realistic":
                style_mappings = {
                    "digital-art": "digital art style",
                    "oil-painting": "oil painting style",
                    "watercolor": "watercolor painting style",
                    "anime": "anime art style",
                    "3d-render": "3D rendered, high quality CGI",
                    "minimalist": "minimalist design, clean and simple",
                    "abstract": "abstract art style, creative and expressive"
                }
                style_suffix = style_mappings.get(style, style)
                enhanced_prompt = f"{prompt}, {style_suffix}"

            # Add aspect ratio hint to prompt
            ratio_hints = {
                "1:1": "square composition",
                "16:9": "wide landscape composition",
                "9:16": "tall portrait composition",
                "4:3": "standard composition"
            }
            if aspect_ratio in ratio_hints:
                enhanced_prompt += f", {ratio_hints[aspect_ratio]}"

            logger.info(f"Generating image with Flux model for user {user_id}")
            logger.debug(f"Enhanced prompt: {enhanced_prompt}")

            # Call Flux API
            response = requests.post(
                f"{self.base_url}/images/generations",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "prompt": enhanced_prompt,
                },
                timeout=60  # 60 second timeout
            )

            response.raise_for_status()
            data = response.json()

            # Extract image URL from response
            if "data" in data and len(data["data"]) > 0:
                image_url = data["data"][0].get("url")
                if not image_url:
                    logger.error("No image URL in Flux API response")
                    return {
                        "success": False,
                        "error": "Image generation failed - no URL returned"
                    }

                # Success
                logger.info(f"Image generated successfully: {image_url[:50]}...")
                return {
                    "success": True,
                    "image_url": image_url,
                    "metadata": {
                        "model": self.model,
                        "original_prompt": prompt,
                        "enhanced_prompt": enhanced_prompt,
                        "style": style,
                        "aspect_ratio": aspect_ratio,
                        "generated_at": datetime.utcnow().isoformat()
                    }
                }
            else:
                logger.error(f"Unexpected Flux API response: {data}")
                return {
                    "success": False,
                    "error": "Unexpected response format from image generation API"
                }

        except requests.exceptions.Timeout:
            logger.error("Flux API request timed out")
            return {
                "success": False,
                "error": "Image generation timed out. Please try again."
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Flux API request failed: {str(e)}")
            return {
                "success": False,
                "error": f"Image generation API error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Unexpected error in Flux service: {type(e).__name__}: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                "success": False,
                "error": "An unexpected error occurred during image generation"
            }


# Singleton instance
_flux_service_instance: Optional[FluxImageService] = None


def get_flux_service() -> FluxImageService:
    """Get or create FluxImageService singleton instance"""
    global _flux_service_instance

    if _flux_service_instance is None:
        api_key = os.getenv("AIMLAPI_KEY")
        if not api_key:
            raise ValueError(
                "AIMLAPI_KEY environment variable not set. "
                "Please add your aimlapi.com API key to .env file."
            )

        _flux_service_instance = FluxImageService(api_key)
        logger.info("FluxImageService initialized successfully")

    return _flux_service_instance


def get_flux_service_for_user(user_id: int) -> FluxImageService:
    """
    Get FluxImageService instance for a specific user (reads API key from database)

    Args:
        user_id: User's ID

    Returns:
        FluxImageService instance configured with user's API key

    Raises:
        ValueError: If user doesn't have AIMLAPI key configured
    """
    from database.connection import get_db_connection, return_db_connection
    from utils.api_key_crypto import get_user_api_key

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()

        if not result:
            raise ValueError(f"User {user_id} not found")

        user_encrypted_key = result[0]

        # Get user's AIMLAPI key from database
        api_key = get_user_api_key(user_id, 'aimlapi', user_encrypted_key)

        if not api_key:
            raise ValueError(
                "AIMLAPI key not configured. "
                "Please configure your API key in Settings → API Keys."
            )

        logger.info(f"Retrieved AIMLAPI key for user {user_id}")
        return FluxImageService(api_key)

    finally:
        return_db_connection(conn)
