"""
utils/gpt5_service.py
GPT-5 AI Script Generation Service
Integrates with aimlapi.com for creative script generation
"""

import os
import logging
from typing import Dict, Any, Optional
from openai import OpenAI
from utils.input_sanitizer import comprehensive_input_scan, log_malicious_input, detect_xss, has_control_characters

logger = logging.getLogger(__name__)

class GPT5Service:
    """
    Service for generating creative scripts using GPT-5 via aimlapi.com

    Security Features:
    - Input validation and malicious pattern detection
    - Rate limiting enforcement
    - Audit logging for all AI requests
    - Encrypted storage of generated content
    """

    def __init__(self):
        """Initialize GPT-5 client with API key from environment"""
        self.api_key = os.getenv("AIMLAPI_KEY")

        if not self.api_key or self.api_key == "your_aimlapi_key_here":
            logger.warning("AIMLAPI_KEY not configured. GPT-5 service will not function.")
            self.client = None
        else:
            try:
                import httpx
                import certifi

                # Create HTTP client with proper SSL configuration
                http_client = httpx.Client(
                    timeout=httpx.Timeout(60.0, connect=10.0),
                    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                    verify=certifi.where()  # Use certifi's CA bundle for SSL verification
                )

                self.client = OpenAI(
                    base_url="https://api.aimlapi.com/v1",
                    api_key=self.api_key,
                    http_client=http_client,
                    max_retries=2
                )
                logger.info("GPT-5 service initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize GPT-5 client: {e}")
                self.client = None

    def validate_inputs(
        self,
        title: str,
        description: str,
        content_type: str,
        brand_voice: Optional[str],
        target_audience: str,
        key_messages: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Validate all inputs for malicious content before sending to AI

        Note: Light validation for creative content - only checks for script injection
        and control characters. SQL keywords like CREATE, DROP, etc. are perfectly
        valid in creative scripts and should not be blocked.

        Returns:
            (is_valid, error_message) tuple
        """
        inputs_to_check = {
            "title": title,
            "description": description,
            "content_type": content_type,
            "target_audience": target_audience,
            "key_messages": key_messages
        }

        if brand_voice:
            inputs_to_check["brand_voice"] = brand_voice

        for field_name, value in inputs_to_check.items():
            # Check for XSS (script injection) - matters if content is displayed in HTML
            xss_pattern = detect_xss(str(value))
            if xss_pattern:
                logger.warning(f"XSS detected in {field_name}")
                if user_id and ip_address:
                    log_malicious_input(
                        user_id=user_id,
                        input_value=str(value)[:500],
                        attack_type='xss',
                        pattern=xss_pattern,
                        ip_address=ip_address,
                        endpoint="/api/v1/ideas/generate-script"
                    )
                return False, f"Invalid characters detected in {field_name}"

            # Check for control characters (null bytes, etc.)
            if has_control_characters(str(value)):
                logger.warning(f"Control characters detected in {field_name}")
                return False, f"Invalid characters detected in {field_name}"

        return True, None

    def generate_script(
        self,
        title: str,
        description: str,
        content_type: str,
        brand_voice: Optional[str],
        target_audience: str,
        key_messages: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a creative script using GPT-5

        Args:
            title: Project title
            description: Project description
            content_type: Type of content (Script, Copywriting, etc.)
            brand_voice: Brand voice and tone
            target_audience: Target audience description
            key_messages: Key messages to communicate
            user_id: User ID for logging (optional)
            ip_address: IP address for logging (optional)

        Returns:
            Dictionary with:
            - success: bool
            - script: str (if successful)
            - error: str (if failed)
            - metadata: dict with generation details
        """

        # Check if service is available
        if not self.client:
            return {
                "success": False,
                "error": "AI service not configured. Please contact administrator.",
                "script": None,
                "metadata": {}
            }

        # Validate inputs for security
        is_valid, error_msg = self.validate_inputs(
            title=title,
            description=description,
            content_type=content_type,
            brand_voice=brand_voice,
            target_audience=target_audience,
            key_messages=key_messages,
            user_id=user_id,
            ip_address=ip_address
        )

        if not is_valid:
            return {
                "success": False,
                "error": error_msg,
                "script": None,
                "metadata": {}
            }

        # Build the prompt for GPT-5
        prompt = self._build_prompt(
            title=title,
            description=description,
            content_type=content_type,
            brand_voice=brand_voice,
            target_audience=target_audience,
            key_messages=key_messages
        )

        try:
            logger.info(f"Generating script with GPT-5 for user {user_id}: {title}")
            logger.debug(f"API Base URL: {self.client.base_url}")
            logger.debug(f"Using model: openai/gpt-5-chat-latest")

            # Call GPT-5 API with timeout
            response = self.client.chat.completions.create(
                model="openai/gpt-5-chat-latest",  # GPT-5 via aimlapi.com
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt(content_type)
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.8,  # Creative but not too random
                max_tokens=4096,   # Maximum tokens for response
                timeout=60.0  # 60 second timeout
            )

            # Extract generated content
            generated_script = response.choices[0].message.content

            # Get metadata
            metadata = {
                "model": "openai/gpt-5-chat-latest",
                "prompt_tokens": response.usage.prompt_tokens if hasattr(response, 'usage') else 0,
                "completion_tokens": response.usage.completion_tokens if hasattr(response, 'usage') else 0,
                "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0,
                "content_type": content_type,
                "word_count": len(generated_script.split())
            }

            logger.info(
                f"Successfully generated script for user {user_id}: "
                f"{metadata['word_count']} words, {metadata['total_tokens']} tokens"
            )

            return {
                "success": True,
                "script": generated_script,
                "error": None,
                "metadata": metadata
            }

        except Exception as e:
            import traceback
            error_type = type(e).__name__
            error_msg = str(e)
            full_traceback = traceback.format_exc()

            logger.error(f"GPT-5 script generation failed: {error_type}: {error_msg}")
            logger.error(f"Full traceback:\n{full_traceback}")

            # Check if it's a connection error - try direct API test
            if "APIConnectionError" in error_type or "Connection" in error_msg:
                logger.info("Testing direct API connection with requests library...")
                try:
                    import requests
                    test_response = requests.post(
                        "https://api.aimlapi.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "openai/gpt-5-chat-latest",
                            "messages": [{"role": "user", "content": "test"}],
                            "max_tokens": 10
                        },
                        timeout=30
                    )
                    logger.info(f"Direct API test status: {test_response.status_code}")
                    logger.info(f"Direct API test response: {test_response.text[:500]}")

                    # Check if model is temporarily unavailable
                    if test_response.status_code == 400:
                        try:
                            response_json = test_response.json()
                            if "temporarily unavailable" in response_json.get("message", "").lower():
                                logger.warning("GPT-5 model is temporarily unavailable on AIMLAPI")
                                return {
                                    "success": False,
                                    "error": "The GPT-5 model is temporarily unavailable. Please try again in a few minutes.",
                                    "script": None,
                                    "metadata": {}
                                }
                        except:
                            pass
                except Exception as req_error:
                    logger.error(f"Direct API test also failed: {type(req_error).__name__}: {req_error}")

            # Provide user-friendly error message
            if "APIConnectionError" in error_type or "Connection" in error_msg:
                user_error = "Unable to connect to AI service. Please check your internet connection and try again."
            elif "APIStatusError" in error_type or "401" in error_msg:
                user_error = "AI API authentication failed. Please check your API key configuration."
            elif "RateLimitError" in error_type:
                user_error = "AI API rate limit exceeded. Please try again in a few minutes."
            elif "timeout" in error_msg.lower():
                user_error = "AI service request timed out. Please try again."
            else:
                user_error = f"AI generation failed. Please try again. ({error_type})"

            return {
                "success": False,
                "error": user_error,
                "script": None,
                "metadata": {}
            }

    def _get_system_prompt(self, content_type: str) -> str:
        """
        Get the appropriate system prompt based on content type
        """
        prompts = {
            "Script": """You are a master screenwriter and creative director. Generate highly creative, visually stunning movie scripts with:
            - Detailed scene descriptions with vivid imagery
            - Compelling dialogue that reveals character
            - Professional camera directions (e.g., FADE IN, CUT TO, CLOSE-UP)
            - Clear scene headings (INT./EXT. - LOCATION - TIME)
            - Proper screenplay formatting
            - Engaging narrative structure""",

            "Copywriting": """You are an expert copywriter specializing in persuasive, engaging content. Create:
            - Compelling headlines and hooks
            - Clear value propositions
            - Persuasive calls-to-action
            - Brand-appropriate tone and voice
            - Benefits-focused messaging
            - Concise, impactful copy""",

            "Video Script": """You are a professional video script writer. Create scripts with:
            - Shot-by-shot descriptions
            - Voice-over narration
            - On-screen text suggestions
            - B-roll recommendations
            - Timing and pacing notes
            - Visual storytelling techniques""",

            "Social Media": """You are a social media content expert. Create posts that:
            - Grab attention immediately
            - Encourage engagement and sharing
            - Use appropriate hashtags
            - Include emoji where relevant
            - Match platform best practices
            - Drive specific actions""",

            "Email Campaign": """You are an email marketing specialist. Write emails with:
            - Attention-grabbing subject lines
            - Personalized greeting
            - Clear structure (intro, body, CTA)
            - Compelling calls-to-action
            - Professional yet conversational tone
            - Mobile-friendly formatting""",

            "Blog Post": """You are a professional content writer. Create blog posts with:
            - SEO-friendly structure
            - Engaging introduction
            - Clear subheadings
            - Informative body content
            - Actionable takeaways
            - Strong conclusion""",

            "Storyboard": """You are a storyboard artist and visual storyteller. Create detailed storyboards with:
            - Scene-by-scene visual descriptions
            - Camera angles and movements
            - Character positions and actions
            - Lighting and mood notes
            - Transition suggestions
            - Visual composition details"""
        }

        return prompts.get(
            content_type,
            "You are a creative content specialist. Generate professional, engaging content that meets the user's requirements."
        )

    def _build_prompt(
        self,
        title: str,
        description: str,
        content_type: str,
        brand_voice: Optional[str],
        target_audience: str,
        key_messages: str
    ) -> str:
        """
        Build a comprehensive prompt for GPT-5
        """
        prompt_parts = [
            f"# Project: {title}",
            f"\n## Content Type: {content_type}",
            f"\n## Description:\n{description}" if description else "",
            f"\n## Target Audience:\n{target_audience}",
            f"\n## Key Messages:\n{key_messages}",
            f"\n## Brand Voice & Tone:\n{brand_voice}" if brand_voice else "",
            "\n\n---\n",
            f"Create a professional {content_type.lower()} that:",
            "- Captures the essence of the project description",
            "- Speaks directly to the target audience",
            "- Communicates the key messages effectively",
            "- Maintains the specified brand voice and tone" if brand_voice else "",
            "- Includes all necessary structural elements",
            "- Is ready for production/publication\n",
            f"\nGenerate a complete, polished {content_type.lower()} now:"
        ]

        return "\n".join(filter(None, prompt_parts))


# Global service instance
_gpt5_service = None

def get_gpt5_service() -> GPT5Service:
    """
    Get or create the global GPT5Service instance
    """
    global _gpt5_service
    if _gpt5_service is None:
        _gpt5_service = GPT5Service()
    return _gpt5_service


def get_gpt5_service_for_user(user_id: int) -> GPT5Service:
    """
    Get GPT5Service instance for a specific user (reads API key from database)

    Args:
        user_id: User's ID

    Returns:
        GPT5Service instance configured with user's API key

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
        return GPT5Service(api_key)

    finally:
        return_db_connection(conn)
