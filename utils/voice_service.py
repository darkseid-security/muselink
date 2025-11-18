"""
utils/voice_service.py
AI Voice Generation Service using ElevenLabs via aimlapi.com
"""

import os
import requests
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Available ElevenLabs voices
AVAILABLE_VOICES = {
    # Professional voices
    "male-professional": "Antoni",
    "female-professional": "Rachel",

    # Casual voices
    "male-casual": "Josh",
    "female-casual": "Domi",

    # Narrator voices
    "male-narrator": "Arnold",
    "female-narrator": "Bella",

    # Additional voices
    "Rachel": "Rachel",
    "Drew": "Drew",
    "Clyde": "Clyde",
    "Paul": "Paul",
    "Aria": "Aria",
    "Domi": "Domi",
    "Dave": "Dave",
    "Roger": "Roger",
    "Fin": "Fin",
    "Sarah": "Sarah",
    "Antoni": "Antoni",
    "Laura": "Laura",
    "Thomas": "Thomas",
    "Charlie": "Charlie",
    "George": "George",
    "Emily": "Emily",
    "Elli": "Elli",
    "Callum": "Callum",
    "Patrick": "Patrick",
    "River": "River",
    "Harry": "Harry",
    "Liam": "Liam",
    "Dorothy": "Dorothy",
    "Josh": "Josh",
    "Arnold": "Arnold",
    "Charlotte": "Charlotte",
    "Alice": "Alice",
    "Matilda": "Matilda",
    "James": "James",
    "Joseph": "Joseph",
    "Will": "Will",
    "Jeremy": "Jeremy",
    "Jessica": "Jessica",
    "Eric": "Eric",
    "Michael": "Michael",
    "Ethan": "Ethan",
    "Chris": "Chris",
    "Gigi": "Gigi",
    "Freya": "Freya",
    "Santa Claus": "Santa Claus",
    "Brian": "Brian",
    "Grace": "Grace",
    "Daniel": "Daniel",
    "Lily": "Lily",
    "Serena": "Serena",
    "Adam": "Adam",
    "Nicole": "Nicole",
    "Bill": "Bill",
    "Jessie": "Jessie",
    "Sam": "Sam",
    "Glinda": "Glinda",
    "Giovanni": "Giovanni",
    "Mimi": "Mimi"
}

# Available models
AVAILABLE_MODELS = {
    "standard": "elevenlabs/eleven_turbo_v2_5",
    "multilingual": "elevenlabs/eleven_multilingual_v2",
    "alpha": "elevenlabs/v3_alpha"
}


class VoiceGenerationService:
    """AI Voice Generation Service using ElevenLabs via aimlapi.com"""

    def __init__(self):
        self.api_key = os.getenv("AIMLAPI_KEY")
        if not self.api_key:
            logger.warning("AIMLAPI_KEY not found in environment variables")

        self.api_url = "https://api.aimlapi.com/v1/tts"
        self.output_dir = os.getenv("VOICE_OUTPUT_DIR", "generated_audio")

        # Ensure output directory exists
        Path(self.output_dir).mkdir(exist_ok=True)

    def generate_voice(
        self,
        text: str,
        voice_type: str = "female-professional",
        model: str = "standard",
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate voice from text using ElevenLabs TTS

        Args:
            text: Text to convert to speech
            voice_type: Voice type (e.g., "male-professional", "female-casual")
            model: Model to use ("standard", "multilingual", "alpha")
            user_id: User ID for logging
            ip_address: IP address for logging

        Returns:
            Dict with success status, file path, and metadata
        """

        # Validate inputs
        if not text or len(text.strip()) == 0:
            return {
                "success": False,
                "error": "Text cannot be empty"
            }

        if len(text) > 5000:
            return {
                "success": False,
                "error": "Text is too long (max 5000 characters)"
            }

        # Check API key
        if not self.api_key:
            return {
                "success": False,
                "error": "Voice generation is not configured. Please contact administrator."
            }

        # Map voice type to actual voice name
        voice_name = AVAILABLE_VOICES.get(voice_type, "Rachel")

        # Map model to actual model name
        model_name = AVAILABLE_MODELS.get(model, AVAILABLE_MODELS["standard"])

        try:
            # Prepare request
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": model_name,
                "text": text,
                "voice": voice_name
            }

            logger.info(
                f"Generating voice for user_id={user_id}, "
                f"voice={voice_name}, model={model_name}, "
                f"text_length={len(text)}"
            )

            # Make API request
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                stream=True,
                timeout=30
            )

            # Check response status (accept any 2xx success code)
            if response.status_code < 200 or response.status_code >= 300:
                error_detail = "Unknown error"
                try:
                    error_detail = response.text[:500]  # Limit error message size
                except:
                    error_detail = "Could not read error response"

                logger.error(
                    f"Voice generation API error: {response.status_code} - {error_detail}"
                )
                return {
                    "success": False,
                    "error": f"Voice API error ({response.status_code}): {error_detail}"
                }

            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"voice_{user_id}_{timestamp}.wav"
            file_path = os.path.join(self.output_dir, filename)

            # Save audio file
            try:
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            except Exception as e:
                logger.error(f"Failed to save audio file: {str(e)}")
                return {
                    "success": False,
                    "error": f"Failed to save audio file: {str(e)}"
                }

            # Verify file was created and get file size
            if not os.path.exists(file_path):
                logger.error("Audio file was not created")
                return {
                    "success": False,
                    "error": "Audio file was not created"
                }

            file_size = os.path.getsize(file_path)

            # Check if file is suspiciously small (might be an error response)
            if file_size < 100:
                logger.warning(f"Audio file is very small ({file_size} bytes), might be an error")
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        logger.error(f"Small file content: {content[:200]}")
                except:
                    pass

            logger.info(
                f"Voice generated successfully: {filename}, size={file_size} bytes"
            )

            return {
                "success": True,
                "file_path": file_path,
                "filename": filename,
                "metadata": {
                    "voice": voice_name,
                    "model": model_name,
                    "text_length": len(text),
                    "file_size": file_size,
                    "duration_estimate": len(text.split()) * 0.5  # Rough estimate: 0.5s per word
                }
            }

        except requests.exceptions.Timeout:
            logger.error("Voice generation request timed out")
            return {
                "success": False,
                "error": "Voice generation timed out. Please try again."
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Voice generation request error: {str(e)}")
            return {
                "success": False,
                "error": "Failed to connect to voice generation service"
            }

        except Exception as e:
            logger.error(f"Unexpected error in voice generation: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                "success": False,
                "error": "An unexpected error occurred during voice generation"
            }


# Singleton instance
_voice_service_instance = None


def get_voice_service() -> VoiceGenerationService:
    """Get singleton instance of VoiceGenerationService"""
    global _voice_service_instance
    if _voice_service_instance is None:
        _voice_service_instance = VoiceGenerationService()
    return _voice_service_instance
