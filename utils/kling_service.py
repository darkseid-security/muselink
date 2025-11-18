"""
utils/kling_service.py
Kling AI Video Generation Service (via aimlapi.com)
"""

import os
import requests
import logging
import time
from typing import Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path
from utils.input_sanitizer import comprehensive_input_scan, log_malicious_input, detect_xss, has_control_characters

logger = logging.getLogger(__name__)


class KlingVideoService:
    """Kling AI v2.5 Turbo Pro video generation service via aimlapi.com"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.aimlapi.com/v2/generate/video/kling/generation"
        self.model = "klingai/v2.5-turbo/pro/text-to-video"
        self.video_output_dir = os.getenv("VIDEO_OUTPUT_DIR", "./generated_videos")

        # Create output directory if it doesn't exist
        Path(self.video_output_dir).mkdir(exist_ok=True)

    def start_video_generation(
        self,
        prompt: str,
        duration: int = 10,
        aspect_ratio: str = "16:9",
        cfg_scale: float = 0.7,
        negative_prompt: Optional[str] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Dict:
        """
        Start video generation task (async operation)

        Args:
            prompt: Video generation prompt
            duration: Video duration in seconds (5 or 10)
            aspect_ratio: Video aspect ratio (16:9, 9:16, 1:1)
            cfg_scale: CFG scale for prompt adherence (0.0-1.0)
            negative_prompt: Negative prompt to avoid unwanted elements
            user_id: User ID for audit logging
            ip_address: IP address for security logging

        Returns:
            Dict with task_id, status, and metadata
        """
        try:
            # Light validation for creative content - only check for script injection
            # SQL keywords like CREATE, DROP, etc. are perfectly valid in video prompts
            # Only block actual script/XSS patterns that could be dangerous if displayed

            # Check for XSS (script injection)
            xss_pattern = detect_xss(prompt)
            if xss_pattern:
                logger.warning(f"XSS detected in video prompt")
                if user_id and ip_address:
                    log_malicious_input(
                        user_id=user_id,
                        input_value=prompt[:500],
                        attack_type='xss',
                        pattern=xss_pattern,
                        ip_address=ip_address,
                        endpoint="/api/v1/ideas/generate-video"
                    )
                return {
                    "success": False,
                    "error": "Invalid characters detected in prompt"
                }

            # Check for control characters (null bytes, etc.)
            if has_control_characters(prompt):
                logger.warning(f"Control characters detected in video prompt")
                return {
                    "success": False,
                    "error": "Invalid characters detected in prompt"
                }

            # Validate duration
            if duration not in [5, 10]:
                return {
                    "success": False,
                    "error": "Duration must be 5 or 10 seconds"
                }

            # Validate aspect ratio
            if aspect_ratio not in ["16:9", "9:16", "1:1"]:
                return {
                    "success": False,
                    "error": "Invalid aspect ratio. Must be 16:9, 9:16, or 1:1"
                }

            # Prepare payload
            payload = {
                "model": self.model,
                "prompt": prompt,
                "duration": str(duration),
                "aspect_ratio": aspect_ratio,
                "cfg_scale": cfg_scale
            }

            if negative_prompt:
                payload["negative_prompt"] = negative_prompt

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            logger.info(
                f"Starting Kling video generation for user {user_id}: "
                f"duration={duration}s, aspect_ratio={aspect_ratio}"
            )

            # Make API request
            response = requests.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=30
            )

            # Accept both 200 OK and 201 Created as success
            if response.status_code not in [200, 201]:
                error_msg = f"API error {response.status_code}: {response.text}"
                logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "status_code": response.status_code
                }

            data = response.json()
            logger.info(f"Kling API response: status={response.status_code}, data={data}")

            # Extract task ID
            task_id = data.get("id")
            if not task_id:
                logger.error(f"No task ID in response: {data}")
                return {
                    "success": False,
                    "error": "No task ID received from API",
                    "response": data
                }

            logger.info(f"Video generation task started: {task_id}")

            return {
                "success": True,
                "task_id": task_id,
                "status": "processing",
                "duration": duration,
                "aspect_ratio": aspect_ratio,
                "prompt": prompt
            }

        except requests.exceptions.Timeout:
            logger.error("Video generation request timed out")
            return {
                "success": False,
                "error": "Request timed out. Please try again."
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Video generation request failed: {str(e)}")
            return {
                "success": False,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Unexpected error in video generation: {str(e)}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }

    def check_video_status(self, task_id: str) -> Dict:
        """
        Check the status of a video generation task

        Args:
            task_id: The task ID returned from start_video_generation

        Returns:
            Dict with status, video_url (if completed), and metadata
        """
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            params = {"generation_id": task_id}

            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=15
            )

            # Accept both 200 OK and 201 Created as success
            if response.status_code not in [200, 201]:
                error_msg = f"Status check error {response.status_code}: {response.text}"
                logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "status": "error"
                }

            data = response.json()
            status = data.get("status")

            logger.info(f"Video task {task_id} status: {status}")

            # Map Kling API statuses to our internal statuses
            # Kling uses: "queued", "processing", "generating", "completed", "failed"
            if status == "completed":
                # Extract video URL
                video_url = None
                if "video" in data and "url" in data["video"]:
                    video_url = data["video"]["url"]
                elif "url" in data:
                    video_url = data["url"]

                if not video_url:
                    logger.error(f"No video URL in completed response: {data}")
                    return {
                        "success": False,
                        "status": "error",
                        "error": "Video completed but no URL found"
                    }

                return {
                    "success": True,
                    "status": "completed",
                    "video_url": video_url,
                    "task_id": task_id
                }

            elif status in ["failed", "error"]:
                error_reason = data.get("error", "Unknown error")
                logger.error(f"Video generation failed: {error_reason}")
                return {
                    "success": False,
                    "status": "failed",
                    "error": error_reason
                }

            elif status in ["queued", "processing", "generating"]:
                # Kling API uses: "queued" (waiting), "processing" (started), "generating" (in progress)
                # Map all to "processing" for frontend
                return {
                    "success": True,
                    "status": "processing",
                    "task_id": task_id
                }

            else:
                # Unknown status - treat as still processing
                logger.warning(f"Unknown status '{status}' for task {task_id}, treating as processing")
                return {
                    "success": True,
                    "status": "processing",
                    "task_id": task_id
                }

        except requests.exceptions.Timeout:
            logger.error("Video status check timed out")
            return {
                "success": False,
                "error": "Status check timed out",
                "status": "error"
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Video status check failed: {str(e)}")
            return {
                "success": False,
                "error": f"Network error: {str(e)}",
                "status": "error"
            }
        except Exception as e:
            logger.error(f"Unexpected error checking video status: {str(e)}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "status": "error"
            }

    def download_video(self, video_url: str, task_id: str) -> Optional[str]:
        """
        Download video from URL and save to disk

        Args:
            video_url: URL of the generated video
            task_id: Task ID for filename

        Returns:
            Local file path if successful, None otherwise
        """
        try:
            logger.info(f"Downloading video from: {video_url}")

            response = requests.get(video_url, timeout=120)
            response.raise_for_status()

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"kling_{task_id[:8]}_{timestamp}.mp4"
            filepath = os.path.join(self.video_output_dir, filename)

            with open(filepath, "wb") as f:
                f.write(response.content)

            file_size = os.path.getsize(filepath)
            logger.info(
                f"Video downloaded successfully: {filepath} ({file_size} bytes)"
            )

            return filepath

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download video: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading video: {str(e)}")
            return None


# Singleton instance
_kling_service = None


def get_kling_service() -> KlingVideoService:
    """Get or create Kling video service instance"""
    global _kling_service
    if _kling_service is None:
        api_key = os.getenv("AIMLAPI_KEY")
        if not api_key:
            raise ValueError("AIMLAPI_KEY environment variable not set")
        _kling_service = KlingVideoService(api_key)
    return _kling_service
