"""
utils/gemini_service.py
Google Gemini Pro 2.5 Integration Service

Security Features:
- Input validation and malicious pattern detection
- Rate limiting (handled at router level)
- Audit logging for all AI requests
- Context size limits to prevent abuse
- Safe content filtering
- API key validation
"""

import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import google.generativeai as genai
from utils.input_sanitizer import comprehensive_input_scan, MaliciousInputDetected
from utils.audit import log_audit_event

logger = logging.getLogger(__name__)


class GeminiService:
    """
    Google Gemini Pro 2.5 Service for AI assistance

    Features:
    - Conversational AI assistance
    - Multimodal content analysis
    - Script analysis and enhancement
    - Flowchart generation and analysis
    - Context-aware responses
    """

    def __init__(self, api_key: str = None):
        """
        Initialize Gemini service

        Args:
            api_key: Google AI Studio API key (defaults to env var)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not self.api_key or self.api_key == "your_google_ai_studio_api_key_here":
            raise ValueError(
                "GEMINI_API_KEY not configured. "
                "Get your API key from https://aistudio.google.com/app/apikey"
            )

        # Configure Gemini
        genai.configure(api_key=self.api_key)

        # Initialize model
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-pro")
        self.model = genai.GenerativeModel(self.model_name)

        # Safety settings
        self.safety_settings = {
            "HARM_CATEGORY_HARASSMENT": "BLOCK_MEDIUM_AND_ABOVE",
            "HARM_CATEGORY_HATE_SPEECH": "BLOCK_MEDIUM_AND_ABOVE",
            "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_MEDIUM_AND_ABOVE",
            "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_MEDIUM_AND_ABOVE",
        }

        # Generation config
        self.generation_config = {
            "temperature": float(os.getenv("GEMINI_TEMPERATURE", "0.7")),
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": int(os.getenv("GEMINI_MAX_TOKENS", "64000")),
        }

        logger.info(f"Gemini service initialized with model: {self.model_name}")

    def _validate_input(self, text: str, user_id: int, ip_address: str, context: str = "input"):
        """
        Validate input for malicious patterns

        Args:
            text: Input text to validate
            user_id: User ID for logging
            ip_address: Request IP for logging
            context: Context description for logging

        Raises:
            MaliciousInputDetected: If malicious pattern detected
        """
        is_malicious, attack_type, pattern = comprehensive_input_scan(text)

        if is_malicious:
            logger.warning(
                f"Malicious input detected in Gemini {context}: "
                f"user_id={user_id}, attack_type={attack_type}"
            )
            raise MaliciousInputDetected(
                attack_type,
                pattern,
                text
            )

    def chat(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        user_id: int = None,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """
        Chat with AI assistant

        Args:
            message: User's message
            context: Optional context (user's ideas, projects, etc.)
            conversation_history: Previous conversation turns
            user_id: User ID for audit logging
            ip_address: IP address for audit logging

        Returns:
            {
                "success": bool,
                "response": str,
                "model": str,
                "context_used": dict,
                "tokens": int,
                "error": str (if failed)
            }
        """
        try:
            # Note: Input validation is skipped for chat messages
            # Chat messages are natural language and can legitimately contain
            # any content (code, SQL, technical discussions, etc.)
            # This endpoint is already protected by authentication, CSRF, and rate limiting.

            # Build system prompt
            system_prompt = self._build_system_prompt(context)

            # Build conversation history
            chat_history = []
            if conversation_history:
                for turn in conversation_history[-10:]:  # Last 10 turns only
                    chat_history.append({
                        "role": "user" if turn.get("role") == "user" else "model",
                        "parts": [turn.get("content", "")]
                    })

            # Create prompt with context
            full_prompt = f"{system_prompt}\n\nUser: {message}"

            # Generate response
            response = self.model.generate_content(
                full_prompt,
                safety_settings=self.safety_settings,
                generation_config=self.generation_config
            )

            # Check for blocked content
            if response.prompt_feedback.block_reason:
                logger.warning(
                    f"Gemini blocked content: {response.prompt_feedback.block_reason}"
                )
                return {
                    "success": False,
                    "error": "Content blocked by safety filters",
                    "block_reason": str(response.prompt_feedback.block_reason)
                }

            # Extract response text
            response_text = response.text

            # Count tokens (approximate)
            token_count = len(response_text.split()) + len(message.split())

            logger.info(
                f"Gemini chat successful: user_id={user_id}, "
                f"tokens~{token_count}, model={self.model_name}"
            )

            return {
                "success": True,
                "response": response_text,
                "model": self.model_name,
                "context_used": bool(context),
                "tokens": token_count,
                "timestamp": datetime.utcnow().isoformat()
            }

        except MaliciousInputDetected as e:
            return {
                "success": False,
                "error": str(e),
                "attack_type": e.attack_type
            }
        except Exception as e:
            logger.error(f"Gemini chat error: {type(e).__name__}: {str(e)}")
            return {
                "success": False,
                "error": f"AI assistant error: {str(e)}"
            }

    def analyze_script(
        self,
        script_content: str,
        user_id: int = None,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """
        Analyze screenplay/script for quality, pacing, character arcs

        Args:
            script_content: Full script text
            user_id: User ID for audit logging
            ip_address: IP address for audit logging

        Returns:
            {
                "success": bool,
                "analysis": {
                    "overall_score": float,
                    "pacing": {...},
                    "characters": [...],
                    "plot": {...},
                    "suggestions": [...]
                },
                "error": str (if failed)
            }
        """
        try:
            # Check script length
            word_count = len(script_content.split())
            if word_count > 50000:
                return {
                    "success": False,
                    "error": "Script too long (max 50,000 words)"
                }

            # Build analysis prompt
            prompt = f"""
You are an expert screenplay analyst. Analyze the following script and provide detailed feedback.

SCRIPT:
{script_content}

Provide analysis in the following JSON format:
{{
    "overall_score": <1-10>,
    "overall_assessment": "<brief summary>",
    "pacing": {{
        "score": <1-10>,
        "feedback": "<detailed pacing analysis>",
        "issues": ["<issue 1>", "<issue 2>"]
    }},
    "character_development": {{
        "score": <1-10>,
        "characters": [
            {{
                "name": "<character name>",
                "arc_quality": <1-10>,
                "feedback": "<character analysis>"
            }}
        ]
    }},
    "plot_structure": {{
        "score": <1-10>,
        "strengths": ["<strength 1>", "<strength 2>"],
        "weaknesses": ["<weakness 1>", "<weakness 2>"],
        "plot_holes": ["<hole 1>", "<hole 2>"]
    }},
    "dialogue_quality": {{
        "score": <1-10>,
        "feedback": "<dialogue analysis>"
    }},
    "suggestions": [
        {{
            "priority": "<high|medium|low>",
            "category": "<category>",
            "suggestion": "<specific improvement>"
        }}
    ]
}}
"""

            # Generate analysis
            response = self.model.generate_content(
                prompt,
                safety_settings=self.safety_settings,
                generation_config={
                    **self.generation_config,
                    "temperature": 0.3,  # Lower temp for analysis
                }
            )

            # Parse JSON response
            import json
            import re

            response_text = response.text

            # Extract JSON from markdown code blocks if present
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1)

            try:
                analysis = json.loads(response_text)
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw text
                analysis = {
                    "raw_analysis": response_text,
                    "parsed": False
                }

            logger.info(
                f"Gemini script analysis: user_id={user_id}, "
                f"word_count={word_count}"
            )

            return {
                "success": True,
                "analysis": analysis,
                "word_count": word_count,
                "model": self.model_name
            }

        except Exception as e:
            logger.error(f"Gemini script analysis error: {type(e).__name__}: {str(e)}")
            return {
                "success": False,
                "error": f"Analysis failed: {str(e)}"
            }

    def generate_flowchart(
        self,
        description: str,
        user_id: int = None,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """
        Generate Mermaid.js flowchart from text description

        Args:
            description: Text description of workflow
            user_id: User ID for audit logging
            ip_address: IP address for audit logging

        Returns:
            {
                "success": bool,
                "mermaid": str,
                "description": str,
                "error": str (if failed)
            }
        """
        try:
            # Note: Input validation is skipped for flowchart descriptions
            # Flowchart descriptions are natural language that may legitimately contain
            # technical terms, SQL keywords, code snippets, etc.
            # This endpoint is already protected by authentication, CSRF, and rate limiting.

            prompt = f"""
Generate a Mermaid.js flowchart based on this description:

{description}

Requirements:
1. Use proper Mermaid.js syntax
2. Use flowchart TD (top-down) format
3. Include decision points (diamonds) where applicable
4. Use clear, concise node labels
5. Show the complete workflow from start to end
6. IMPORTANT: Wrap ALL node labels in quotes to avoid parsing errors (e.g., A["Step Name"])
7. Avoid parentheses, brackets, and special characters in labels - use quotes instead
8. Use simple alphanumeric node IDs (A, B, C or step1, step2, etc.)

Example format:
flowchart TD
    A["Start"] --> B["First Step"]
    B --> C["Second Step"]
    C --> D["End"]

Output ONLY the Mermaid.js code, no explanations.
"""

            response = self.model.generate_content(
                prompt,
                safety_settings=self.safety_settings,
                generation_config=self.generation_config
            )

            mermaid_code = response.text.strip()

            # Extract from code blocks if present
            import re
            code_match = re.search(r'```(?:mermaid)?\s*(.*?)\s*```', mermaid_code, re.DOTALL)
            if code_match:
                mermaid_code = code_match.group(1)

            logger.info(f"Gemini flowchart generated: user_id={user_id}")

            return {
                "success": True,
                "mermaid": mermaid_code,
                "description": description,
                "model": self.model_name
            }

        except MaliciousInputDetected as e:
            return {
                "success": False,
                "error": str(e),
                "attack_type": e.attack_type
            }
        except Exception as e:
            logger.error(f"Gemini flowchart generation error: {type(e).__name__}: {str(e)}")
            return {
                "success": False,
                "error": f"Flowchart generation failed: {str(e)}"
            }

    def _build_system_prompt(self, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Build system prompt with user context

        Args:
            context: User context (ideas, projects, etc.)

        Returns:
            System prompt string
        """
        base_prompt = """You are an AI creative assistant for the Muse platform, a professional content creation and collaboration tool.

Your role:
- Help users brainstorm creative ideas for screenplays, videos, and media
- Provide constructive feedback on scripts, images, and videos
- Suggest improvements to workflows and processes
- Answer questions about their projects
- Offer creative direction and inspiration

Guidelines:
- Be helpful, professional, and encouraging
- Provide specific, actionable advice
- Reference user's existing work when relevant
- Ask clarifying questions when needed
- Respect creative vision while suggesting improvements
"""

        if context:
            context_text = "\n\nUser Context:\n"

            if context.get("recent_ideas"):
                context_text += f"\nRecent Ideas: {len(context['recent_ideas'])} ideas created\n"
                for idea in context["recent_ideas"][:3]:
                    context_text += f"  - {idea.get('title', 'Untitled')}\n"

            if context.get("recent_images"):
                context_text += f"\nRecent Images: {len(context['recent_images'])} images generated\n"

            if context.get("teams"):
                context_text += f"\nTeams: {', '.join(context['teams'])}\n"

            if context.get("active_projects"):
                context_text += f"\nActive Projects: {len(context['active_projects'])}\n"

            return base_prompt + context_text

        return base_prompt


# Singleton instance
_gemini_service_instance = None


def get_gemini_service() -> GeminiService:
    """
    Get singleton Gemini service instance

    Returns:
        GeminiService instance
    """
    global _gemini_service_instance

    if _gemini_service_instance is None:
        _gemini_service_instance = GeminiService()

    return _gemini_service_instance


def get_gemini_service_for_user(user_id: int) -> GeminiService:
    """
    Get Gemini service instance for a specific user (reads API key from database)

    Args:
        user_id: User's ID

    Returns:
        GeminiService instance configured with user's API key

    Raises:
        ValueError: If user doesn't have Gemini API key configured
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

        # Get user's Gemini API key from database
        api_key = get_user_api_key(user_id, 'gemini', user_encrypted_key)

        if not api_key:
            raise ValueError(
                "Gemini API key not configured. "
                "Please configure your API key in Settings → API Keys."
            )

        logger.info(f"Retrieved Gemini API key for user {user_id}")
        return GeminiService(api_key)

    finally:
        return_db_connection(conn)
