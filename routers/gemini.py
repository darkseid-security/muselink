"""
routers/gemini.py
Google Gemini Pro 2.5 AI Assistant Router

Security Features:
- Rate limiting (10 requests/hour for chat, 5/hour for analysis)
- Input validation and malicious pattern detection
- IDOR protection (user context only)
- Audit logging for all AI requests
- Encrypted context handling
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.auth_dependencies import require_auth
from utils.audit import log_audit_event
from utils.encryption import decrypt_user_key
from utils.crypto_aes import decrypt_text
from utils.gemini_service import get_gemini_service_for_user
from utils.input_sanitizer import MaliciousInputDetected

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Pydantic Models

class ChatMessage(BaseModel):
    """Chat message model"""
    message: str = Field(..., min_length=1, max_length=5000)
    include_context: bool = Field(default=True)
    conversation_id: Optional[str] = Field(None, max_length=100)

    @validator('message')
    def strip_message(cls, v):
        return v.strip()


class ChatHistoryItem(BaseModel):
    """Chat history item"""
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str = Field(..., max_length=10000)


class ScriptAnalysisRequest(BaseModel):
    """Script analysis request"""
    idea_id: int = Field(..., gt=0)


class FlowchartGenerationRequest(BaseModel):
    """Flowchart generation request"""
    description: str = Field(..., min_length=10, max_length=2000)

    @validator('description')
    def strip_description(cls, v):
        return v.strip()


# Helper Functions

async def gather_user_context(user_id: int, limit: int = 5) -> Dict[str, Any]:
    """
    Gather user's recent content for AI context

    Security:
    - IDOR Protection: Only fetches user's own content
    - Decrypts content for AI analysis
    - Limits context size to prevent abuse

    Args:
        user_id: User ID
        limit: Max items per category

    Returns:
        {
            "recent_ideas": [...],
            "recent_images": [...],
            "teams": [...],
            "active_projects": int
        }
    """
    conn = None
    context = {
        "recent_ideas": [],
        "recent_images": [],
        "teams": [],
        "active_projects": 0
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key_result = cursor.fetchone()

        if not user_encrypted_key_result:
            return context

        user_encrypted_key = user_encrypted_key_result[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Get recent ideas (IDOR-safe: owner_id filter)
        cursor.execute(
            """
            SELECT id, title_encrypted, encryption_iv, encryption_tag, created_at
            FROM ideas
            WHERE owner_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_id, limit)
        )

        for row in cursor.fetchall():
            idea_id, title_enc, iv, tag, created_at = row
            try:
                # Decrypt title (format: title|||description|||content)
                combined_decrypted = decrypt_text(title_enc, user_key, iv, tag)
                parts = combined_decrypted.split("|||")
                title = parts[0].strip() if parts and parts[0].strip() else "Untitled"

                context["recent_ideas"].append({
                    "id": idea_id,
                    "title": title,
                    "created_at": created_at.isoformat()
                })
            except Exception as e:
                logger.error(f"Failed to decrypt idea {idea_id} for context: {e}")
                continue

        # Get recent images (IDOR-safe: user_id filter)
        cursor.execute(
            """
            SELECT id, prompt_encrypted, encryption_iv, encryption_tag, created_at
            FROM generated_images
            WHERE user_id = %s AND is_deleted = FALSE
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_id, limit)
        )

        for row in cursor.fetchall():
            image_id, prompt_enc, iv, tag, created_at = row
            try:
                prompt = decrypt_text(prompt_enc, user_key, iv, tag)
                context["recent_images"].append({
                    "id": image_id,
                    "prompt_preview": prompt[:100] + "..." if len(prompt) > 100 else prompt,
                    "created_at": created_at.isoformat()
                })
            except Exception as e:
                logger.error(f"Failed to decrypt image {image_id} prompt for context: {e}")
                continue

        # Get user's teams
        cursor.execute(
            """
            SELECT t.name
            FROM teams t
            INNER JOIN team_members tm ON t.id = tm.team_id
            WHERE tm.user_id = %s AND tm.is_active = TRUE
            """,
            (user_id,)
        )

        context["teams"] = [row[0] for row in cursor.fetchall()]

        # Count active projects (ideas in progress)
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM ideas
            WHERE owner_id = %s AND status = 'in_progress' AND is_deleted = FALSE
            """,
            (user_id,)
        )

        context["active_projects"] = cursor.fetchone()[0]

        logger.info(
            f"Context gathered for user {user_id}: "
            f"{len(context['recent_ideas'])} ideas, "
            f"{len(context['recent_images'])} images, "
            f"{len(context['teams'])} teams"
        )

        return context

    except Exception as e:
        logger.error(f"Error gathering user context: {type(e).__name__}: {str(e)}")
        return context
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


# Endpoints

@router.post("/chat", status_code=status.HTTP_200_OK)
@limiter.limit("30/hour")  # 30 chat messages per hour
async def chat_with_assistant(
    chat_request: ChatMessage,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Chat with AI assistant

    Security Features:
    - Rate limited to 30 requests per hour
    - Input validation and malicious pattern detection
    - IDOR protection (user's context only)
    - Audit logging for all requests
    - Safe content filtering via Gemini

    Example Request:
    {
        "message": "Help me brainstorm ideas for a sci-fi screenplay",
        "include_context": true,
        "conversation_id": "conv_123"
    }

    Returns:
    {
        "success": true,
        "response": "AI assistant response...",
        "context_used": true,
        "tokens": 150,
        "timestamp": "2025-11-15T12:00:00"
    }
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Gemini service
        gemini_service = get_gemini_service_for_user(user_id)

        # Gather user context if requested
        context = None
        if chat_request.include_context:
            context = await gather_user_context(user_id, limit=5)

        # Get conversation history if conversation_id provided
        conversation_history = None
        if chat_request.conversation_id:
            # TODO: Implement conversation history storage
            # For now, just pass None
            pass

        # Chat with AI
        result = gemini_service.chat(
            message=chat_request.message,
            context=context,
            conversation_history=conversation_history,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            # Check for malicious input
            if "attack_type" in result:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Malicious input detected: {result['attack_type']}"
                )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "AI assistant failed")
            )

        # Audit log
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "gemini_chat",
            "success",
            ip_address,
            {
                "tokens": result.get("tokens"),
                "context_used": result.get("context_used"),
                "model": result.get("model")
            }
        )
        conn.commit()

        logger.info(
            f"Gemini chat successful: user_id={user_id}, "
            f"tokens={result.get('tokens')}"
        )

        return result

    except HTTPException:
        raise
    except MaliciousInputDetected as e:
        if conn:
            cursor = conn.cursor()
            log_audit_event(
                cursor, user_id, "gemini_chat_blocked", "failed", ip_address,
                {"reason": "malicious_input", "attack_type": str(e.attack_type)}
            )
            conn.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malicious input detected: {e.attack_type}"
        )
    except Exception as e:
        logger.error(f"Gemini chat error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI assistant error. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.post("/analyze-script", status_code=status.HTTP_200_OK)
@limiter.limit("5/hour")  # 5 script analyses per hour (expensive)
async def analyze_script(
    analysis_request: ScriptAnalysisRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Analyze screenplay/script with AI

    Security Features:
    - Rate limited to 5 requests per hour (expensive operation)
    - IDOR protection (verifies ownership)
    - Decrypts script for analysis
    - Audit logging

    Returns detailed analysis including:
    - Overall quality score
    - Pacing analysis
    - Character development
    - Plot structure
    - Dialogue quality
    - Actionable suggestions
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get idea and verify ownership (IDOR protection)
        cursor.execute(
            """
            SELECT owner_id, title_encrypted, encryption_iv, encryption_tag
            FROM ideas
            WHERE id = %s AND is_deleted = FALSE
            """,
            (analysis_request.idea_id,)
        )

        row = cursor.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Script not found"
            )

        owner_id, combined_enc, iv, tag = row

        if owner_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

        # Get user's encryption key
        cursor.execute(
            "SELECT encryption_key FROM users WHERE id = %s",
            (user_id,)
        )
        user_encrypted_key = cursor.fetchone()[0]
        user_key = decrypt_user_key(user_encrypted_key)

        # Decrypt script (format: title|||description|||content)
        combined_decrypted = decrypt_text(combined_enc, user_key, iv, tag)
        parts = combined_decrypted.split("|||")

        if len(parts) >= 3:
            script_content = parts[2]
        else:
            script_content = combined_decrypted

        # Analyze with Gemini
        gemini_service = get_gemini_service_for_user(user_id)
        result = gemini_service.analyze_script(
            script_content=script_content,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Analysis failed")
            )

        # Audit log
        log_audit_event(
            cursor,
            user_id,
            "gemini_script_analysis",
            "success",
            ip_address,
            {
                "idea_id": analysis_request.idea_id,
                "word_count": result.get("word_count"),
                "model": result.get("model")
            }
        )
        conn.commit()

        logger.info(
            f"Gemini script analysis successful: user_id={user_id}, "
            f"idea_id={analysis_request.idea_id}"
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Gemini script analysis error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Script analysis failed. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.post("/generate-flowchart", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")  # 10 flowchart generations per hour
async def generate_flowchart(
    flowchart_request: FlowchartGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Generate Mermaid.js flowchart from text description

    Security Features:
    - Rate limited to 10 requests per hour
    - Input validation and malicious pattern detection
    - Audit logging

    Example Request:
    {
        "description": "Create a flowchart for video production workflow:
                       script writing, storyboarding, filming, editing, publishing"
    }

    Returns:
    {
        "success": true,
        "mermaid": "flowchart TD\n  A[Start] --> B[Script Writing]...",
        "description": "..."
    }
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Gemini service
        gemini_service = get_gemini_service_for_user(user_id)

        # Generate flowchart
        result = gemini_service.generate_flowchart(
            description=flowchart_request.description,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            # Check for malicious input
            if "attack_type" in result:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Malicious input detected: {result['attack_type']}"
                )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Flowchart generation failed")
            )

        # Audit log
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "gemini_flowchart_generated",
            "success",
            ip_address,
            {
                "description_length": len(flowchart_request.description),
                "model": result.get("model")
            }
        )
        conn.commit()

        logger.info(f"Gemini flowchart generated: user_id={user_id}")

        return result

    except HTTPException:
        raise
    except MaliciousInputDetected as e:
        if conn:
            cursor = conn.cursor()
            log_audit_event(
                cursor, user_id, "gemini_flowchart_blocked", "failed", ip_address,
                {"reason": "malicious_input", "attack_type": str(e.attack_type)}
            )
            conn.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malicious input detected: {e.attack_type}"
        )
    except Exception as e:
        logger.error(f"Gemini flowchart generation error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Flowchart generation failed. Please try again."
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.get("/context", status_code=status.HTTP_200_OK)
async def get_user_context(current_user: dict = Depends(require_auth)):
    """
    Get user's context for AI assistant

    IDOR Protection: Returns only current user's context

    Returns summary of user's:
    - Recent ideas
    - Recent images
    - Teams
    - Active projects
    """
    user_id = current_user["id"]

    try:
        context = await gather_user_context(user_id, limit=10)

        return {
            "success": True,
            "context": context
        }

    except Exception as e:
        logger.error(f"Error fetching user context: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch context"
        )


@router.post("/optimize-workflow", status_code=status.HTTP_200_OK)
@limiter.limit("10/hour")
async def optimize_workflow(
    flowchart_request: FlowchartGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Analyze and optimize an existing workflow

    AI analyzes the flowchart and provides:
    - Bottleneck identification
    - Parallelization opportunities
    - Missing steps
    - Efficiency improvements
    - Time estimates

    Rate Limited: 10 requests/hour
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        # Get Gemini service
        gemini_service = get_gemini_service_for_user(user_id)

        # Build optimization prompt
        prompt = f"""
Analyze this workflow and provide optimization suggestions:

WORKFLOW:
{flowchart_request.description}

Provide analysis in JSON format:
{{
    "bottlenecks": [
        {{"step": "<step name>", "issue": "<description>", "solution": "<recommendation>"}}
    ],
    "parallelization": [
        {{"steps": ["<step1>", "<step2>"], "reason": "<why they can be parallel>"}}
    ],
    "missing_steps": [
        {{"after": "<existing step>", "suggestion": "<missing step>", "reason": "<why needed>"}}
    ],
    "efficiency_score": <1-10>,
    "time_estimate": "<estimated duration>",
    "improvements": [
        {{"priority": "<high|medium|low>", "suggestion": "<specific improvement>"}}
    ]
}}
"""

        # Generate optimization
        result = gemini_service.chat(
            message=prompt,
            context=None,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Optimization failed")
            )

        # Parse JSON response
        import json
        import re

        response_text = result["response"]
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(1)

        try:
            analysis = json.loads(response_text)
        except json.JSONDecodeError:
            analysis = {
                "raw_analysis": response_text,
                "parsed": False
            }

        # Audit log
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "gemini_workflow_optimized",
            "success",
            ip_address,
            {"model": result.get("model")}
        )
        conn.commit()

        logger.info(f"Workflow optimized: user_id={user_id}")

        return {
            "success": True,
            "analysis": analysis,
            "model": result.get("model")
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Workflow optimization error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Workflow optimization failed"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)


@router.post("/suggest-next-steps", status_code=status.HTTP_200_OK)
@limiter.limit("20/hour")
async def suggest_next_steps(
    flowchart_request: FlowchartGenerationRequest,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Get smart suggestions for next workflow steps

    AI analyzes current workflow and suggests:
    - Logical next steps
    - Quality checkpoints
    - Backup/contingency plans
    - Best practices

    Rate Limited: 20 requests/hour
    """
    user_id = current_user["id"]
    ip_address = request.client.host if request.client else None
    conn = None

    try:
        gemini_service = get_gemini_service_for_user(user_id)

        prompt = f"""
Based on this workflow, suggest smart next steps and improvements:

CURRENT WORKFLOW:
{flowchart_request.description}

Provide 3-5 actionable suggestions in JSON format:
{{
    "suggestions": [
        {{
            "type": "<checkpoint|step|backup|improvement>",
            "title": "<short title>",
            "description": "<detailed suggestion>",
            "priority": "<high|medium|low>",
            "placement": "<where to add this>"
        }}
    ]
}}
"""

        result = gemini_service.chat(
            message=prompt,
            context=None,
            user_id=user_id,
            ip_address=ip_address
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Suggestions failed")
            )

        # Parse JSON
        import json
        import re

        response_text = result["response"]
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(1)

        try:
            suggestions = json.loads(response_text)
        except json.JSONDecodeError:
            suggestions = {
                "suggestions": [],
                "raw": response_text
            }

        # Audit log
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "gemini_workflow_suggestions",
            "success",
            ip_address,
            {"count": len(suggestions.get("suggestions", []))}
        )
        conn.commit()

        return {
            "success": True,
            "suggestions": suggestions.get("suggestions", []),
            "model": result.get("model")
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Suggestions error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate suggestions"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)
