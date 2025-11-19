"""
routers/creative.py
Creative content generation router for AI Draft Generator
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import json
import secrets
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.connection import get_db_connection, return_db_connection
from utils.security import verify_session_token
from utils.audit import log_audit_event
from utils.auth_dependencies import require_auth, require_admin
from utils.input_sanitizer import (
    comprehensive_input_scan,
    log_malicious_input
)

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Enums

class ContentType(str, Enum):
    """Types of creative content"""
    COPYWRITING = "copywriting"
    SCRIPT = "script"
    STORYBOARD = "storyboard"
    SOCIAL_MEDIA = "social_media"
    EMAIL_CAMPAIGN = "email_campaign"

class ToneVoice(str, Enum):
    """Tone and voice options"""
    PROFESSIONAL = "professional"
    CASUAL = "casual"
    FRIENDLY = "friendly"
    AUTHORITATIVE = "authoritative"
    PLAYFUL = "playful"
    INSPIRATIONAL = "inspirational"

class DraftStatus(str, Enum):
    """Draft status"""
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PUBLISHED = "published"

# Pydantic Models

class BrandGuidelines(BaseModel):
    """Brand guidelines for content generation"""
    brand_name: str = Field(..., max_length=200)
    industry: str = Field(..., max_length=100)
    target_audience: str = Field(..., max_length=500)
    tone_voice: ToneVoice
    key_values: List[str] = Field(..., max_items=10)
    dos: Optional[List[str]] = Field(None, max_items=10)
    donts: Optional[List[str]] = Field(None, max_items=10)
    
    @validator('key_values', 'dos', 'donts')
    def validate_list_items(cls, v):
        if v:
            for item in v:
                if len(item) > 200:
                    raise ValueError('List items must be under 200 characters')
        return v

class CreativeBrief(BaseModel):
    """Creative brief for content generation"""
    content_type: ContentType
    title: str = Field(..., min_length=3, max_length=200)
    objective: str = Field(..., min_length=10, max_length=1000)
    key_messages: List[str] = Field(..., min_items=1, max_items=5)
    target_audience: str = Field(..., max_length=500)
    tone_voice: ToneVoice
    word_count: Optional[int] = Field(None, ge=50, le=10000)
    additional_context: Optional[str] = Field(None, max_length=2000)
    brand_guidelines: Optional[BrandGuidelines] = None
    
    @validator('key_messages')
    def validate_messages(cls, v):
        for msg in v:
            if len(msg) > 300:
                raise ValueError('Key messages must be under 300 characters')
        return v

class DraftSelection(BaseModel):
    """Draft selection for refinement"""
    draft_ids: List[int] = Field(..., min_items=1, max_items=5)
    refinement_notes: Optional[str] = Field(None, max_length=1000)

class DraftFeedback(BaseModel):
    """Feedback on generated draft"""
    draft_id: int
    rating: int = Field(..., ge=1, le=5)
    feedback_text: Optional[str] = Field(None, max_length=2000)
    approved: bool = False

# Helper Functions

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify user session and return user_id"""
    token = credentials.credentials
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user_id = verify_session_token(cursor, token)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        return user_id
        
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

def generate_mock_drafts(brief: CreativeBrief, count: int = 10) -> List[Dict[str, Any]]:
    """
    Generate mock AI drafts (placeholder for actual AI integration)
    In production, this would call your AI model
    """
    drafts = []
    
    for i in range(count):
        draft = {
            "variation_number": i + 1,
            "direction": f"Creative Direction {i + 1}",
            "content": f"""
# {brief.title} - Variation {i + 1}

## Objective
{brief.objective}

## Target Audience
{brief.target_audience}

## Key Messages
{', '.join(brief.key_messages)}

## Draft Content
[AI-generated {brief.content_type.value} content would appear here]

This is a mock draft demonstrating the structure. In production, this would contain
AI-generated creative content based on the brief parameters, brand guidelines,
and tone of voice specified.

Tone: {brief.tone_voice.value}
Word Count Target: {brief.word_count or 'Not specified'}

Additional Context Considered:
{brief.additional_context or 'None provided'}
            """.strip(),
            "word_count": brief.word_count or 500,
            "tone_analysis": {
                "detected_tone": brief.tone_voice.value,
                "confidence": 0.85 + (i * 0.01)
            }
        }
        drafts.append(draft)
    
    return drafts

# Endpoints

@router.post("/brief", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
async def submit_creative_brief(
    brief: CreativeBrief,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Submit a creative brief and generate multiple draft variations
    Rate limited to prevent abuse
    """
    user_id = current_user["id"]
    conn = None

    try:
        # Scan title for malicious input
        is_malicious, attack_type, pattern = comprehensive_input_scan(brief.title)
        if is_malicious:
            log_malicious_input(
                user_id=user_id,
                input_value=brief.title,
                attack_type=attack_type,
                pattern=pattern,
                ip_address=request.client.host if request.client else None,
                endpoint="/api/v1/creative/brief",
                severity="medium"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected in title"
            )

        # Scan objective
        is_malicious, attack_type, pattern = comprehensive_input_scan(brief.objective)
        if is_malicious:
            log_malicious_input(
                user_id=user_id,
                input_value=brief.objective,
                attack_type=attack_type,
                pattern=pattern,
                ip_address=request.client.host if request.client else None,
                endpoint="/api/v1/creative/brief",
                severity="medium"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected in objective"
            )

        # Scan key messages
        for idx, message in enumerate(brief.key_messages):
            is_malicious, attack_type, pattern = comprehensive_input_scan(message)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=message,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/brief",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Malicious input detected in key message {idx + 1}"
                )

        # Scan target audience
        is_malicious, attack_type, pattern = comprehensive_input_scan(brief.target_audience)
        if is_malicious:
            log_malicious_input(
                user_id=user_id,
                input_value=brief.target_audience,
                attack_type=attack_type,
                pattern=pattern,
                ip_address=request.client.host if request.client else None,
                endpoint="/api/v1/creative/brief",
                severity="medium"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected in target audience"
            )

        # Scan additional context if provided
        if brief.additional_context:
            is_malicious, attack_type, pattern = comprehensive_input_scan(brief.additional_context)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=brief.additional_context,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/brief",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in additional context"
                )

        # Scan brand guidelines if provided
        if brief.brand_guidelines:
            # Scan brand name
            is_malicious, attack_type, pattern = comprehensive_input_scan(brief.brand_guidelines.brand_name)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=brief.brand_guidelines.brand_name,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/brief",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in brand name"
                )

            # Scan industry
            is_malicious, attack_type, pattern = comprehensive_input_scan(brief.brand_guidelines.industry)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=brief.brand_guidelines.industry,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/brief",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in industry"
                )

            # Scan brand target audience
            is_malicious, attack_type, pattern = comprehensive_input_scan(brief.brand_guidelines.target_audience)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=brief.brand_guidelines.target_audience,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/brief",
                    severity="medium"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in brand target audience"
                )

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Store the brief
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS creative_briefs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content_type VARCHAR(50) NOT NULL,
                title VARCHAR(200) NOT NULL,
                objective TEXT NOT NULL,
                key_messages JSONB NOT NULL,
                target_audience TEXT NOT NULL,
                tone_voice VARCHAR(50) NOT NULL,
                word_count INTEGER,
                additional_context TEXT,
                brand_guidelines JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        cursor.execute(
            """
            INSERT INTO creative_briefs (
                user_id, content_type, title, objective, key_messages,
                target_audience, tone_voice, word_count, additional_context,
                brand_guidelines
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                brief.content_type.value,
                brief.title,
                brief.objective,
                json.dumps(brief.key_messages),
                brief.target_audience,
                brief.tone_voice.value,
                brief.word_count,
                brief.additional_context,
                json.dumps(brief.brand_guidelines.dict()) if brief.brand_guidelines else None
            )
        )
        
        brief_id = cursor.fetchone()[0]
        
        # Generate drafts (mock for now)
        drafts = generate_mock_drafts(brief, count=10)
        
        # Store generated drafts
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS generated_drafts (
                id SERIAL PRIMARY KEY,
                brief_id INTEGER NOT NULL REFERENCES creative_briefs(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                variation_number INTEGER NOT NULL,
                direction VARCHAR(200),
                content TEXT NOT NULL,
                word_count INTEGER,
                tone_analysis JSONB,
                status VARCHAR(50) DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        draft_ids = []
        for draft in drafts:
            cursor.execute(
                """
                INSERT INTO generated_drafts (
                    brief_id, user_id, variation_number, direction,
                    content, word_count, tone_analysis
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    brief_id,
                    user_id,
                    draft['variation_number'],
                    draft['direction'],
                    draft['content'],
                    draft['word_count'],
                    json.dumps(draft['tone_analysis'])
                )
            )
            draft_ids.append(cursor.fetchone()[0])
        
        # Log activity
        log_audit_event(
            cursor, user_id, "creative_brief_submitted", "success",
            None, {"brief_id": brief_id, "content_type": brief.content_type.value}
        )
        
        conn.commit()
        
        logger.info(f"Creative brief {brief_id} created by user {user_id}")
        
        return {
            "message": "Creative brief submitted and drafts generated",
            "brief_id": brief_id,
            "drafts_generated": len(draft_ids),
            "draft_ids": draft_ids
        }
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Brief submission error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process creative brief"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/briefs")
async def get_my_briefs(
    current_user: dict = Depends(require_auth),
    limit: int = 20,
    offset: int = 0
):
    """Get user's creative briefs"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, content_type, title, objective, created_at
            FROM creative_briefs
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )
        
        briefs = []
        for row in cursor.fetchall():
            briefs.append({
                "id": row[0],
                "content_type": row[1],
                "title": row[2],
                "objective": row[3],
                "created_at": row[4].isoformat()
            })
        
        return {
            "briefs": briefs,
            "total": len(briefs)
        }
        
    except Exception as e:
        logger.error(f"Error fetching briefs: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch briefs"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/brief/{brief_id}/drafts")
async def get_brief_drafts(
    brief_id: int,
    current_user: dict = Depends(require_auth)
):
    """Get all drafts for a specific brief"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute(
            "SELECT user_id FROM creative_briefs WHERE id = %s",
            (brief_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Brief not found"
            )
        
        if result[0] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get drafts
        cursor.execute(
            """
            SELECT id, variation_number, direction, content, 
                   word_count, tone_analysis, status, created_at
            FROM generated_drafts
            WHERE brief_id = %s
            ORDER BY variation_number
            """,
            (brief_id,)
        )
        
        drafts = []
        for row in cursor.fetchall():
            drafts.append({
                "id": row[0],
                "variation_number": row[1],
                "direction": row[2],
                "content": row[3],
                "word_count": row[4],
                "tone_analysis": row[5],
                "status": row[6],
                "created_at": row[7].isoformat()
            })
        
        return {
            "brief_id": brief_id,
            "drafts": drafts,
            "total": len(drafts)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching drafts: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch drafts"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/draft/{draft_id}")
async def get_draft_detail(
    draft_id: int,
    current_user: dict = Depends(require_auth)
):
    """Get detailed view of a specific draft"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT d.id, d.brief_id, d.variation_number, d.direction,
                   d.content, d.word_count, d.tone_analysis, d.status,
                   d.created_at, d.updated_at, d.user_id
            FROM generated_drafts d
            WHERE d.id = %s
            """,
            (draft_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Draft not found"
            )
        
        # Verify ownership
        if result[10] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        draft = {
            "id": result[0],
            "brief_id": result[1],
            "variation_number": result[2],
            "direction": result[3],
            "content": result[4],
            "word_count": result[5],
            "tone_analysis": result[6],
            "status": result[7],
            "created_at": result[8].isoformat(),
            "updated_at": result[9].isoformat()
        }
        
        return draft
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching draft: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch draft"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/draft/{draft_id}/refine")
@limiter.limit("20/hour")
async def refine_draft(
    draft_id: int,
    refinement_notes: str,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """
    Request AI refinement of a selected draft
    Rate limited
    """
    user_id = current_user["id"]
    conn = None

    try:
        # Scan refinement notes for malicious input
        is_malicious, attack_type, pattern = comprehensive_input_scan(refinement_notes)
        if is_malicious:
            log_malicious_input(
                user_id=user_id,
                input_value=refinement_notes,
                attack_type=attack_type,
                pattern=pattern,
                ip_address=request.client.host if request.client else None,
                endpoint="/api/v1/creative/draft/refine",
                severity="medium"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected in refinement notes"
            )

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute(
            "SELECT user_id, content FROM generated_drafts WHERE id = %s",
            (draft_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Draft not found"
            )
        
        if result[0] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        original_content = result[1]
        
        # Generate refined version (mock)
        refined_content = f"{original_content}\n\n---\n[REFINED VERSION]\n\nRefinement Notes Applied: {refinement_notes}\n\n[AI-refined content would appear here based on your feedback]"
        
        # Update draft
        cursor.execute(
            """
            UPDATE generated_drafts
            SET content = %s, updated_at = NOW(), status = 'in_review'
            WHERE id = %s
            """,
            (refined_content, draft_id)
        )
        
        log_audit_event(
            cursor, user_id, "draft_refined", "success",
            None, {"draft_id": draft_id}
        )
        
        conn.commit()
        
        return {
            "message": "Draft refined successfully",
            "draft_id": draft_id,
            "status": "in_review"
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Draft refinement error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refine draft"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.post("/draft/feedback")
async def submit_feedback(
    feedback: DraftFeedback,
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Submit feedback and rating for a draft"""
    user_id = current_user["id"]
    conn = None

    try:
        # Scan feedback text for malicious input if provided
        if feedback.feedback_text:
            is_malicious, attack_type, pattern = comprehensive_input_scan(feedback.feedback_text)
            if is_malicious:
                log_malicious_input(
                    user_id=user_id,
                    input_value=feedback.feedback_text,
                    attack_type=attack_type,
                    pattern=pattern,
                    ip_address=request.client.host if request.client else None,
                    endpoint="/api/v1/creative/draft/feedback",
                    severity="low"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Malicious input detected in feedback text"
                )

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute(
            "SELECT user_id FROM generated_drafts WHERE id = %s",
            (feedback.draft_id,)
        )
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Draft not found"
            )
        
        if result[0] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Store feedback
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS draft_feedback (
                id SERIAL PRIMARY KEY,
                draft_id INTEGER NOT NULL REFERENCES generated_drafts(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                feedback_text TEXT,
                approved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        cursor.execute(
            """
            INSERT INTO draft_feedback (draft_id, user_id, rating, feedback_text, approved)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (feedback.draft_id, user_id, feedback.rating, feedback.feedback_text, feedback.approved)
        )
        
        feedback_id = cursor.fetchone()[0]
        
        # Update draft status if approved
        if feedback.approved:
            cursor.execute(
                """
                UPDATE generated_drafts
                SET status = 'approved', updated_at = NOW()
                WHERE id = %s
                """,
                (feedback.draft_id,)
            )
        
        log_audit_event(
            cursor, user_id, "draft_feedback_submitted", "success",
            None, {"draft_id": feedback.draft_id, "rating": feedback.rating}
        )
        
        conn.commit()
        
        return {
            "message": "Feedback submitted successfully",
            "feedback_id": feedback_id
        }
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Feedback submission error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)

@router.get("/analytics")
async def get_user_analytics(current_user: dict = Depends(require_auth)):
    """Get analytics for user's creative activity"""
    user_id = current_user["id"]
    conn = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Count briefs
        cursor.execute(
            "SELECT COUNT(*) FROM creative_briefs WHERE user_id = %s",
            (user_id,)
        )
        total_briefs = cursor.fetchone()[0]
        
        # Count drafts
        cursor.execute(
            "SELECT COUNT(*) FROM generated_drafts WHERE user_id = %s",
            (user_id,)
        )
        total_drafts = cursor.fetchone()[0]
        
        # Count approved drafts
        cursor.execute(
            "SELECT COUNT(*) FROM generated_drafts WHERE user_id = %s AND status = 'approved'",
            (user_id,)
        )
        approved_drafts = cursor.fetchone()[0]
        
        # Average rating
        cursor.execute(
            """
            SELECT AVG(rating)
            FROM draft_feedback
            WHERE user_id = %s
            """,
            (user_id,)
        )
        avg_rating = cursor.fetchone()[0] or 0
        
        return {
            "total_briefs": total_briefs,
            "total_drafts": total_drafts,
            "approved_drafts": approved_drafts,
            "average_rating": float(avg_rating),
            "approval_rate": (approved_drafts / total_drafts * 100) if total_drafts > 0 else 0
        }
        
    except Exception as e:
        logger.error(f"Analytics error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch analytics"
        )
    finally:
        if conn:
            cursor.close()
            return_db_connection(conn)