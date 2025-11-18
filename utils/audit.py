"""
utils/audit.py
Audit logging utilities for security events tracking
"""

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

def log_audit_event(
    cursor,
    user_id: Optional[int],
    action: str,
    status: str,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Log security audit event to database
    
    Args:
        cursor: Database cursor
        user_id: ID of user performing action (None for anonymous)
        action: Action being performed (e.g., 'login', 'logout', 'password_change')
        status: 'success' or 'failed'
        ip_address: IP address of client (anonymized if privacy mode enabled)
        details: Additional details as dictionary (will be stored as JSONB)
        
    Returns:
        True if logged successfully, False otherwise
    """
    try:
        # Validate status
        if status not in ['success', 'failed']:
            logger.error(f"Invalid audit status: {status}")
            return False
        
        # Anonymize IP if needed (remove last octet for IPv4)
        if ip_address and should_anonymize_ip():
            parts = ip_address.rsplit('.', 1)
            if len(parts) == 2:
                ip_address = f"{parts[0]}.0"  # Use .0 instead of .xxx for valid inet type
        
        # Insert audit log
        cursor.execute(
            """
            INSERT INTO audit_logs (
                user_id, action, status, ip_address, details
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user_id,
                action,
                status,
                ip_address,
                json.dumps(details) if details else None
            )
        )
        
        # Also log to application logs (without sensitive data)
        log_message = f"Audit: {action} - Status: {status}"
        if user_id:
            log_message += f" - User ID: {user_id}"
        
        if status == 'success':
            logger.info(log_message)
        else:
            logger.warning(log_message)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
        return False

def should_anonymize_ip() -> bool:
    """
    Check if IP addresses should be anonymized
    Based on privacy configuration
    
    Returns:
        True if IPs should be anonymized
    """
    import os
    return os.getenv('ANONYMIZE_IPS', 'true').lower() == 'true'

def get_audit_logs(
    cursor,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> list:
    """
    Retrieve audit logs with filters
    
    Args:
        cursor: Database cursor
        user_id: Filter by user ID
        action: Filter by action type
        status: Filter by status
        limit: Maximum number of records to return
        offset: Number of records to skip
        
    Returns:
        List of audit log dictionaries
    """
    try:
        query = """
            SELECT id, user_id, action, status, ip_address, 
                   details, created_at
            FROM audit_logs
            WHERE 1=1
        """
        params = []
        
        if user_id is not None:
            query += " AND user_id = %s"
            params.append(user_id)
        
        if action:
            query += " AND action = %s"
            params.append(action)
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0],
                'user_id': row[1],
                'action': row[2],
                'status': row[3],
                'ip_address': row[4],
                'details': row[5],
                'created_at': row[6].isoformat() if row[6] else None
            })
        
        return logs
        
    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}")
        return []

def get_user_activity_summary(cursor, user_id: int, days: int = 30) -> Dict[str, Any]:
    """
    Get summary of user activity for the specified period
    
    Args:
        cursor: Database cursor
        user_id: User ID
        days: Number of days to look back
        
    Returns:
        Dictionary with activity summary
    """
    try:
        query = """
            SELECT 
                COUNT(*) as total_actions,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_actions,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_actions,
                COUNT(DISTINCT DATE(created_at)) as active_days,
                MAX(created_at) as last_activity
            FROM audit_logs
            WHERE user_id = %s
              AND created_at >= NOW() - INTERVAL '%s days'
        """
        
        cursor.execute(query, (user_id, days))
        
        result = cursor.fetchone()
        
        return {
            'total_actions': result[0] or 0,
            'successful_actions': result[1] or 0,
            'failed_actions': result[2] or 0,
            'active_days': result[3] or 0,
            'last_activity': result[4].isoformat() if result[4] else None,
            'period_days': days
        }
        
    except Exception as e:
        logger.error(f"Failed to get activity summary: {e}")
        return {
            'total_actions': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'active_days': 0,
            'last_activity': None,
            'period_days': days
        }

def get_failed_login_attempts(cursor, user_id: int, hours: int = 24) -> int:
    """
    Get count of failed login attempts in the specified time period
    
    Args:
        cursor: Database cursor
        user_id: User ID
        hours: Number of hours to look back
        
    Returns:
        Count of failed login attempts
    """
    try:
        query = """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE user_id = %s
              AND action = 'login_failed'
              AND status = 'failed'
              AND created_at >= NOW() - INTERVAL '%s hours'
        """
        
        cursor.execute(query, (user_id, hours))
        return cursor.fetchone()[0] or 0
        
    except Exception as e:
        logger.error(f"Failed to get failed login attempts: {e}")
        return 0

def clean_old_audit_logs(cursor, days_to_keep: int = 90) -> int:
    """
    Clean audit logs older than specified days
    Should be run periodically as a maintenance task
    
    Args:
        cursor: Database cursor
        days_to_keep: Number of days of logs to retain
        
    Returns:
        Number of records deleted
    """
    try:
        query = """
            DELETE FROM audit_logs
            WHERE created_at < NOW() - INTERVAL '%s days'
        """
        
        cursor.execute(query, (days_to_keep,))
        return cursor.rowcount
        
    except Exception as e:
        logger.error(f"Failed to clean audit logs: {e}")
        return 0

def detect_suspicious_activity(cursor, user_id: int, threshold: int = 5) -> Dict[str, Any]:
    """
    Detect suspicious activity patterns for a user
    
    Args:
        cursor: Database cursor
        user_id: User ID to check
        threshold: Number of failed attempts to consider suspicious
        
    Returns:
        Dictionary with suspicious activity indicators
    """
    try:
        # Check failed logins in last hour
        query = """
            SELECT COUNT(*) as failed_count,
                   COUNT(DISTINCT ip_address) as unique_ips
            FROM audit_logs
            WHERE user_id = %s
              AND action IN ('login_failed', 'invalid_token')
              AND created_at >= NOW() - INTERVAL '1 hour'
        """
        
        cursor.execute(query, (user_id,))
        failed_count, unique_ips = cursor.fetchone()
        
        is_suspicious = failed_count >= threshold or unique_ips >= 3
        
        return {
            'is_suspicious': is_suspicious,
            'failed_attempts_last_hour': failed_count or 0,
            'unique_ips_last_hour': unique_ips or 0,
            'threshold': threshold,
            'recommendation': 'Account lockout recommended' if is_suspicious else 'Activity normal'
        }
        
    except Exception as e:
        logger.error(f"Failed to detect suspicious activity: {e}")
        return {
            'is_suspicious': False,
            'failed_attempts_last_hour': 0,
            'unique_ips_last_hour': 0,
            'threshold': threshold,
            'recommendation': 'Unable to analyze'
        }

# Action types constants for consistency
class AuditAction:
    """Standard audit action types"""
    # Authentication
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILED = 'login_failed'
    LOGOUT = 'logout'
    
    # Registration
    USER_REGISTERED = 'user_registered'
    EMAIL_VERIFIED = 'email_verified'
    
    # Password management
    PASSWORD_CHANGED = 'password_changed'
    PASSWORD_RESET_REQUESTED = 'password_reset_requested'
    PASSWORD_RESET_COMPLETED = 'password_reset_completed'

    # Email management
    EMAIL_CHANGED = 'email_changed'

    # MFA
    MFA_ENABLED = 'mfa_enabled'
    MFA_DISABLED = 'mfa_disabled'
    MFA_VERIFIED = 'mfa_verified'
    
    # Account management
    ACCOUNT_SUSPENDED = 'account_suspended'
    ACCOUNT_REACTIVATED = 'account_reactivated'
    ACCOUNT_DELETED = 'account_deleted'
    
    # Creative content
    CREATIVE_BRIEF_SUBMITTED = 'creative_brief_submitted'
    DRAFT_GENERATED = 'draft_generated'
    DRAFT_REFINED = 'draft_refined'
    DRAFT_APPROVED = 'draft_approved'
    DRAFT_FEEDBACK_SUBMITTED = 'draft_feedback_submitted'
    
    # Admin actions
    ADMIN_USER_CREATED = 'admin_user_created'
    ADMIN_USER_UPDATED = 'admin_user_updated'
    ADMIN_USER_DELETED = 'admin_user_deleted'
    ADMIN_SETTINGS_CHANGED = 'admin_settings_changed'
    
    # Security events
    INVALID_TOKEN = 'invalid_token'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded'
    INTRUSION_ATTEMPT = 'intrusion_attempt'

    # Messages
    MESSAGE_SENT = 'message_sent'
    MESSAGE_READ = 'message_read'
    MESSAGE_DELETED = 'message_deleted'