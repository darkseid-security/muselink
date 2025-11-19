"""
utils/security_monitor.py
Security Monitoring and Alerting System

Tracks and alerts on:
- IDOR probing attempts (multiple 404s on resources)
- Rate limit violations
- Malicious file upload attempts
- Suspicious activity patterns

Implements ISO 27001 A.12.4 Logging and Monitoring
"""

import logging
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from collections import defaultdict
import threading
from database.connection import get_db_connection, return_db_connection
from utils.audit import log_audit_event

logger = logging.getLogger(__name__)

# Thread-safe counters for tracking security events
_event_tracker = defaultdict(lambda: defaultdict(int))
_event_tracker_lock = threading.Lock()

# Alert thresholds
IDOR_PROBE_THRESHOLD = 5  # 5 failed resource access attempts in window
RATE_LIMIT_THRESHOLD = 3  # 3 rate limit hits in window
FILE_UPLOAD_THRESHOLD = 3  # 3 malicious file uploads in window
ALERT_WINDOW_MINUTES = 15  # Time window for counting events

# Alert cooldown to prevent spam
_alert_cooldown = {}
ALERT_COOLDOWN_MINUTES = 60  # Don't re-alert for same user/IP for 60 mins


class SecurityAlert:
    """Security alert data model"""

    def __init__(
        self,
        alert_type: str,
        severity: str,
        user_id: Optional[int],
        ip_address: Optional[str],
        description: str,
        event_count: int,
        metadata: Optional[Dict] = None
    ):
        self.alert_type = alert_type
        self.severity = severity
        self.user_id = user_id
        self.ip_address = ip_address
        self.description = description
        self.event_count = event_count
        self.metadata = metadata or {}
        self.timestamp = datetime.now()


def track_idor_attempt(
    user_id: Optional[int],
    ip_address: Optional[str],
    resource_type: str,
    resource_id: int,
    endpoint: str
) -> Optional[SecurityAlert]:
    """
    Track IDOR probing attempt (404 on resource access)

    Args:
        user_id: User attempting access (None if unauthenticated)
        ip_address: Client IP address
        resource_type: Type of resource (message, file, note, etc.)
        resource_id: ID of resource attempted
        endpoint: API endpoint

    Returns:
        SecurityAlert if threshold exceeded, None otherwise
    """
    # Create tracking key
    key = f"idor:{user_id or 'anon'}:{ip_address}"

    with _event_tracker_lock:
        _event_tracker[key]['count'] += 1
        _event_tracker[key]['last_seen'] = datetime.now()
        _event_tracker[key]['resources'] = _event_tracker[key].get('resources', set())
        _event_tracker[key]['resources'].add(f"{resource_type}:{resource_id}")

        count = _event_tracker[key]['count']

    # Log to database
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "idor_attempt",
            "failed",
            ip_address,
            {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "endpoint": endpoint
            }
        )

        conn.commit()
    except Exception as e:
        logger.error(f"Failed to log IDOR attempt: {e}")
    finally:
        if conn:
            return_db_connection(conn)

    # Check threshold
    if count >= IDOR_PROBE_THRESHOLD:
        if not _should_alert(key, "idor"):
            return None

        alert = SecurityAlert(
            alert_type="idor_probing",
            severity="high",
            user_id=user_id,
            ip_address=ip_address,
            description=f"Potential IDOR probing: {count} failed resource access attempts",
            event_count=count,
            metadata={
                "resource_type": resource_type,
                "unique_resources": len(_event_tracker[key]['resources']),
                "endpoint": endpoint
            }
        )

        _record_alert(alert)
        _set_alert_cooldown(key, "idor")

        logger.warning(
            f"IDOR PROBING DETECTED: user_id={user_id}, ip={ip_address}, "
            f"count={count}, resources={len(_event_tracker[key]['resources'])}"
        )

        return alert

    return None


def track_rate_limit_violation(
    user_id: Optional[int],
    ip_address: Optional[str],
    endpoint: str,
    limit: str
) -> Optional[SecurityAlert]:
    """
    Track rate limit violation

    Args:
        user_id: User violating rate limit
        ip_address: Client IP address
        endpoint: API endpoint
        limit: Rate limit that was exceeded (e.g., "5/minute")

    Returns:
        SecurityAlert if threshold exceeded, None otherwise
    """
    key = f"ratelimit:{user_id or 'anon'}:{ip_address}"

    with _event_tracker_lock:
        _event_tracker[key]['count'] += 1
        _event_tracker[key]['last_seen'] = datetime.now()
        _event_tracker[key]['endpoints'] = _event_tracker[key].get('endpoints', set())
        _event_tracker[key]['endpoints'].add(endpoint)

        count = _event_tracker[key]['count']

    # Log to database
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        log_audit_event(
            cursor,
            user_id,
            "rate_limit_exceeded",
            "failed",
            ip_address,
            {
                "endpoint": endpoint,
                "limit": limit
            }
        )

        conn.commit()
    except Exception as e:
        logger.error(f"Failed to log rate limit violation: {e}")
    finally:
        if conn:
            return_db_connection(conn)

    # Check threshold
    if count >= RATE_LIMIT_THRESHOLD:
        if not _should_alert(key, "ratelimit"):
            return None

        alert = SecurityAlert(
            alert_type="rate_limit_abuse",
            severity="medium",
            user_id=user_id,
            ip_address=ip_address,
            description=f"Repeated rate limit violations: {count} violations in {ALERT_WINDOW_MINUTES} minutes",
            event_count=count,
            metadata={
                "endpoint": endpoint,
                "limit": limit,
                "unique_endpoints": len(_event_tracker[key]['endpoints'])
            }
        )

        _record_alert(alert)
        _set_alert_cooldown(key, "ratelimit")

        logger.warning(
            f"RATE LIMIT ABUSE DETECTED: user_id={user_id}, ip={ip_address}, "
            f"count={count}, endpoints={_event_tracker[key]['endpoints']}"
        )

        return alert

    return None


def track_malicious_file_upload(
    user_id: int,
    ip_address: Optional[str],
    filename: str,
    attack_type: str,
    pattern: str
) -> Optional[SecurityAlert]:
    """
    Track malicious file upload attempt

    Args:
        user_id: User attempting upload
        ip_address: Client IP address
        filename: Name of malicious file
        attack_type: Type of attack detected
        pattern: Specific pattern that triggered detection

    Returns:
        SecurityAlert if threshold exceeded, None otherwise
    """
    key = f"fileupload:{user_id}:{ip_address}"

    with _event_tracker_lock:
        _event_tracker[key]['count'] += 1
        _event_tracker[key]['last_seen'] = datetime.now()
        _event_tracker[key]['attack_types'] = _event_tracker[key].get('attack_types', set())
        _event_tracker[key]['attack_types'].add(attack_type)

        count = _event_tracker[key]['count']

    # Already logged to security_incidents table by file validator
    # Just check threshold for alerting

    if count >= FILE_UPLOAD_THRESHOLD:
        if not _should_alert(key, "fileupload"):
            return None

        alert = SecurityAlert(
            alert_type="malicious_file_uploads",
            severity="high",
            user_id=user_id,
            ip_address=ip_address,
            description=f"Multiple malicious file uploads: {count} attempts in {ALERT_WINDOW_MINUTES} minutes",
            event_count=count,
            metadata={
                "filename": filename,
                "attack_type": attack_type,
                "pattern": pattern,
                "unique_attack_types": len(_event_tracker[key]['attack_types'])
            }
        )

        _record_alert(alert)
        _set_alert_cooldown(key, "fileupload")

        logger.warning(
            f"MALICIOUS FILE UPLOAD ATTACK DETECTED: user_id={user_id}, ip={ip_address}, "
            f"count={count}, attack_types={_event_tracker[key]['attack_types']}"
        )

        return alert

    return None


def _should_alert(key: str, alert_type: str) -> bool:
    """
    Check if we should send alert (respects cooldown period)

    Args:
        key: Tracking key
        alert_type: Type of alert

    Returns:
        True if should alert, False if in cooldown
    """
    cooldown_key = f"{key}:{alert_type}"

    if cooldown_key in _alert_cooldown:
        last_alert = _alert_cooldown[cooldown_key]
        if datetime.now() - last_alert < timedelta(minutes=ALERT_COOLDOWN_MINUTES):
            return False

    return True


def _set_alert_cooldown(key: str, alert_type: str):
    """Set alert cooldown timestamp"""
    cooldown_key = f"{key}:{alert_type}"
    _alert_cooldown[cooldown_key] = datetime.now()


def _record_alert(alert: SecurityAlert):
    """
    Record security alert to database

    Args:
        alert: SecurityAlert to record
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO security_incidents (
                user_id, ip_address, attack_type, severity,
                pattern, endpoint, metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                alert.user_id,
                alert.ip_address,
                alert.alert_type,
                alert.severity,
                alert.description,
                alert.metadata.get('endpoint', 'N/A'),
                str(alert.metadata)
            )
        )

        conn.commit()
        logger.info(f"Security alert recorded: {alert.alert_type}")

    except Exception as e:
        logger.error(f"Failed to record security alert: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            return_db_connection(conn)


def cleanup_old_trackers():
    """
    Clean up old event trackers (called periodically by scheduler)

    Removes trackers that haven't been updated in ALERT_WINDOW_MINUTES
    """
    cutoff = datetime.now() - timedelta(minutes=ALERT_WINDOW_MINUTES)

    with _event_tracker_lock:
        keys_to_delete = []

        for key, data in _event_tracker.items():
            last_seen = data.get('last_seen')
            if last_seen and last_seen < cutoff:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del _event_tracker[key]

        if keys_to_delete:
            logger.info(f"Cleaned up {len(keys_to_delete)} old security trackers")


def get_active_alerts() -> List[Dict]:
    """
    Get currently active security trackers (for monitoring dashboard)

    Returns:
        List of active security events being tracked
    """
    with _event_tracker_lock:
        alerts = []

        for key, data in _event_tracker.items():
            parts = key.split(':')
            alert_type = parts[0]
            user_id = parts[1] if parts[1] != 'anon' else None
            ip_address = parts[2] if len(parts) > 2 else None

            alerts.append({
                "alert_type": alert_type,
                "user_id": user_id,
                "ip_address": ip_address,
                "count": data['count'],
                "last_seen": data['last_seen'],
                "metadata": {
                    k: list(v) if isinstance(v, set) else v
                    for k, v in data.items()
                    if k not in ['count', 'last_seen']
                }
            })

        return alerts


def send_alert_notification(alert: SecurityAlert):
    """
    Send alert notification (email, Slack, PagerDuty, etc.)

    Args:
        alert: SecurityAlert to send

    Note: This is a placeholder. Integrate with your notification system.
    """
    # TODO: Integrate with notification service
    # Examples:
    # - Send email to security team
    # - Post to Slack security channel
    # - Create PagerDuty incident
    # - Trigger SIEM integration

    logger.critical(
        f"SECURITY ALERT [{alert.severity.upper()}]: {alert.alert_type}\n"
        f"Description: {alert.description}\n"
        f"User ID: {alert.user_id}\n"
        f"IP Address: {alert.ip_address}\n"
        f"Event Count: {alert.event_count}\n"
        f"Metadata: {alert.metadata}\n"
        f"Timestamp: {alert.timestamp}"
    )

    # Example: Send email (uncomment and configure)
    # from utils.email_service import send_security_alert_email
    # send_security_alert_email(alert)

    # Example: Post to Slack (uncomment and configure)
    # from utils.slack import post_security_alert
    # post_security_alert(alert)
