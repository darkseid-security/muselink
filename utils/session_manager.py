"""
utils/session_manager.py
Secure Server-Side Session Management with Redis + PostgreSQL

Architecture:
- Redis: Fast session cache (temporary storage)
- PostgreSQL: Persistent session backup (audit trail)
- HTTP-only cookies: Secure token transmission
- No client-side storage: Zero XSS exposure

Implements:
- ISO 27001 A.8.5 Secure Authentication
- OWASP Session Management Best Practices
"""

import os
import secrets
import logging
from typing import Optional, Dict
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

# Try to import Redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available, using PostgreSQL-only sessions")

# Session configuration
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


class SessionManager:
    """
    Hybrid session manager using Redis (cache) + PostgreSQL (persistent)

    Redis: Fast lookup, automatic expiration
    PostgreSQL: Audit trail, persistent storage, fallback
    """

    def __init__(self):
        """Initialize Redis connection if available"""
        self.redis_client = None

        if REDIS_AVAILABLE and not REDIS_URL.startswith("memory://"):
            try:
                self.redis_client = redis.from_url(
                    REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                logger.info("Redis session cache connected")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Using PostgreSQL-only sessions")
                self.redis_client = None

    def generate_session_token(self) -> str:
        """
        Generate cryptographically secure session token

        Returns:
            64-character hex token (256 bits of entropy)
        """
        return secrets.token_hex(32)

    def create_session(
        self,
        cursor,
        user_id: int,
        ip_address: str,
        user_agent: str,
        remember_me: bool = False
    ) -> str:
        """
        Create new session in both Redis and PostgreSQL

        Args:
            cursor: Database cursor
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client User-Agent
            remember_me: Extend session to 30 days

        Returns:
            Session token (for HTTP-only cookie)
        """
        # Generate secure token
        session_token = self.generate_session_token()

        # Calculate expiration
        if remember_me:
            expires_hours = 30 * 24  # 30 days
        else:
            expires_hours = SESSION_EXPIRE_HOURS

        expires_at = datetime.now() + timedelta(hours=expires_hours)

        # Store in PostgreSQL (persistent)
        cursor.execute(
            """
            INSERT INTO user_sessions (
                user_id, session_token, ip_address, user_agent,
                expires_at, is_active, created_at, last_activity
            )
            VALUES (%s, %s, %s, %s, %s, TRUE, NOW(), NOW())
            RETURNING id
            """,
            (user_id, session_token, ip_address, user_agent, expires_at)
        )

        session_id = cursor.fetchone()[0]

        # Store in Redis (cache) if available
        if self.redis_client:
            try:
                session_data = {
                    "session_id": session_id,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "expires_at": expires_at.isoformat()
                }

                # Store with TTL matching expiration
                ttl_seconds = int(expires_hours * 3600)
                self.redis_client.setex(
                    f"session:{session_token}",
                    ttl_seconds,
                    json.dumps(session_data)
                )

                logger.info(f"Session created in Redis: user_id={user_id}, ttl={expires_hours}h")
            except Exception as e:
                logger.error(f"Redis session creation failed: {e}")
                # Continue with PostgreSQL-only session

        logger.info(f"Session created: user_id={user_id}, session_id={session_id}")
        return session_token

    def validate_session(self, cursor, session_token: str) -> Optional[Dict]:
        """
        Validate session and return user data

        Lookup order:
        1. Redis (fast cache)
        2. PostgreSQL (fallback + update Redis)

        Args:
            cursor: Database cursor
            session_token: Session token from cookie

        Returns:
            User session data dict or None if invalid
        """
        if not session_token:
            return None

        # Try Redis first (fast path)
        if self.redis_client:
            try:
                redis_data = self.redis_client.get(f"session:{session_token}")
                if redis_data:
                    session_data = json.loads(redis_data)

                    # Verify not expired
                    expires_at = datetime.fromisoformat(session_data["expires_at"])
                    if expires_at > datetime.now():
                        # Update last activity in background (PostgreSQL)
                        try:
                            cursor.execute(
                                "UPDATE user_sessions SET last_activity = NOW() WHERE session_token = %s",
                                (session_token,)
                            )
                        except:
                            pass  # Non-critical

                        logger.debug(f"Session validated from Redis: user_id={session_data['user_id']}")
                        return session_data
            except Exception as e:
                logger.error(f"Redis session lookup failed: {e}")
                # Fall through to PostgreSQL

        # PostgreSQL lookup (slow path / fallback)
        cursor.execute(
            """
            SELECT s.id, s.user_id, s.ip_address, s.expires_at, u.username, u.email
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s
              AND s.is_active = TRUE
              AND s.expires_at > NOW()
            """,
            (session_token,)
        )

        result = cursor.fetchone()

        if not result:
            return None

        session_id, user_id, ip_address, expires_at, username, email = result

        # Update last activity
        cursor.execute(
            "UPDATE user_sessions SET last_activity = NOW() WHERE id = %s",
            (session_id,)
        )

        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "username": username,
            "email": email,
            "ip_address": ip_address,
            "expires_at": expires_at.isoformat()
        }

        # Update Redis cache
        if self.redis_client:
            try:
                ttl_seconds = int((expires_at - datetime.now()).total_seconds())
                if ttl_seconds > 0:
                    self.redis_client.setex(
                        f"session:{session_token}",
                        ttl_seconds,
                        json.dumps(session_data)
                    )
            except:
                pass  # Non-critical

        logger.info(f"Session validated from PostgreSQL: user_id={user_id}")
        return session_data

    def invalidate_session(self, cursor, session_token: str) -> bool:
        """
        Invalidate session (logout)

        Removes from both Redis and PostgreSQL

        Args:
            cursor: Database cursor
            session_token: Session token to invalidate

        Returns:
            True if session was found and invalidated
        """
        if not session_token:
            return False

        # Remove from Redis
        if self.redis_client:
            try:
                self.redis_client.delete(f"session:{session_token}")
            except Exception as e:
                logger.error(f"Redis session deletion failed: {e}")

        # Mark as inactive in PostgreSQL
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE, updated_at = NOW()
            WHERE session_token = %s
            RETURNING user_id
            """,
            (session_token,)
        )

        result = cursor.fetchone()

        if result:
            user_id = result[0]
            logger.info(f"Session invalidated: user_id={user_id}")
            return True

        return False

    def invalidate_all_user_sessions(self, cursor, user_id: int) -> int:
        """
        Invalidate all sessions for a user (e.g., password change)

        Args:
            cursor: Database cursor
            user_id: User ID

        Returns:
            Number of sessions invalidated
        """
        # Get all active session tokens for this user
        cursor.execute(
            """
            SELECT session_token FROM user_sessions
            WHERE user_id = %s AND is_active = TRUE
            """,
            (user_id,)
        )

        tokens = [row[0] for row in cursor.fetchall()]

        # Remove from Redis
        if self.redis_client and tokens:
            try:
                redis_keys = [f"session:{token}" for token in tokens]
                self.redis_client.delete(*redis_keys)
            except Exception as e:
                logger.error(f"Redis bulk delete failed: {e}")

        # Mark all as inactive in PostgreSQL
        cursor.execute(
            """
            UPDATE user_sessions
            SET is_active = FALSE, updated_at = NOW()
            WHERE user_id = %s AND is_active = TRUE
            """,
            (user_id,)
        )

        count = cursor.rowcount
        logger.info(f"Invalidated {count} sessions for user_id={user_id}")
        return count

    def cleanup_expired_sessions(self, cursor) -> int:
        """
        Clean up expired sessions from PostgreSQL
        Redis handles expiration automatically

        Args:
            cursor: Database cursor

        Returns:
            Number of sessions cleaned up
        """
        cursor.execute(
            """
            DELETE FROM user_sessions
            WHERE expires_at < NOW() - INTERVAL '7 days'
            """
        )

        count = cursor.rowcount
        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions from PostgreSQL")

        return count


# Global session manager instance
session_manager = SessionManager()
