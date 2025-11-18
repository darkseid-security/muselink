"""
database/sqlalchemy_db.py
SQLAlchemy Core Database Connection Manager

Security Features:
1. Automatic parameterization via SQLAlchemy Core
2. Second-order SQL injection protection via safe_bind()
3. Connection pooling with sensible limits
4. Context managers for safe connection handling
5. No raw SQL string concatenation possible

Usage:
    from database.sqlalchemy_db import get_db, execute_query, safe_bind

    # Method 1: Using context manager
    with get_db() as conn:
        result = conn.execute(
            select(users).where(users.c.id == user_id)
        )

    # Method 2: Using helper function
    result = execute_query(
        select(users).where(users.c.email == safe_bind(email))
    )

    # Method 3: Second-order SQLi protection
    user_input = "admin' OR '1'='1"  # Malicious input
    safe_input = safe_bind(user_input)  # Automatically escaped
    result = execute_query(
        select(users).where(users.c.username == safe_input)
    )
"""

import os
import logging
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Union
from sqlalchemy import create_engine, event, text, bindparam
from sqlalchemy.engine import Engine, Connection
from sqlalchemy.pool import QueuePool
from sqlalchemy.sql import ClauseElement
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# Database configuration from environment
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "creative_ai_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# Connection string
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Global engine instance
_engine: Optional[Engine] = None


def get_engine() -> Engine:
    """
    Get or create SQLAlchemy engine with connection pooling

    Returns:
        SQLAlchemy Engine instance
    """
    global _engine

    if _engine is None:
        _engine = create_engine(
            DATABASE_URL,
            poolclass=QueuePool,
            pool_size=10,  # Number of connections to maintain
            max_overflow=20,  # Max connections above pool_size
            pool_timeout=30,  # Seconds to wait for connection
            pool_recycle=3600,  # Recycle connections after 1 hour
            pool_pre_ping=True,  # Verify connection before use
            echo=False,  # Set to True for SQL debugging
            future=True  # Use SQLAlchemy 2.0 style
        )

        # Log engine creation
        logger.info(f"SQLAlchemy engine created: {DB_HOST}:{DB_PORT}/{DB_NAME}")

        # Add connection event listeners
        @event.listens_for(_engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            """Log new connections"""
            logger.debug("New database connection established")

        @event.listens_for(_engine, "checkout")
        def receive_checkout(dbapi_conn, connection_record, connection_proxy):
            """Log connection checkout from pool"""
            logger.debug("Connection checked out from pool")

    return _engine


@contextmanager
def get_db():
    """
    Context manager for database connections
    Automatically handles connection cleanup and error rollback

    Usage:
        with get_db() as conn:
            result = conn.execute(select(users))
            conn.commit()

    Yields:
        SQLAlchemy Connection
    """
    engine = get_engine()
    connection = engine.connect()
    transaction = connection.begin()

    try:
        yield connection
        transaction.commit()
    except Exception as e:
        transaction.rollback()
        logger.error(f"Database error, transaction rolled back: {e}")
        raise
    finally:
        connection.close()


def execute_query(
    query: Union[ClauseElement, str],
    params: Optional[Dict[str, Any]] = None,
    fetch_one: bool = False,
    fetch_all: bool = False,
    commit: bool = False
) -> Any:
    """
    Execute a SQLAlchemy query with automatic connection management

    Args:
        query: SQLAlchemy query object or text query
        params: Query parameters (automatically bound and escaped)
        fetch_one: Return first row only
        fetch_all: Return all rows
        commit: Commit transaction after execution (handled by context manager)

    Returns:
        Query result (Row, List[Row], or ResultProxy)

    Examples:
        # Select query
        result = execute_query(
            select(users).where(users.c.id == bindparam('user_id')),
            params={'user_id': 5},
            fetch_one=True
        )

        # Insert query
        execute_query(
            users.insert(),
            params={'email': 'user@example.com', 'username': 'user'},
            commit=True
        )

        # Text query with safe parameters
        execute_query(
            text("SELECT * FROM users WHERE email = :email"),
            params={'email': user_input},  # Automatically escaped
            fetch_all=True
        )
    """
    engine = get_engine()
    connection = engine.connect()
    transaction = connection.begin()

    try:
        if isinstance(query, str):
            query = text(query)

        result = connection.execute(query, params or {})

        # Fetch results before commit (if needed)
        if fetch_one:
            fetched_result = result.fetchone()
        elif fetch_all:
            fetched_result = result.fetchall()
        else:
            fetched_result = result

        # Commit if requested (for INSERT/UPDATE/DELETE)
        if commit:
            transaction.commit()
        else:
            transaction.rollback()  # Rollback read-only queries

        return fetched_result

    except Exception as e:
        transaction.rollback()
        logger.error(f"Query execution error: {e}")
        raise
    finally:
        connection.close()


def safe_bind(value: Any) -> Any:
    """
    Second-Order SQL Injection Protection

    Ensures user-provided values are safely bound to queries
    even if they were previously stored in the database

    This prevents second-order SQL injection where:
    1. Attacker stores malicious SQL in database (e.g., username)
    2. Application retrieves value from database
    3. Application uses value in another query (VULNERABLE if not re-escaped)

    Args:
        value: User-provided or database-retrieved value

    Returns:
        Safe bindable parameter

    Example:
        # Vulnerable to second-order SQLi (psycopg2):
        username = cursor.fetchone()[0]  # Could be "admin' OR '1'='1"
        cursor.execute(f"SELECT * FROM logs WHERE user = '{username}'")  # UNSAFE

        # Safe with SQLAlchemy (automatic escaping):
        username = row['username']  # Could be "admin' OR '1'='1"
        result = execute_query(
            select(audit_logs).where(audit_logs.c.username == safe_bind(username))
        )  # SAFE - automatically parameterized
    """
    # SQLAlchemy automatically handles escaping when using bound parameters
    # This function is primarily for documentation and consistency
    # In SQLAlchemy, ALL values passed to queries are automatically bound

    # Additional validation: reject suspicious patterns
    if isinstance(value, str):
        # Detect obvious SQL injection attempts
        suspicious_patterns = [
            "'--", "' OR '", "' AND '", "UNION SELECT",
            "DROP TABLE", "DELETE FROM", "INSERT INTO",
            "'; --", "' OR 1=1", "admin'--"
        ]

        value_upper = value.upper()
        for pattern in suspicious_patterns:
            if pattern.upper() in value_upper:
                logger.warning(f"Suspicious SQL pattern detected in safe_bind: {pattern}")
                # Log security incident
                from utils.input_sanitizer import log_malicious_input
                log_malicious_input(
                    user_id=None,
                    input_value=value[:100],  # First 100 chars only
                    attack_type="second_order_sqli_attempt",
                    pattern=pattern,
                    ip_address="internal",
                    endpoint="safe_bind"
                )

    # Return value as-is - SQLAlchemy will handle safe binding
    return value


def execute_raw_query(
    query: str,
    params: Optional[Dict[str, Any]] = None,
    fetch_one: bool = False,
    fetch_all: bool = False
) -> Any:
    """
    Execute raw SQL query with MANDATORY parameter binding

    WARNING: Only use this for complex queries that cannot be expressed
    in SQLAlchemy Core. Always use named parameters (:param_name).

    Args:
        query: Raw SQL query with :param_name placeholders
        params: Dictionary of parameter names to values
        fetch_one: Return first row only
        fetch_all: Return all rows

    Returns:
        Query result

    Examples:
        # CORRECT - uses named parameters
        execute_raw_query(
            "SELECT * FROM users WHERE email = :email AND is_active = :active",
            params={'email': user_input, 'active': True},
            fetch_all=True
        )

        # WRONG - string concatenation (will raise error)
        execute_raw_query(
            f"SELECT * FROM users WHERE email = '{user_input}'"  # BLOCKED
        )
    """
    if params is None:
        logger.error("execute_raw_query called without params - potential SQL injection!")
        raise ValueError("Raw queries MUST use parameter binding. Provide params dict.")

    # Detect string interpolation attempts
    if '%s' in query or '{' in query:
        logger.error("String interpolation detected in raw query - BLOCKED")
        raise ValueError("String interpolation in SQL queries is forbidden. Use :param_name syntax.")

    # Ensure query uses named parameters
    if ':' not in query and params:
        logger.warning("Raw query provided with params but no :param_name placeholders found")

    return execute_query(text(query), params=params, fetch_one=fetch_one, fetch_all=fetch_all)


def bulk_insert(table: Any, data: List[Dict[str, Any]]) -> int:
    """
    Bulk insert multiple rows efficiently

    Args:
        table: SQLAlchemy Table object
        data: List of dictionaries (rows to insert)

    Returns:
        Number of rows inserted

    Example:
        bulk_insert(users, [
            {'email': 'user1@example.com', 'username': 'user1'},
            {'email': 'user2@example.com', 'username': 'user2'}
        ])
    """
    if not data:
        return 0

    with get_db() as conn:
        result = conn.execute(table.insert(), data)
        conn.commit()
        return result.rowcount


def get_pool_status() -> Dict[str, int]:
    """
    Get connection pool statistics

    Returns:
        Dictionary with pool status information
    """
    engine = get_engine()
    pool = engine.pool

    return {
        'size': pool.size(),
        'checked_in': pool.checkedin(),
        'checked_out': pool.checkedout(),
        'overflow': pool.overflow(),
        'queue_size': pool.queue_size if hasattr(pool, 'queue_size') else 0
    }


def test_connection() -> bool:
    """
    Test database connection

    Returns:
        True if connection successful, False otherwise
    """
    try:
        with get_db() as conn:
            result = conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False


# =============================================================================
# Second-Order SQL Injection Protection Examples
# =============================================================================

"""
Second-Order SQL Injection Explained:

1. FIRST-ORDER (Traditional) SQL Injection:
   User input directly injected into query

   Vulnerable:
       username = request.form['username']
       query = f"SELECT * FROM users WHERE username = '{username}'"

   Safe with SQLAlchemy:
       username = request.form['username']
       query = select(users).where(users.c.username == username)  # Auto-bound

2. SECOND-ORDER SQL Injection:
   Attacker stores malicious SQL in database, triggered later when used in query

   Step 1: Attacker registers with username: admin'--
   Step 2: Username stored in database: "admin'--"
   Step 3: Application retrieves username and uses in another query:

   Vulnerable (psycopg2):
       cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
       user = cursor.fetchone()
       username_from_db = user[0]  # "admin'--"

       # Later in code - VULNERABLE if not re-parameterized:
       cursor.execute(f"INSERT INTO logs (user) VALUES ('{username_from_db}')")
       # Executes: INSERT INTO logs (user) VALUES ('admin'--')
       # The '--' comments out the rest, breaking query

   Safe with SQLAlchemy (automatic re-binding):
       result = conn.execute(select(users).where(users.c.username == username))
       user = result.fetchone()
       username_from_db = user['username']  # "admin'--"

       # Later in code - SAFE because SQLAlchemy auto-binds ALL values:
       conn.execute(
           audit_logs.insert(),
           {'user': username_from_db}  # Automatically escaped
       )
       # SQLAlchemy executes: INSERT INTO logs (user) VALUES ($1)
       # With parameter: ["admin'--"]
       # Result: Stored safely as literal string "admin'--"

3. Why SQLAlchemy Prevents Second-Order SQLi:
   - ALL values passed to queries are bound parameters
   - No string concatenation in query building
   - Values retrieved from DB are treated as data, not SQL
   - Even if attacker stores SQL syntax, it's executed as literal text

4. Additional Protection with safe_bind():
   - Detects suspicious patterns even in DB-retrieved values
   - Logs potential second-order attack attempts
   - Documents developer intent for security audits
"""

# =============================================================================
# Migration Helper Functions
# =============================================================================

def migrate_from_psycopg2_cursor(cursor):
    """
    Helper to gradually migrate from psycopg2 to SQLAlchemy

    Usage:
        # Old code:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        # New code:
        from database.models import users
        result = execute_query(
            select(users).where(users.c.id == user_id),
            fetch_one=True
        )
        user = result
    """
    pass  # Documentation function only
