"""
database/connection.py
Secure database connection pool with automatic connection management
"""

import psycopg2
from psycopg2 import pool
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class DatabasePool:
    """
    Database connection pool for PostgreSQL
    Manages connections securely and efficiently
    """
    
    def __init__(self, dbname: str, user: str, password: str, 
                 host: str = 'localhost', port: int = 5432,
                 min_conn: int = 2, max_conn: int = 10):
        """Initialize connection pool"""
        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(
                min_conn,
                max_conn,
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port,
                # Security settings
                connect_timeout=10,
                options='-c statement_timeout=30000'  # 30 second query timeout
            )
            logger.info("Database connection pool created successfully")
        except psycopg2.Error as e:
            logger.error(f"Failed to create connection pool: {e}")
            raise
    
    def get_connection(self):
        """Get connection from pool"""
        try:
            conn = self.pool.getconn()
            # Set session parameters for security
            cursor = conn.cursor()
            cursor.execute("SET SESSION statement_timeout = '30s'")
            cursor.execute("SET SESSION idle_in_transaction_session_timeout = '60s'")
            cursor.close()
            return conn
        except psycopg2.Error as e:
            logger.error(f"Failed to get connection from pool: {e}")
            raise
    
    def return_connection(self, conn):
        """Return connection to pool"""
        try:
            self.pool.putconn(conn)
        except psycopg2.Error as e:
            logger.error(f"Failed to return connection to pool: {e}")
    
    def close_all(self):
        """Close all connections in pool"""
        try:
            self.pool.closeall()
            logger.info("All database connections closed")
        except psycopg2.Error as e:
            logger.error(f"Error closing connection pool: {e}")

# Global connection pool instance
_db_pool: Optional[DatabasePool] = None

def initialize_pool(dbname: str, user: str, password: str,
                   host: str = 'localhost', port: int = 5432,
                   min_conn: int = 2, max_conn: int = 10):
    """Initialize global connection pool"""
    global _db_pool
    _db_pool = DatabasePool(dbname, user, password, host, port, min_conn, max_conn)

def get_db_connection():
    """
    Get database connection from pool
    Should be used in try-finally blocks to ensure proper cleanup
    """
    global _db_pool
    
    if _db_pool is None:
        raise RuntimeError("Database pool not initialized")
    
    return _db_pool.get_connection()

def return_db_connection(conn):
    """Return database connection to pool"""
    global _db_pool
    
    if _db_pool is None:
        raise RuntimeError("Database pool not initialized")
    
    _db_pool.return_connection(conn)

def close_db_pool():
    """Close database pool"""
    global _db_pool
    
    if _db_pool is not None:
        _db_pool.close_all()
        _db_pool = None