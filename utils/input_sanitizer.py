"""
utils/input_sanitizer.py
Comprehensive input sanitization and malicious input detection
Detects and blocks SQL injection, XSS, command injection, path traversal, and more
"""

import re
import logging
from typing import Optional, Tuple, Dict, List
from database.connection import get_db_connection, return_db_connection

logger = logging.getLogger(__name__)

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    # Classic SQL keywords
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b",
    r"\bUNION\b.*\bSELECT\b",
    r"\bOR\b.*=.*",
    r"\bAND\b.*=.*",

    # SQL comments
    r"(--|#|/\*|\*/)",

    # SQL functions and procedures
    r"\b(xp_|sp_|sys\.|information_schema)",

    # String concatenation tricks
    r"(\|\||CONCAT\()",

    # Time-based blind SQL injection
    r"\b(SLEEP|WAITFOR|DELAY|BENCHMARK)\b",

    # Stacked queries
    r";.*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b",
]

# XSS (Cross-Site Scripting) patterns
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",  # Event handlers (onclick, onload, etc.)
    r"<iframe",
    r"<object",
    r"<embed",
    r"<applet",
    r"<meta",
    r"<link",
    r"<style",
    r"data:text/html",
    r"vbscript:",
    r"<svg.*onload",
    r"<img.*onerror",
]

# Command Injection patterns (more specific to avoid false positives with passwords)
COMMAND_INJECTION_PATTERNS = [
    r";\s*(rm|cat|ls|wget|curl|bash|sh|nc|netcat)",  # Command chaining with dangerous commands
    r"\|\s*(rm|cat|ls|wget|curl|bash|sh|nc|netcat)",  # Pipe to dangerous commands
    r"`[^`]*\b(rm|cat|ls|wget|curl|bash|sh|nc|netcat)\b",  # Backtick command substitution
    r"\$\([^)]*\b(rm|cat|ls|wget|curl|bash|sh|nc|netcat)\b",  # Command substitution
    r"&&\s*(rm|cat|ls|wget|curl|bash|sh|nc|netcat)",  # AND chaining with dangerous commands
    r"\|\|\s*(rm|cat|ls|wget|curl|bash|sh|nc|netcat)",  # OR chaining with dangerous commands
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e/",
    r"%2e%2e\\",
    r"..%2f",
    r"..%5c",
]

# LDAP Injection patterns
LDAP_INJECTION_PATTERNS = [
    r"\*\)",
    r"\(\|",
    r"\(&",
    r"\(!",
]

# XML/XXE patterns
XXE_PATTERNS = [
    r"<!ENTITY",
    r"<!DOCTYPE",
    r"SYSTEM",
    r"PUBLIC",
]

# SSRF (Server-Side Request Forgery) patterns
SSRF_PATTERNS = [
    # Internal IP addresses
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",

    # Localhost variations
    r"\blocalhost\b",
    r"\b0\.0\.0\.0\b",

    # IPv6 localhost
    r"::1",
    r"\[::1\]",

    # Internal domain names
    r"\.local\b",
    r"\.internal\b",
]

# SSTI (Server-Side Template Injection) patterns
SSTI_PATTERNS = [
    r"\{\{.*\}\}",
    r"\{%.*%\}",
    r"\${.*}",
    r"<%.*%>",
]

# NoSQL Injection patterns
NOSQL_INJECTION_PATTERNS = [
    r"\$where",
    r"\$ne",
    r"\$gt",
    r"\$lt",
    r"\$regex",
    r"\$or",
    r"\$and",
]

# Compile all patterns for performance
COMPILED_SQL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS]
COMPILED_XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
COMPILED_COMMAND_PATTERNS = [re.compile(p, re.IGNORECASE) for p in COMMAND_INJECTION_PATTERNS]
COMPILED_PATH_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]
COMPILED_LDAP_PATTERNS = [re.compile(p, re.IGNORECASE) for p in LDAP_INJECTION_PATTERNS]
COMPILED_XXE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in XXE_PATTERNS]
COMPILED_SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SSRF_PATTERNS]
COMPILED_SSTI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SSTI_PATTERNS]
COMPILED_NOSQL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in NOSQL_INJECTION_PATTERNS]


class MaliciousInputDetected(Exception):
    """Exception raised when malicious input is detected"""
    def __init__(self, attack_type: str, pattern: str, input_sample: str):
        self.attack_type = attack_type
        self.pattern = pattern
        self.input_sample = input_sample[:100]  # Limit sample size
        super().__init__(f"{attack_type} detected: {pattern}")


def detect_sql_injection(text: str) -> Optional[str]:
    """
    Detect SQL injection attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_SQL_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_xss(text: str) -> Optional[str]:
    """
    Detect XSS attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_XSS_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_command_injection(text: str) -> Optional[str]:
    """
    Detect command injection attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_COMMAND_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_path_traversal(text: str) -> Optional[str]:
    """
    Detect path traversal attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_PATH_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_ldap_injection(text: str) -> Optional[str]:
    """
    Detect LDAP injection attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_LDAP_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_xxe(text: str) -> Optional[str]:
    """
    Detect XXE (XML External Entity) injection attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_XXE_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_ssrf(text: str) -> Optional[str]:
    """
    Detect SSRF (Server-Side Request Forgery) attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_SSRF_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_ssti(text: str) -> Optional[str]:
    """
    Detect SSTI (Server-Side Template Injection) attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_SSTI_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def detect_nosql_injection(text: str) -> Optional[str]:
    """
    Detect NoSQL injection attempts

    Args:
        text: Input text to check

    Returns:
        Pattern matched if detected, None otherwise
    """
    for pattern in COMPILED_NOSQL_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def comprehensive_input_scan(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Scan input for all types of malicious patterns

    Args:
        text: Input text to scan

    Returns:
        Tuple of (is_malicious, attack_type, pattern)
    """
    if not text:
        return False, None, None

    # Convert to string if not already
    text = str(text)

    # Control characters check
    if has_control_characters(text):
        return True, "control_characters", "control_chars_detected"

    # SQL Injection
    pattern = detect_sql_injection(text)
    if pattern:
        return True, "sql_injection", pattern

    # XSS
    pattern = detect_xss(text)
    if pattern:
        return True, "xss", pattern

    # Command Injection
    pattern = detect_command_injection(text)
    if pattern:
        return True, "command_injection", pattern

    # Path Traversal
    pattern = detect_path_traversal(text)
    if pattern:
        return True, "path_traversal", pattern

    # LDAP Injection
    pattern = detect_ldap_injection(text)
    if pattern:
        return True, "ldap_injection", pattern

    # XXE
    pattern = detect_xxe(text)
    if pattern:
        return True, "xxe_injection", pattern

    # SSRF
    pattern = detect_ssrf(text)
    if pattern:
        return True, "ssrf", pattern

    # SSTI
    pattern = detect_ssti(text)
    if pattern:
        return True, "ssti", pattern

    # NoSQL Injection
    pattern = detect_nosql_injection(text)
    if pattern:
        return True, "nosql_injection", pattern

    return False, None, None


def has_control_characters(text: str) -> bool:
    """
    Check if text contains control characters (except allowed whitespace)
    
    Args:
        text: Input text to check
        
    Returns:
        True if control characters found, False otherwise
    """
    if not text:
        return False
    
    # Allow: space (32), tab (9), newline (10), carriage return (13)
    # Block: all other control characters (0-31, 127-159)
    for char in text:
        code = ord(char)
        if code < 32 and code not in (9, 10, 13):  # Control chars except tab, LF, CR
            return True
        if 127 <= code <= 159:  # DEL and C1 control characters
            return True
    return False


def sanitize_input(
    text: str,
    max_length: int = 10000,
    allow_html: bool = False,
    strip_dangerous: bool = True
) -> str:
    """
    Sanitize user input by removing dangerous characters

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        allow_html: Whether to allow HTML tags
        strip_dangerous: Whether to strip dangerous characters

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Convert to string
    text = str(text)

    # Truncate to max length
    text = text[:max_length]

    # Remove null bytes and control characters
    text = text.replace('\x00', '')
    
    if strip_dangerous:
        # Remove control characters (except newline, tab, carriage return)
        # Allow printable ASCII (32-126) and extended Unicode, plus tab/newline/CR
        text = ''.join(char for char in text 
                      if (ord(char) >= 32 and ord(char) < 127) or 
                         ord(char) >= 128 or 
                         char in '\n\t\r')

    if not allow_html:
        # HTML entity encoding
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        text = text.replace('/', '&#x2F;')

    # Strip leading/trailing whitespace
    text = text.strip()

    return text


def log_malicious_input(
    user_id: Optional[int],
    input_value: str,
    attack_type: str,
    pattern: str,
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None
) -> None:
    """
    Log malicious input attempt to database

    Args:
        user_id: User ID if authenticated
        input_value: The malicious input (truncated)
        attack_type: Type of attack detected
        pattern: Pattern that was matched
        ip_address: Client IP address
        endpoint: API endpoint targeted
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Truncate input value for logging
        input_sample = input_value[:500] if input_value else None

        cursor.execute(
            """
            INSERT INTO security_incidents (
                user_id, incident_type, severity, ip_address,
                endpoint, input_sample, pattern_matched, details
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                attack_type,
                'high',
                ip_address,
                endpoint,
                input_sample,
                pattern,
                None  # Additional details as JSON if needed
            )
        )

        conn.commit()
        return_db_connection(conn)

        logger.warning(
            f"Malicious input detected - Type: {attack_type}, "
            f"Pattern: {pattern}, IP: {ip_address}, Endpoint: {endpoint}"
        )

    except Exception as e:
        logger.error(f"Failed to log malicious input: {e}")


def validate_and_sanitize(
    text: str,
    max_length: int = 10000,
    allow_html: bool = False,
    block_on_detection: bool = True,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None
) -> str:
    """
    Comprehensive validation and sanitization pipeline

    Args:
        text: Input text to validate and sanitize
        max_length: Maximum allowed length
        allow_html: Whether to allow HTML tags
        block_on_detection: Whether to raise exception on malicious input
        user_id: User ID for logging
        ip_address: Client IP for logging
        endpoint: Endpoint for logging

    Returns:
        Sanitized text

    Raises:
        MaliciousInputDetected: If malicious input detected and block_on_detection=True
    """
    if not text:
        return ""

    # Scan for malicious patterns
    is_malicious, attack_type, pattern = comprehensive_input_scan(text)

    if is_malicious:
        # Log the incident
        log_malicious_input(
            user_id=user_id,
            input_value=text,
            attack_type=attack_type,
            pattern=pattern,
            ip_address=ip_address,
            endpoint=endpoint
        )

        if block_on_detection:
            raise MaliciousInputDetected(attack_type, pattern, text)

    # Sanitize input
    return sanitize_input(text, max_length, allow_html, strip_dangerous=True)


def validate_email(email: str) -> bool:
    """
    Validate email format and check for injection attacks

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    if not email:
        return False

    # Check for malicious patterns
    is_malicious, _, _ = comprehensive_input_scan(email)
    if is_malicious:
        return False

    # Basic email format validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False

    # Additional checks
    if len(email) > 254:  # RFC 5321
        return False

    local, domain = email.rsplit('@', 1)
    if len(local) > 64:  # RFC 5321
        return False

    return True


def validate_username(username: str) -> bool:
    """
    Validate username format

    Args:
        username: Username to validate

    Returns:
        True if valid, False otherwise
    """
    if not username:
        return False

    # Check for malicious patterns
    is_malicious, _, _ = comprehensive_input_scan(username)
    if is_malicious:
        return False

    # Username rules: 3-30 characters, alphanumeric + underscore + hyphen
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return bool(re.match(pattern, username))


def validate_url(url: str) -> bool:
    """
    Validate URL and check for SSRF attacks

    Args:
        url: URL to validate

    Returns:
        True if valid, False otherwise
    """
    if not url:
        return False

    # Check for SSRF patterns
    pattern = detect_ssrf(url)
    if pattern:
        return False

    # Only allow http and https
    if not url.startswith(('http://', 'https://')):
        return False

    # Check for malicious patterns
    is_malicious, _, _ = comprehensive_input_scan(url)
    if is_malicious:
        return False

    return True
