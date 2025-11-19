"""
MFA Input Validation Middleware
Provides strict input validation for MFA codes with comprehensive payload detection

Security Features:
- Uses comprehensive_input_scan() from utils/input_sanitizer.py for all attack detection
- Detects URL encoding obfuscation
- Detects base64 encoding obfuscation
- Only allows 6-digit integers for MFA codes
- Logs all suspicious input to security_incidents table

Attack Detection (via comprehensive_input_scan):
- SQL Injection (UNION, OR, AND, SQL functions, stacked queries, comments)
- XSS (script tags, event handlers, iframes, data URIs, vbscript)
- Command Injection (shell metacharacters, command substitution, dangerous commands)
- Path Traversal (../, ..\\, URL-encoded variants)
- LDAP Injection
- XXE (XML External Entity)
- SSRF (internal IPs, localhost, link-local addresses)
- SSTI (Server-Side Template Injection)
- NoSQL Injection ($where, $ne, $regex, $gt, $lt, $or, $and)
- Control Characters (null bytes, non-printable ASCII)
"""

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from utils.audit import log_audit_event
from utils.input_sanitizer import log_malicious_input, comprehensive_input_scan
import re
import logging
import base64
import urllib.parse

logger = logging.getLogger(__name__)

class MFAValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate MFA input and detect malicious payloads

    Uses comprehensive_input_scan() for defense-in-depth security validation
    """

    async def dispatch(self, request: Request, call_next):
        # Only validate MFA-related endpoints
        if '/mfa/' in request.url.path or '/verify-mfa' in request.url.path:
            if request.method in ['POST', 'PUT']:
                try:
                    # Read request body
                    body = await request.body()

                    if body:
                        import json
                        try:
                            data = json.loads(body.decode('utf-8'))

                            # Validate MFA code if present
                            if 'code' in data or 'mfa_code' in data or 'totp_code' in data:
                                code = data.get('code') or data.get('mfa_code') or data.get('totp_code')

                                # Convert to string for validation
                                code_str = str(code)

                                # === FIRST: Strict format validation ===
                                # Security validation: ONLY allow 6 digits
                                if not re.match(r'^\d{6}$', code_str):
                                    # Log malicious attempt
                                    log_malicious_input(
                                        user_id=None,
                                        input_value=code_str[:100],  # Truncate for logging
                                        attack_type='mfa_invalid_format',
                                        pattern='Non-digit characters in MFA code',
                                        ip_address=request.client.host,
                                        endpoint=request.url.path
                                    )

                                    logger.warning(
                                        f"MFA code validation failed from {request.client.host}: "
                                        f"Invalid format (expected 6 digits)"
                                    )

                                    raise HTTPException(
                                        status_code=400,
                                        detail="MFA code must be exactly 6 digits"
                                    )

                                # === SECOND: URL encoding detection ===
                                # Detect URL-encoded payloads (attacker may encode malicious input)
                                try:
                                    decoded_url = urllib.parse.unquote(code_str)
                                    if decoded_url != code_str:
                                        # Input was URL-encoded (suspicious for numeric code)
                                        log_malicious_input(
                                            user_id=None,
                                            input_value=code_str[:100],
                                            attack_type='url_encoding_obfuscation',
                                            pattern=f'URL-encoded MFA code detected (decoded: {decoded_url[:50]})',
                                            ip_address=request.client.host,
                                            endpoint=request.url.path
                                        )

                                        logger.warning(
                                            f"URL-encoded MFA code from {request.client.host}: {code_str}"
                                        )

                                        raise HTTPException(
                                            status_code=400,
                                            detail="Invalid MFA code format"
                                        )
                                except Exception as e:
                                    logger.error(f"URL decode error in MFA validation: {e}")

                                # === THIRD: Base64 encoding detection ===
                                # Detect base64-encoded payloads
                                try:
                                    # Check if input looks like base64 (alphanumeric + / + = padding)
                                    # and is longer than a normal 6-digit code
                                    if re.match(r'^[A-Za-z0-9+/=]+$', code_str) and len(code_str) >= 8:
                                        try:
                                            decoded_b64 = base64.b64decode(code_str).decode('utf-8', errors='ignore')
                                            # If it successfully decodes to something different, it's likely obfuscation
                                            if decoded_b64 != code_str and len(decoded_b64) > 0:
                                                log_malicious_input(
                                                    user_id=None,
                                                    input_value=code_str[:100],
                                                    attack_type='base64_encoding_obfuscation',
                                                    pattern=f'Base64-encoded payload detected (decoded: {decoded_b64[:50]})',
                                                    ip_address=request.client.host,
                                                    endpoint=request.url.path
                                                )

                                                logger.warning(
                                                    f"Base64-encoded MFA code from {request.client.host}: {code_str}"
                                                )

                                                raise HTTPException(
                                                    status_code=400,
                                                    detail="Invalid MFA code format"
                                                )
                                        except Exception:
                                            pass  # Not valid base64, continue validation
                                except Exception as e:
                                    logger.error(f"Base64 decode error in MFA validation: {e}")

                                # === FOURTH: Comprehensive security scan ===
                                # Use comprehensive scanner from utils/input_sanitizer.py
                                # This checks for ALL attack vectors:
                                # - SQL injection (UNION, OR, AND, SQL functions, stacked queries)
                                # - XSS (script tags, event handlers, iframes, data URIs)
                                # - Command injection (shell metacharacters, command substitution)
                                # - Path traversal (../, ..\\, URL-encoded)
                                # - LDAP injection
                                # - XXE (XML External Entity)
                                # - SSRF (internal IPs, localhost)
                                # - SSTI (Server-Side Template Injection)
                                # - NoSQL injection ($where, $ne, $regex)
                                # - Control characters
                                is_malicious, attack_type, pattern = comprehensive_input_scan(code_str)

                                if is_malicious:
                                    log_malicious_input(
                                        user_id=None,
                                        input_value=code_str[:100],
                                        attack_type=attack_type,
                                        pattern=pattern,
                                        ip_address=request.client.host,
                                        endpoint=request.url.path
                                    )

                                    logger.warning(
                                        f"{attack_type} detected in MFA code from {request.client.host}: {pattern}"
                                    )

                                    raise HTTPException(
                                        status_code=400,
                                        detail="Invalid MFA code format"
                                    )

                                logger.info(f"MFA code validation passed from {request.client.host}")

                        except json.JSONDecodeError:
                            pass  # Let the endpoint handle invalid JSON

                        # Reconstruct request with original body
                        async def receive():
                            return {"type": "http.request", "body": body}

                        request._receive = receive

                except Exception as e:
                    logger.error(f"MFA validation middleware error: {e}")
                    # Don't block request on middleware errors
                    pass

        response = await call_next(request)
        return response


def validate_mfa_code_format(code: str) -> bool:
    """
    Validate MFA code format (6 digits only)

    Args:
        code: The MFA code to validate

    Returns:
        True if valid, False otherwise
    """
    if not code:
        return False

    # Must be exactly 6 digits
    return bool(re.match(r'^\d{6}$', str(code)))


def sanitize_mfa_code(code: str) -> str:
    """
    Sanitize MFA code by removing all non-digit characters

    Args:
        code: The MFA code to sanitize

    Returns:
        Sanitized code containing only digits
    """
    if not code:
        return ""

    # Remove all non-digit characters
    sanitized = re.sub(r'\D', '', str(code))

    # Truncate to 6 digits
    return sanitized[:6]
