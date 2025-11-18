"""
utils/file_validator.py
Comprehensive file validation and malware detection
Protects against magic bytes mismatch, double extensions, polyglots, ImageMagick exploits
"""

import os
import re
import magic
import hashlib
import logging
from typing import Tuple, Optional, Dict
from PIL import Image
import io

logger = logging.getLogger(__name__)

# File upload configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.txt', '.pdf', '.docx', '.csv'}

# Magic bytes signatures for allowed file types
MAGIC_BYTES_SIGNATURES = {
    'image/jpeg': [
        b'\xFF\xD8\xFF\xDB',  # JPEG raw
        b'\xFF\xD8\xFF\xE0',  # JFIF
        b'\xFF\xD8\xFF\xE1',  # EXIF
        b'\xFF\xD8\xFF\xE2',  # Canon JPEG
        b'\xFF\xD8\xFF\xE3',  # Samsung JPEG
        b'\xFF\xD8\xFF\xE8',  # SPIFF JPEG
    ],
    'image/png': [
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',  # PNG signature
    ],
    'application/pdf': [
        b'%PDF-',  # PDF header
    ],
    'text/plain': [
        # Text files don't have magic bytes, validate content instead
    ],
    'text/csv': [
        # CSV files are text-based, validated by content
    ],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
        b'PK\x03\x04',  # ZIP signature (DOCX is a ZIP)
    ],
}

# Dangerous file extensions (double extension attacks)
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jar',
    '.msi', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.com', '.scr',
    '.pif', '.application', '.gadget', '.msp', '.cpl', '.hta',
    '.inf', '.ins', '.isp', '.jse', '.lib', '.lnk', '.mde',
    '.msc', '.msp', '.mst', '.paf', '.scf', '.sct', '.shb',
    '.sys', '.vb', '.vbe', '.vxd', '.wsc', '.wsf', '.wsh'
}

# Polyglot attack patterns
POLYGLOT_PATTERNS = [
    b'<!DOCTYPE html',
    b'<html',
    b'<script',
    b'<?php',
    b'<%',
    b'#!/bin/bash',
    b'#!/usr/bin/python',
    b'MZ\x90\x00',  # PE executable
    b'\x7fELF',  # ELF executable
]

# ImageMagick exploit patterns
IMAGEMAGICK_EXPLOIT_PATTERNS = [
    b'push graphic-context',
    b'viewbox',
    b'image over',
    b'url(',
    b'label:',
    b'caption:',
    b'pango:',
    b'https://',
    b'http://',
    b'file://',
    b'ephemeral:',
    b'msl:',
    b'text:',
    b'inline:',
]

# SVG-specific attack patterns
SVG_EXPLOIT_PATTERNS = [
    b'<script',
    b'javascript:',
    b'onload=',
    b'onerror=',
    b'onclick=',
    b'<foreignObject',
    b'<iframe',
    b'<embed',
    b'<object',
]


class FileValidationError(Exception):
    """Custom exception for file validation errors"""
    pass


def validate_file_size(file_content: bytes) -> None:
    """
    Validate file size does not exceed maximum

    Args:
        file_content: File bytes

    Raises:
        FileValidationError: If file exceeds size limit
    """
    if len(file_content) > MAX_FILE_SIZE:
        raise FileValidationError(
            f"File size {len(file_content)} bytes exceeds maximum of {MAX_FILE_SIZE} bytes"
        )

    if len(file_content) == 0:
        raise FileValidationError("File is empty")


def validate_extension(filename: str) -> str:
    """
    Validate file extension is allowed

    Args:
        filename: Original filename

    Returns:
        Lowercase file extension

    Raises:
        FileValidationError: If extension is not allowed
    """
    # Normalize filename
    filename = filename.lower().strip()

    # Check for double extensions (e.g., file.pdf.exe)
    parts = filename.split('.')
    if len(parts) > 2:
        # Check all extensions except the last one
        for i in range(len(parts) - 1):
            ext = '.' + parts[i]
            if ext in DANGEROUS_EXTENSIONS:
                raise FileValidationError(
                    f"Double extension detected: {filename} contains dangerous extension {ext}"
                )

    # Get final extension
    ext = os.path.splitext(filename)[1].lower()

    if not ext:
        raise FileValidationError("File has no extension")

    if ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"Extension {ext} not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    return ext


def validate_magic_bytes(file_content: bytes, claimed_mime: str) -> None:
    """
    Validate file magic bytes match claimed MIME type

    Args:
        file_content: File bytes
        claimed_mime: MIME type from client

    Raises:
        FileValidationError: If magic bytes don't match MIME type
    """
    if not file_content:
        raise FileValidationError("Cannot validate magic bytes: empty file")

    # Use python-magic to detect actual MIME type
    try:
        mime = magic.Magic(mime=True)
        actual_mime = mime.from_buffer(file_content)

        # Normalize MIME types for comparison
        actual_mime_normalized = actual_mime.lower().strip()
        claimed_mime_normalized = claimed_mime.lower().strip()

        # Handle JPEG variations
        if claimed_mime_normalized in ['image/jpeg', 'image/jpg']:
            claimed_mime_normalized = 'image/jpeg'
        if actual_mime_normalized in ['image/jpeg', 'image/jpg']:
            actual_mime_normalized = 'image/jpeg'

        # Check if actual matches claimed
        if actual_mime_normalized != claimed_mime_normalized:
            raise FileValidationError(
                f"MIME type mismatch: file claims to be '{claimed_mime}' but is actually '{actual_mime}'"
            )

    except Exception as e:
        logger.error(f"Magic bytes validation error: {e}")
        raise FileValidationError(f"Failed to validate file type: {str(e)}")

    # Additional manual magic bytes check
    signatures = MAGIC_BYTES_SIGNATURES.get(claimed_mime, [])
    if signatures:
        header_match = False
        for signature in signatures:
            if file_content.startswith(signature):
                header_match = True
                break

        if not header_match:
            raise FileValidationError(
                f"File header does not match expected magic bytes for {claimed_mime}"
            )


def detect_polyglot_attack(file_content: bytes, mime_type: str) -> None:
    """
    Detect polyglot files (files that are valid in multiple formats)

    Args:
        file_content: File bytes
        mime_type: MIME type for context-aware detection

    Raises:
        FileValidationError: If polyglot patterns detected
    """
    # For image files with valid magic bytes, only check the first 1KB and last 1KB
    # to avoid false positives from metadata/EXIF data
    is_image = mime_type.startswith('image/')

    if is_image:
        # Check only header and footer regions for images (avoid metadata false positives)
        check_regions = [
            file_content[:1024],  # First 1KB
            file_content[-1024:] if len(file_content) > 1024 else b''  # Last 1KB
        ]
    else:
        # For non-images, check the entire file
        check_regions = [file_content]

    # Check for common polyglot patterns in selected regions
    dangerous_patterns = [
        b'<!DOCTYPE html',
        b'<html',
        b'<?php',
        b'<%',
        b'#!/bin/bash',
        b'#!/usr/bin/python',
        b'MZ\x90\x00',  # PE executable header
        b'\x7fELF',  # ELF executable
    ]

    for region in check_regions:
        if not region:
            continue

        for pattern in dangerous_patterns:
            if pattern in region:
                raise FileValidationError(
                    f"Potential polyglot attack detected: file contains suspicious pattern"
                )

    # Check for embedded executables (full file scan - more specific check)
    # PE header with DOS stub (very specific to avoid false positives)
    if b'MZ\x90\x00' in file_content[:2] or (
        b'MZ' in file_content and b'This program cannot be run in DOS mode' in file_content
    ):
        raise FileValidationError("Embedded executable detected in file")

    # Check for script tags in HTML context (not just binary data)
    # Only flag if we see clear HTML/script structure
    content_lower = file_content[:2048].lower()  # Check first 2KB only
    if b'<script' in content_lower and (b'<html' in content_lower or b'<!doctype' in content_lower):
        raise FileValidationError("HTML/Script content detected in file")


def detect_imagemagick_exploits(file_content: bytes, mime_type: str) -> None:
    """
    Detect ImageMagick CVE exploits (CVE-2016-3714, etc.)

    Args:
        file_content: File bytes
        mime_type: MIME type

    Raises:
        FileValidationError: If ImageMagick exploit detected
    """
    # Only check image files
    if not mime_type.startswith('image/'):
        return

    # For PNG/JPEG, URLs in metadata are legitimate - only check for exploit-specific patterns
    # Exclude http:// and https:// from checks for raster images (PNG, JPEG)
    exploit_patterns_to_check = []

    if mime_type in ['image/png', 'image/jpeg', 'image/jpg']:
        # For raster images, skip URL patterns (legitimate in metadata)
        # Only check for actual ImageMagick MVG/MSL exploit patterns
        exploit_patterns_to_check = [
            b'push graphic-context',
            b'viewbox',
            b'image over',
            b'label:',
            b'caption:',
            b'pango:',
            b'file://',
            b'ephemeral:',
            b'msl:',
            b'text:',
            b'inline:',
        ]
    else:
        # For other image types (SVG, etc.), check all patterns
        exploit_patterns_to_check = IMAGEMAGICK_EXPLOIT_PATTERNS

    # Check for ImageMagick exploit patterns in first 4KB (where MVG commands would be)
    check_region = file_content[:4096]
    for pattern in exploit_patterns_to_check:
        if pattern in check_region.lower():
            raise FileValidationError(
                "Potential ImageMagick exploit detected in image file"
            )

    # SVG-specific checks (SVG is XML-based, so script injection is a real threat)
    if mime_type == 'image/svg+xml' or file_content.startswith(b'<?xml') or b'<svg' in file_content:
        for pattern in SVG_EXPLOIT_PATTERNS:
            if pattern in file_content.lower():
                raise FileValidationError(
                    "Potential SVG exploit detected"
                )


def validate_image_integrity(file_content: bytes, mime_type: str) -> None:
    """
    Validate image file integrity using PIL

    Args:
        file_content: File bytes
        mime_type: MIME type

    Raises:
        FileValidationError: If image is corrupted or malformed
    """
    if not mime_type.startswith('image/'):
        return

    # Skip SVG (PIL doesn't handle SVG)
    if 'svg' in mime_type.lower():
        return

    try:
        # Attempt to open and verify image
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify image integrity

        # Additional check: try to load the image data
        img = Image.open(io.BytesIO(file_content))
        img.load()  # Actually decode the image

        # Check for reasonable dimensions (prevent decompression bombs)
        width, height = img.size
        if width * height > 100_000_000:  # 100 megapixels
            raise FileValidationError(
                f"Image dimensions too large: {width}x{height} (potential decompression bomb)"
            )

    except FileValidationError:
        raise
    except Exception as e:
        raise FileValidationError(f"Image validation failed: {str(e)}")


def detect_null_bytes(file_content: bytes) -> None:
    """
    Detect null byte injection attacks

    Args:
        file_content: File bytes

    Raises:
        FileValidationError: If suspicious null bytes detected
    """
    # Count null bytes
    null_count = file_content.count(b'\x00')

    # Binary files can have null bytes, but excessive nulls are suspicious
    # Allow up to 10% null bytes in binary files
    if null_count > len(file_content) * 0.1:
        raise FileValidationError(
            f"Excessive null bytes detected ({null_count} in {len(file_content)} bytes)"
        )


def calculate_file_hash(file_content: bytes) -> str:
    """
    Calculate SHA-256 hash of file content

    Args:
        file_content: File bytes

    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(file_content).hexdigest()


def validate_text_content(file_content: bytes, mime_type: str) -> None:
    """
    Validate text-based files for malicious content

    Args:
        file_content: File bytes
        mime_type: MIME type

    Raises:
        FileValidationError: If malicious content detected
    """
    if mime_type not in ['text/plain', 'text/csv']:
        return

    try:
        # Decode as UTF-8
        text = file_content.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise FileValidationError("Text file contains invalid UTF-8 characters")

    # Check for script injection
    dangerous_patterns = [
        '<script', '</script>',
        'javascript:',
        'onclick=', 'onload=', 'onerror=',
        '<?php', '?>',
        '<%', '%>',
        '#!/bin/', '#!/usr/bin/',
    ]

    text_lower = text.lower()
    for pattern in dangerous_patterns:
        if pattern in text_lower:
            raise FileValidationError(
                f"Suspicious content detected in text file: {pattern}"
            )


def validate_pdf_content(file_content: bytes, mime_type: str) -> None:
    """
    Validate PDF files for malicious content

    Args:
        file_content: File bytes
        mime_type: MIME type

    Raises:
        FileValidationError: If malicious content detected
    """
    if mime_type != 'application/pdf':
        return

    # Check for JavaScript in PDF
    if b'/JavaScript' in file_content or b'/JS' in file_content:
        raise FileValidationError("PDF contains JavaScript (potential exploit)")

    # Check for launch actions
    if b'/Launch' in file_content:
        raise FileValidationError("PDF contains launch actions (potential exploit)")

    # Check for embedded files
    if b'/EmbeddedFile' in file_content:
        raise FileValidationError("PDF contains embedded files (not allowed)")

    # Check for GoTo actions with URLs
    if b'/URI' in file_content and b'/GoTo' in file_content:
        raise FileValidationError("PDF contains suspicious URI actions")


def comprehensive_file_validation(
    file_content: bytes,
    filename: str,
    mime_type: str
) -> Dict[str, any]:
    """
    Comprehensive file validation pipeline

    Args:
        file_content: File bytes
        filename: Original filename
        mime_type: Claimed MIME type

    Returns:
        Dictionary with validation results and file metadata

    Raises:
        FileValidationError: If any validation check fails
    """
    logger.info(f"Validating file: {filename} ({mime_type})")

    # 1. Validate file size
    validate_file_size(file_content)

    # 2. Validate extension
    extension = validate_extension(filename)

    # 3. Validate magic bytes
    validate_magic_bytes(file_content, mime_type)

    # 4. Detect polyglot attacks (context-aware)
    detect_polyglot_attack(file_content, mime_type)

    # 5. Detect ImageMagick exploits
    detect_imagemagick_exploits(file_content, mime_type)

    # 6. Validate image integrity (if image)
    validate_image_integrity(file_content, mime_type)

    # 7. Detect null byte injection
    detect_null_bytes(file_content)

    # 8. Validate text content (if text)
    validate_text_content(file_content, mime_type)

    # 9. Validate PDF content (if PDF)
    validate_pdf_content(file_content, mime_type)

    # Calculate file hash
    file_hash = calculate_file_hash(file_content)

    logger.info(f"File validation passed: {filename} (SHA-256: {file_hash})")

    return {
        'filename': filename,
        'extension': extension,
        'mime_type': mime_type,
        'size': len(file_content),
        'sha256': file_hash,
        'validated': True
    }


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and injection attacks

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = os.path.basename(filename)

    # Remove dangerous characters (keep only alphanumeric, dash, underscore, dot)
    filename = re.sub(r'[^\w\-_\.]', '_', filename)

    # Remove multiple consecutive dots
    filename = re.sub(r'\.{2,}', '.', filename)

    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')

    # Ensure filename is not empty
    if not filename or filename == '.' or filename == '..':
        import secrets
        filename = f"file_{secrets.token_hex(8)}"

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext

    return filename
