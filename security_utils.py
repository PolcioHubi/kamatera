"""
Security utilities for the Mobywatel application.
Provides enhanced security functions and validations.
"""

import hashlib
import secrets
import re
from typing import Optional, Tuple, List
import os


def hash_ip_address(ip_address: str) -> str:
    """
    Hash IP address for privacy protection (GDPR/RODO compliant).
    
    Args:
        ip_address: Raw IP address string
        
    Returns:
        Hashed IP address (first 16 characters)
    """
    if not ip_address or ip_address in ["127.0.0.1", "localhost", "::1"]:
        return "localhost"
    
    # Hash IP address for privacy protection
    return hashlib.sha256(ip_address.encode()).hexdigest()[:16]


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength according to security standards.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Hasło musi mieć co najmniej 12 znaków"
    
    if len(password) > 128:
        return False, "Hasło może mieć maksymalnie 128 znaków"
    
    # Check for common patterns
    if re.search(r'password|123|qwerty|admin', password.lower()):
        return False, "Hasło nie może zawierać popularnych wzorców"
    
    # Check for character variety
    has_upper = re.search(r'[A-Z]', password)
    has_lower = re.search(r'[a-z]', password)
    has_digit = re.search(r'\d', password)
    has_special = re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Hasło musi zawierać wielkie litery, małe litery, cyfry i znaki specjalne"
    
    return True, "Hasło spełnia wymagania bezpieczeństwa"


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure token.
    
    Args:
        length: Length of token in characters
        
    Returns:
        Secure random token
    """
    return secrets.token_urlsafe(length)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and other attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path separators and other dangerous characters
    dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    sanitized = filename
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '_')
    
    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext
    
    return sanitized


def validate_file_extension(filename: str, allowed_extensions: set) -> bool:
    """
    Validate file extension against allowed list.
    
    Args:
        filename: Name of file to validate
        allowed_extensions: Set of allowed extensions (without dots)
        
    Returns:
        True if extension is allowed
    """
    if not filename or '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in allowed_extensions


def is_safe_file_path(base_path: str, file_path: str) -> bool:
    """
    Enhanced path validation for file operations.
    
    Args:
        base_path: Base directory path
        file_path: File path to validate
        
    Returns:
        True if path is safe
    """
    try:
        # Normalize paths
        base_path = os.path.abspath(base_path)
        file_path = os.path.abspath(file_path)
        
        # Check if base path exists
        if not os.path.exists(base_path):
            return False
        
        # Ensure file path is within base path
        return file_path.startswith(base_path + os.sep) or file_path == base_path
        
    except (OSError, ValueError):
        return False


def rate_limit_key_generator():
    """
    Generate rate limiting key based on IP and user agent.
    This provides better rate limiting than just IP address.
    """
    try:
        from flask import request  # type: ignore
        
        ip = request.remote_addr or "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")
        
        # Create a composite key
        key_data = f"{ip}:{user_agent}"
        return hashlib.md5(key_data.encode()).hexdigest()
    except RuntimeError:
        # Flask context not available
        return "no-context"


def validate_json_payload(
    data: dict,
    required_fields: List[str],
    optional_fields: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """
    Validate JSON payload structure and content.
    
    Args:
        data: JSON data to validate
        required_fields: List of required field names
        optional_fields: List of optional field names
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Dane muszą być w formacie JSON"
    
    # Check required fields
    for field in required_fields:
        if field not in data:
            return False, f"Pole '{field}' jest wymagane"
        
        if data[field] is None or (isinstance(data[field], str) and not data[field].strip()):
            return False, f"Pole '{field}' nie może być puste"
    
    # Check for unexpected fields
    all_fields = set(required_fields)
    if optional_fields is not None:
        all_fields.update(optional_fields)
    
    unexpected_fields = set(data.keys()) - all_fields
    if unexpected_fields:
        return False, f"Nieoczekiwane pola: {', '.join(unexpected_fields)}"
    
    return True, "Dane są poprawne"
