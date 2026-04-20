"""
API Key Security Utilities

Provides secure hashing and masking for API keys.
"""

import hashlib
from typing import Tuple, Optional


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256 for secure storage.
    
    Args:
        api_key: The raw API key to hash
        
    Returns:
        SHA-256 hash of the API key (hex string)
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def mask_api_key(api_key: str) -> str:
    """Create a masked representation of an API key for display.
    
    Shows first 4 characters, ellipsis, and last 4 characters.
    
    Args:
        api_key: The raw API key to mask
        
    Returns:
        Masked API key (e.g., "sk-x...abc1")
    """
    if len(api_key) <= 8:
        return "***" + api_key[-2:] if len(api_key) > 2 else "***"
    
    return f"{api_key[:4]}...{api_key[-4:]}"


def get_api_key_status(api_key: Optional[str]) -> dict:
    """Get status info for an API key (hash and mask).
    
    Args:
        api_key: The raw API key (or None if not set)
        
    Returns:
        Dictionary with 'configured', 'masked', and 'hash' fields
    """
    if not api_key:
        return {
            "configured": False,
            "masked": None,
            "hash": None
        }
    
    return {
        "configured": True,
        "masked": mask_api_key(api_key),
        "hash": hash_api_key(api_key)[:16] + "..."  # Show first 16 chars of hash
    }


def verify_api_key_format(api_key: str, key_type: str = "groq") -> bool:
    """Basic validation of API key format.
    
    Args:
        api_key: The API key to validate
        key_type: Type of API key ("groq", "openai", etc.)
        
    Returns:
        True if format looks valid
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    if key_type == "groq":
        # Groq keys typically start with "gsk-" and are at least 30 chars
        return api_key.startswith("gsk-") and len(api_key) >= 30
    
    return len(api_key) >= 10
