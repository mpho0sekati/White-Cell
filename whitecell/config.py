"""
White Cell Configuration Management

This module handles configuration settings including API keys and agent settings.
Stores configuration securely in a config file.

Author: White Cell Project
"""

import json
import os
from pathlib import Path
from typing import Optional, Any


CONFIG_DIR = Path.home() / ".whitecell"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Default configuration
DEFAULT_CONFIG = {
    "groq_api_key": None,
    "agent_enabled": False,
    "agent_auto_start": False,
    "security_checks": [
        "malware_scan",
        "port_monitoring",
        "process_monitoring",
        "firewall_check",
        "system_logs"
    ],
    "check_interval": 60,  # seconds
    "max_threats": 10,
    "threat_threshold": 50,  # risk score
    "guardian": {
        "check_interval": 2.0,
        "prevention_rate_limit": 3,
        "window_seconds": 60,
        "per_agent": {}
    },
}


def ensure_config_dir() -> Path:
    """Ensure config directory exists."""
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    return CONFIG_DIR


def load_config() -> dict:
    """
    Load configuration from file.
    
    Returns:
        Configuration dictionary
    """
    ensure_config_dir()
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return {**DEFAULT_CONFIG, **config}
        except (json.JSONDecodeError, IOError):
            return DEFAULT_CONFIG.copy()
    
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> bool:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        ensure_config_dir()
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        # Set file permissions to readable only by owner
        os.chmod(CONFIG_FILE, 0o600)
        return True
    except IOError as e:
        print(f"Failed to save config: {e}")
        return False


def get_groq_api_key() -> Optional[str]:
    """
    Get GROQ API key from configuration.
    
    Returns:
        API key or None if not configured
    """
    config = load_config()
    return config.get("groq_api_key")


def set_groq_api_key(api_key: str) -> bool:
    """
    Set GROQ API key in configuration.
    
    Args:
        api_key: The API key to set
        
    Returns:
        True if successful
    """
    config = load_config()
    config["groq_api_key"] = api_key
    return save_config(config)


def is_agent_enabled() -> bool:
    """Check if agent is enabled."""
    config = load_config()
    return config.get("agent_enabled", False)


def set_agent_enabled(enabled: bool) -> bool:
    """
    Enable or disable the agent.
    
    Args:
        enabled: Whether to enable the agent
        
    Returns:
        True if successful
    """
    config = load_config()
    config["agent_enabled"] = enabled
    return save_config(config)


def get_config_value(key: str, default: Any = None) -> Any:
    """
    Get a configuration value.
    
    Args:
        key: Configuration key
        default: Default value if not found
        
    Returns:
        Configuration value or default
    """
    config = load_config()
    return config.get(key, default)


def set_config_value(key: str, value: Any) -> bool:
    """
    Set a configuration value.
    
    Args:
        key: Configuration key
        value: Value to set
        
    Returns:
        True if successful
    """
    config = load_config()
    config[key] = value
    return save_config(config)


def get_all_config() -> dict:
    """
    Get all configuration values (excluding API key for security).
    
    Returns:
        Configuration dictionary
    """
    config = load_config()
    # Don't expose the API key in full output
    safe_config = config.copy()
    if safe_config.get("groq_api_key"):
        safe_config["groq_api_key"] = "***CONFIGURED***"
    return safe_config


def validate_groq_api_key(api_key: str) -> bool:
    """
    Validate GROQ API key format (basic validation).
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if format is valid
    """
    if not api_key or not isinstance(api_key, str):
        return False
    # Groq API keys typically start with 'gsk_' and are fairly long
    return len(api_key.strip()) > 10


def get_guardian_config() -> dict:
    """
    Return guardian-related configuration (with defaults applied).
    """
    config = load_config()
    return config.get("guardian", DEFAULT_CONFIG.get("guardian", {}))
