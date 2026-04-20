"""
Constants for White Cell.

This module contains all the constant values used across the White Cell application.
"""

# Command aliases
COMMAND_ALIASES = {
    "h": "help",
    "?": "help",
    "st": "status",
    "l": "logs",
    "t": "threats",
    "e": "export",
    "a": "analyze",
    "s": "search",
    "c": "clear",
    "q": "exit",
    "d": "dashboard",
    "p": "peek",
    "tr": "triage",
    "inv": "investigate",
    "rsp": "respond",
    "sf": "soc",
    "ag": "agent",
    "gov": "governance",
    "lg": "logo",
    "tt": "task",  # task command alias
    "ta": "trace",  # trace command alias
}

# Default log lines to show
DEFAULT_LOG_LINES = 10

# Maximum export lines
MAX_EXPORT_LINES = 10000

# Agent check intervals
AGENT_CHECK_INTERVAL_MIN = 5
AGENT_CHECK_INTERVAL_MAX = 3600

# Success message for agent start
SUCCESS_AGENT_STARTED = "Agent started successfully."

# Error messages
ERROR_INVALID_INPUT = "Invalid input."
WARN_NO_DATA = "No data available."
WARN_CANCELLED = "Cancelled."