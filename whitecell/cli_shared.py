"""Shared CLI objects and constants."""

from rich.console import Console

console = Console()

WHITECELL_LOGO = r"""
 __        ___   _ ___ _____ _____    ____ _____ _     _
 \ \      / / | | |_ _|_   _| ____|  / ___| ____| |   | |
  \ \ /\ / /| |_| || |  | | |  _|   | |   |  _| | |   | |
   \ V  V / |  _  || |  | | | |___  | |___| |___| |___| |___
    \_/\_/  |_| |_|___| |_| |_____|  \____|_____|_____|_____|
  [====[ SOC OPS ]====]  [====[ THREAT GRID ]====]  [===]
"""

CONTEXT_SUGGESTIONS = {
    "threat": "Try 'analyze <threat>' or 'search <term>'",
    "logs": "Try 'export csv' or 'search <threat>'",
    "agent": "Try 'agent blue <scenario>' or 'agent red <scenario>'",
    "help": "Type 'help' for full command list",
}

STATUS_STYLES = {
    "ok": "green",
    "warn": "yellow",
    "error": "red",
    "info": "cyan",
}

STATUS_LABELS = {
    "ok": "[OK]",
    "warn": "[WARN]",
    "error": "[ERROR]",
    "info": "[INFO]",
}
