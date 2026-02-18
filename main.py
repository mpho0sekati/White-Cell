"""
White Cell: Main entry point for the cybersecurity CLI.

This script serves as the entry point for running the White Cell application.
It initializes and runs the enhanced interactive CLI shell.

Usage:
    python main.py
"""

from whitecell.cli_enhanced import EnhancedWhiteCellCLI
from whitecell.groq_client import groq_client

def main():
    """Start the enhanced CLI."""
    # Ensure Groq client loads any stored API key from config
    groq_client.reload_from_config()
    
    cli = EnhancedWhiteCellCLI()
    cli.start()

if __name__ == "__main__":
    main()
