"""
White Cell: Main entry point for the cybersecurity CLI.

This script serves as the entry point for running the White Cell application.
It initializes and runs the enhanced interactive CLI shell.

Usage:
    python main.py
"""

from whitecell.cli_enhanced import EnhancedWhiteCellCLI

def main():
    """Start the enhanced CLI."""
    cli = EnhancedWhiteCellCLI()
    cli.start()

if __name__ == "__main__":
    main()
