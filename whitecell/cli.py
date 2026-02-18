"""
White Cell CLI: Command-line interface

This module provides the interactive shell for the White Cell cybersecurity assistant.
It uses Rich for terminal formatting and Python's built-in input loop for user interaction.

Author: White Cell Project
"""

import os

from rich.console import Console
from rich.table import Table

from whitecell.engine import get_session_logs, handle_input, initialize_logging, parse_command
from whitecell.groq_client import groq_client
from whitecell.state import global_state

console = Console()

GROQ_FEATURE_FLAG = "WHITECELL_ENABLE_GROQ"


class WhiteCellCLI:
    """Interactive command-line interface for White Cell cybersecurity assistant."""

    def __init__(self):
        """Initialize the CLI with global state."""
        self.state = global_state
        initialize_logging()

    def get_prompt(self) -> str:
        """
        Get the current prompt based on system state.

        Returns:
            Formatted prompt string
        """
        if self.state.command_mode:
            return "[bold red][CRISIS MODE] WhiteCell>[/bold red] "
        return "[bold cyan]WhiteCell>[/bold cyan] "

    @staticmethod
    def is_groq_feature_enabled() -> bool:
        """Return whether Groq commands are enabled via feature flag."""

        return os.getenv(GROQ_FEATURE_FLAG, "1").lower() not in {"0", "false", "off", "no"}

    @staticmethod
    def groq_status_text() -> str:
        """Return a human-readable Groq feature/configuration status."""

        if not WhiteCellCLI.is_groq_feature_enabled():
            return "DISABLED (set WHITECELL_ENABLE_GROQ=1 to enable commands)"
        if groq_client.is_configured():
            return "ENABLED (configured)"
        return "ENABLED (missing GROQ_API_KEY)"

    def display_help(self) -> None:
        """Display help information and available commands."""
        help_text = f"""
[bold green]═══════════════════════════════════════════════════════════════[/bold green]
[bold yellow]White Cell - Cybersecurity Assistant[/bold yellow]
[bold green]═══════════════════════════════════════════════════════════════[/bold green]

[bold cyan]Available Commands:[/bold cyan]
  [yellow]exit[/yellow]                 - Exit the application
  [yellow]help[/yellow]                 - Show this help message
  [yellow]status[/yellow]               - Show current system status
  [yellow]logs[/yellow]                 - Display threat detection logs
  [yellow]clear[/yellow]                - Clear Command Mode
  [yellow]explain <query>[/yellow]      - Ask optional Groq reasoning about a scenario
  [yellow]strategy <threat_type>[/yellow] - Ask optional Groq response strategy

[bold cyan]Usage:[/bold cyan]
  Simply type your query or describe a cybersecurity scenario.
  The system will:
  • Detect potential threats using keyword analysis
  • Calculate risk scores (0-100)
  • Provide recommended actions
  • Log all detected threats

[bold cyan]Command Mode:[/bold cyan]
  When a threat is detected:
  • The system enters CRISIS MODE
  • A risk assessment is displayed
  • Suggested actions are provided
  • Use 'clear' to exit Command Mode
  • All threats are logged to logs/threats.jsonl

[bold cyan]Groq Feature Status:[/bold cyan] {self.groq_status_text()}

[bold green]═══════════════════════════════════════════════════════════════[/bold green]
"""
        console.print(help_text)

    def display_status(self) -> None:
        """Display current system status."""
        status_table = Table(title="System Status", show_header=True, header_style="bold magenta")
        status_table.add_column("Parameter", style="cyan")
        status_table.add_column("Value", style="green")

        status_table.add_row("Command Mode", "[red]ACTIVE[/red]" if self.state.command_mode else "[green]INACTIVE[/green]")
        status_table.add_row("Session Logs", str(len(self.state.logs)))
        status_table.add_row("Last Threat", self.state.last_threat.get("threat_type", "None"))
        status_table.add_row("Groq", self.groq_status_text())

        console.print(status_table)

    def display_logs(self) -> None:
        """Display threat detection logs from file."""
        logs = get_session_logs()
        if not logs:
            console.print("[yellow]No threats have been detected yet.[/yellow]")
            return

        console.print(f"\n[bold cyan]Threat Detection Logs ({len(logs)} total):[/bold cyan]\n")

        logs_table = Table(show_header=True, header_style="bold magenta")
        logs_table.add_column("Timestamp", style="cyan")
        logs_table.add_column("Threat Type", style="yellow")
        logs_table.add_column("Risk Score", style="red")
        logs_table.add_column("Risk Level", style="red")
        logs_table.add_column("POPIA", style="red")

        for log in logs[-10:]:  # Show last 10 logs
            timestamp = log.get("timestamp", "")[-8:]  # Show time only
            threat_type = log.get("threat_type", "unknown")
            risk_score = str(log.get("risk_score", 0))
            risk_level = log.get("risk_level", "unknown")
            popia = "[red]YES[/red]" if log.get("popia_exposure", False) else "[green]NO[/green]"

            logs_table.add_row(timestamp, threat_type, risk_score, risk_level, popia)

        console.print(logs_table)

    def handle_command(self, command: str, args: list[str]) -> bool | None:
        """
        Handle built-in CLI commands.

        Args:
            command: The command to execute
            args: Command arguments

        Returns:
            True to continue the session, False to exit, or None if unrecognized
        """
        if command == "exit":
            console.print("[bold green]Exiting White Cell. Stay secure![/bold green]")
            return False

        if command == "help":
            self.display_help()
            return True

        if command == "status":
            self.display_status()
            return True

        if command == "logs":
            self.display_logs()
            return True

        if command == "clear":
            if self.state.command_mode:
                self.state.deactivate_command_mode()
                console.print("[green]Command Mode deactivated.[/green]")
            else:
                console.print("[yellow]Command Mode is not active.[/yellow]")
            return True

        if command == "explain":
            if not self.is_groq_feature_enabled():
                console.print("[yellow]Groq commands are disabled by feature flag.[/yellow]")
                return True
            query = " ".join(args).strip()
            if not query:
                console.print("[yellow]Usage: explain <query>[/yellow]")
                return True
            console.print(groq_client.get_explanation(query))
            return True

        if command == "strategy":
            if not self.is_groq_feature_enabled():
                console.print("[yellow]Groq commands are disabled by feature flag.[/yellow]")
                return True
            threat_type = " ".join(args).strip()
            if not threat_type:
                console.print("[yellow]Usage: strategy <threat_type>[/yellow]")
                return True
            console.print(groq_client.get_strategy(threat_type))
            return True

        return None

    def start(self) -> None:
        """Start the interactive CLI session."""
        console.print("[green]───────────── White Cell - Cybersecurity Assistant ──────────────[/green]")
        console.print("[yellow]Type 'help' for available commands[/yellow]\n")

        try:
            while self.state.session_active:
                # Get user input
                user_input = input(self.get_prompt())

                if not user_input.strip():
                    continue

                # Parse the input
                command, args = parse_command(user_input)

                # Handle built-in commands
                if command in ["exit", "help", "status", "logs", "clear", "explain", "strategy"]:
                    result = self.handle_command(command, args)
                    if result is False:
                        break
                    continue

                # Process as threat detection / reasoning input
                response = handle_input(user_input)
                console.print(response)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold green]Exiting White Cell. Stay secure![/bold green]")
            self.state.session_active = False


def main() -> None:
    """Entry point for the White Cell CLI."""
    cli = WhiteCellCLI()
    cli.start()


if __name__ == "__main__":
    main()
