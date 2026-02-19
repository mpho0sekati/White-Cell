"""
White Cell CLI: Command-line interface

This module provides the interactive shell for the White Cell cybersecurity assistant.
It uses Rich for terminal formatting and Python's built-in input loop for user interaction.

Author: White Cell Project
"""

import os
import time
from datetime import datetime
from difflib import get_close_matches

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from whitecell.engine import get_session_logs, handle_input, initialize_logging, parse_command
from whitecell.groq_client import groq_client
from whitecell.state import global_state
from whitecell.system_guard import scan_system

console = Console()

GROQ_FEATURE_FLAG = "WHITECELL_ENABLE_GROQ"
BUILTIN_COMMANDS = ("exit", "help", "status", "logs", "clear", "explain", "strategy", "crew", "immune", "brain")


class WhiteCellCLI:
    """Interactive command-line interface for White Cell cybersecurity assistant."""

    def __init__(self):
        """Initialize the CLI with global state."""
        self.state = global_state
        initialize_logging()

        agent_name = os.getenv("WHITECELL_AGENT_NAME", "main-agent")
        drive_enabled = os.getenv("WHITECELL_GOOGLE_DRIVE_ENABLED", "0").lower() in {"1", "true", "yes", "on"}
        drive_folder = os.getenv("WHITECELL_GOOGLE_DRIVE_FOLDER_ID")
        drive_service_account = os.getenv("WHITECELL_GOOGLE_SERVICE_ACCOUNT_FILE")
        self.state.initialize_brain(
            agent_name=agent_name,
            google_drive_enabled=drive_enabled,
            google_drive_folder_id=drive_folder,
            google_service_account_file=drive_service_account,
        )

    @staticmethod
    def suggest_command(command: str) -> str | None:
        """Suggest a known command for near-miss input typos."""

        if not command:
            return None
        matches = get_close_matches(command, BUILTIN_COMMANDS, n=1, cutoff=0.75)
        return matches[0] if matches else None

    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """Format an ISO timestamp for compact table display."""

        if not timestamp:
            return "-"
        try:
            return datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return timestamp

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
            return "ENABLED (configured, placeholder responses)"
        return "ENABLED (missing GROQ_API_KEY)"

    @staticmethod
    def persisted_log_count() -> int:
        """Return count of persisted log entries from JSONL storage."""

        try:
            return len(get_session_logs())
        except OSError:
            return 0

    def display_help(self) -> None:
        """Display help information and available commands."""
        table = Table(title="White Cell Commands", show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="green")
        table.add_row("help", "Show this help message")
        table.add_row("status", "Show current command mode, logs, and Groq status")
        table.add_row("logs", "Display the latest threat detections from JSONL logs")
        table.add_row("clear", "Exit CRISIS MODE if active")
        table.add_row("explain <query>", "Optional Groq reasoning (placeholder response)")
        table.add_row("strategy <threat_type>", "Optional Groq strategy guidance (placeholder response)")
        table.add_row("crew spawn <name> [role]", "Create a helper agent for incident support")
        table.add_row("crew report", "Show helper crew status and recent activity")
        table.add_row("crew learn <name> <technique> | <conversation>", "Store helper lessons for main agent memory")
        table.add_row("crew memory [name]", "Show learned techniques/conversations from helpers")
        table.add_row("crew watch [seconds]", "Live watch helper activity stream")
        table.add_row("immune scan", "Run a host-level immune scan on this system")
        table.add_row("immune report", "Show recent immune scan summaries")
        table.add_row("brain status", "Show main-agent memory storage status")
        table.add_row("brain sync", "Safely sync brain memory to Google Drive (optional)")
        table.add_row("exit", "Exit the application")

        console.print(table)
        console.print(f"[bold cyan]Groq Feature Status:[/bold cyan] {self.groq_status_text()}")
        console.print("[dim]Tip:[/dim] Type a scenario in plain language to run threat detection.")

    def display_status(self) -> None:
        """Display current system status."""
        status_table = Table(title="System Status", show_header=True, header_style="bold magenta")
        status_table.add_column("Parameter", style="cyan")
        status_table.add_column("Value", style="green")

        status_table.add_row("Command Mode", "[red]ACTIVE[/red]" if self.state.command_mode else "[green]INACTIVE[/green]")
        status_table.add_row("Session Logs (in-memory)", str(len(self.state.logs)))
        status_table.add_row("Persisted Logs", str(self.persisted_log_count()))
        status_table.add_row("Last Threat", self.state.last_threat.get("threat_type", "None"))
        status_table.add_row("Groq", self.groq_status_text())
        status_table.add_row("Immune Scans", str(len(self.state.immune_history)))
        status_table.add_row("Learned Techniques", str(len(self.state.get_collective_techniques())))
        status_table.add_row("Brain Agent", self.state.brain_agent_name)

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
            timestamp = self.format_timestamp(log.get("timestamp", ""))
            threat_type = log.get("threat_type", "unknown")
            risk_score = str(log.get("risk_score", 0))
            risk_level = log.get("risk_level", "unknown")
            popia = "[red]YES[/red]" if log.get("popia_exposure", False) else "[green]NO[/green]"

            logs_table.add_row(timestamp, threat_type, risk_score, risk_level, popia)

        console.print(logs_table)


    def display_crew_report(self) -> None:
        """Display helper crew roster and recent activity."""

        if not self.state.helper_crew:
            console.print("[yellow]No helpers spawned yet. Use: crew spawn <name> [role][/yellow]")
            return

        crew_table = Table(title="Helper Crew", show_header=True, header_style="bold magenta")
        crew_table.add_column("Name", style="cyan")
        crew_table.add_column("Role", style="green")
        crew_table.add_column("Status", style="yellow")
        crew_table.add_column("Tasks", style="red")
        crew_table.add_column("Techniques", style="white")

        for helper in self.state.helper_crew:
            crew_table.add_row(
                helper.get("name", "helper"),
                helper.get("role", "analyst"),
                helper.get("status", "idle"),
                str(helper.get("tasks_completed", 0)),
                ", ".join(helper.get("techniques", [])) or "-",
            )

        console.print(crew_table)

        if self.state.helper_activity:
            activity_table = Table(title="Recent Helper Activity", show_header=True, header_style="bold blue")
            activity_table.add_column("Time", style="cyan")
            activity_table.add_column("Helper", style="green")
            activity_table.add_column("Activity", style="white")
            activity_table.add_column("Status", style="yellow")

            for event in self.state.helper_activity[-10:]:
                activity_table.add_row(
                    self.format_timestamp(event.get("timestamp", "")),
                    event.get("helper", "helper"),
                    event.get("activity", ""),
                    event.get("status", "unknown"),
                )
            console.print(activity_table)



    def display_crew_memory(self, helper_name: str | None = None) -> None:
        """Display remembered helper conversations and techniques."""

        memories = self.state.get_helper_memories(helper_name)
        if not memories:
            scope = helper_name or "all helpers"
            console.print(f"[yellow]No learned memory for {scope}. Use: crew learn <name> <technique> | <conversation>[/yellow]")
            return

        table = Table(title="Helper Learning Memory", show_header=True, header_style="bold magenta")
        table.add_column("Time", style="cyan")
        table.add_column("Helper", style="green")
        table.add_column("Techniques", style="yellow")
        table.add_column("Conversation", style="white")

        for memory in memories[-15:]:
            table.add_row(
                self.format_timestamp(memory.get("timestamp", "")),
                memory.get("helper", "helper"),
                ", ".join(memory.get("techniques", [])) or "-",
                memory.get("conversation", "")[:100],
            )

        console.print(table)
        collective = self.state.get_collective_techniques()
        if collective:
            console.print(f"[bold cyan]Collective Techniques:[/bold cyan] {', '.join(collective)}")


    def display_brain_status(self) -> None:
        """Display brain storage status and memory footprint."""

        storage = self.state.brain_storage
        if storage is None:
            console.print("[yellow]Brain storage is not initialized.[/yellow]")
            return

        table = Table(title="Brain Memory Status", show_header=True, header_style="bold magenta")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Agent Name", self.state.brain_agent_name)
        table.add_row("Memory Entries", str(len(self.state.helper_learning)))
        table.add_row("Collective Techniques", str(len(self.state.get_collective_techniques())))
        table.add_row("Local Brain File", str(storage.local_file))
        table.add_row("Google Drive Enabled", "YES" if storage.config.google_drive_enabled else "NO")
        table.add_row("Last Drive Sync", self.format_timestamp(self.state.brain_last_sync or ""))

        console.print(table)

    def display_immune_report(self) -> None:
        """Display recent host immune-scan summaries."""

        if not self.state.immune_history:
            console.print("[yellow]No immune scans yet. Run: immune scan[/yellow]")
            return

        table = Table(title="Host Immune Scan History", show_header=True, header_style="bold magenta")
        table.add_column("Time", style="cyan")
        table.add_column("Host", style="green")
        table.add_column("Risk", style="yellow")
        table.add_column("Connections", style="red")
        table.add_column("Findings", style="white")

        for item in self.state.immune_history[-10:]:
            findings = item.get("findings", [])
            finding_summary = "; ".join(f.get("signal", "signal") for f in findings) if findings else "none"
            table.add_row(
                self.format_timestamp(item.get("timestamp", "")),
                item.get("hostname", "host"),
                item.get("risk_level", "low").upper(),
                str(item.get("established_connections", 0)),
                finding_summary,
            )

        console.print(table)

    def display_crew_watch(self, duration_seconds: int = 8) -> None:
        """Live-watch helper activity for a short duration."""

        if duration_seconds < 1:
            duration_seconds = 1

        def _build_activity_table() -> Table:
            table = Table(title="Helper Activity Watch", show_header=True, header_style="bold magenta")
            table.add_column("Time", style="cyan")
            table.add_column("Helper", style="green")
            table.add_column("Activity", style="white")
            table.add_column("Status", style="yellow")

            rows = self.state.helper_activity[-12:] or [{"timestamp": "", "helper": "-", "activity": "No activity yet", "status": "idle"}]
            for event in rows:
                table.add_row(
                    self.format_timestamp(event.get("timestamp", "")),
                    event.get("helper", "-"),
                    event.get("activity", ""),
                    event.get("status", ""),
                )
            return table

        with Live(_build_activity_table(), console=console, refresh_per_second=4) as live:
            end_time = time.time() + duration_seconds
            while time.time() < end_time:
                live.update(_build_activity_table())
                time.sleep(0.25)

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

        if command == "crew":
            if not args:
                console.print("[yellow]Usage: crew <spawn|report|learn|memory|watch> ...[/yellow]")
                return True

            subcommand = args[0].lower()

            if subcommand == "spawn":
                if len(args) < 2:
                    console.print("[yellow]Usage: crew spawn <name> [role][/yellow]")
                    return True
                name = args[1]
                role = " ".join(args[2:]).strip() or "incident analyst"

                if self.state.get_helper(name):
                    console.print(f"[yellow]Helper '{name}' already exists.[/yellow]")
                    return True

                self.state.spawn_helper(name, role)
                console.print(f"[green]Helper spawned:[/green] {name} ({role})")
                return True

            if subcommand == "report":
                self.display_crew_report()
                return True


            if subcommand == "learn":
                payload = " ".join(args[1:]).strip()
                if not payload or "|" not in payload:
                    console.print("[yellow]Usage: crew learn <name> <technique1,technique2> | <conversation>[/yellow]")
                    return True

                left, conversation = payload.split("|", maxsplit=1)
                left = left.strip()
                conversation = conversation.strip()

                if not left or not conversation:
                    console.print("[yellow]Both technique and conversation are required.[/yellow]")
                    return True

                parts = left.split(maxsplit=1)
                if len(parts) < 2:
                    console.print("[yellow]Usage: crew learn <name> <technique1,technique2> | <conversation>[/yellow]")
                    return True

                name = parts[0]
                techniques = [t.strip() for t in parts[1].split(",") if t.strip()]
                if not techniques:
                    console.print("[yellow]At least one technique is required.[/yellow]")
                    return True

                self.state.learn_from_helper(name, conversation, techniques)
                self.state.record_helper_activity(name, "shared learning with main agent", "learning")
                console.print(f"[green]Main agent learned from {name}:[/green] {', '.join(techniques)}")
                return True

            if subcommand == "memory":
                helper_name = args[1] if len(args) > 1 else None
                self.display_crew_memory(helper_name)
                return True

            if subcommand == "watch":
                watch_seconds = 8
                if len(args) > 1 and args[1].isdigit():
                    watch_seconds = int(args[1])
                self.display_crew_watch(watch_seconds)
                return True

            console.print("[yellow]Unknown crew command. Use spawn, report, learn, memory, or watch.[/yellow]")
            return True

        if command == "brain":
            if not args:
                console.print("[yellow]Usage: brain <status|sync>[/yellow]")
                return True

            subcommand = args[0].lower()
            if subcommand == "status":
                self.display_brain_status()
                return True

            if subcommand == "sync":
                ok, message = self.state.sync_brain_to_google_drive()
                color = "green" if ok else "yellow"
                console.print(f"[{color}]{message}[/{color}]")
                return True

            console.print("[yellow]Unknown brain command. Use status or sync.[/yellow]")
            return True

        if command == "immune":
            if not args:
                console.print("[yellow]Usage: immune <scan|report>[/yellow]")
                return True

            subcommand = args[0].lower()
            if subcommand == "scan":
                scan_result = scan_system()
                self.state.add_immune_scan(scan_result)

                risk = scan_result.get("risk_level", "low").upper()
                risk_color = "red" if risk == "HIGH" else "yellow" if risk == "MEDIUM" else "green"
                console.print(
                    Panel.fit(
                        f"[bold]Host:[/bold] {scan_result.get('hostname')}\n"
                        f"[bold]Risk:[/bold] [{risk_color}]{risk}[/{risk_color}]\n"
                        f"[bold]Established Connections:[/bold] {scan_result.get('established_connections', 0)}\n"
                        f"[bold]Recommendation:[/bold] {scan_result.get('recommendation', '')}",
                        title="Immune Scan Result",
                        border_style=risk_color,
                    )
                )
                findings = scan_result.get("findings", [])
                if findings:
                    findings_table = Table(title="Immune Findings", show_header=True, header_style="bold red")
                    findings_table.add_column("Signal", style="yellow")
                    findings_table.add_column("Severity", style="red")
                    findings_table.add_column("Details", style="white")
                    for finding in findings:
                        findings_table.add_row(
                            finding.get("signal", "signal"),
                            finding.get("severity", "unknown"),
                            finding.get("details", ""),
                        )
                    console.print(findings_table)
                return True

            if subcommand == "report":
                self.display_immune_report()
                return True

            console.print("[yellow]Unknown immune command. Use scan or report.[/yellow]")
            return True

        return None

    def start(self) -> None:
        """Start the interactive CLI session."""
        console.print(
            Panel.fit(
                "[bold green]White Cell - Cybersecurity Assistant[/bold green]\n"
                "Type [cyan]help[/cyan] for commands or describe a security incident.",
                border_style="green",
            )
        )

        try:
            while self.state.session_active:
                # Get user input
                user_input = input(self.get_prompt())

                if not user_input.strip():
                    continue

                # Parse the input
                command, args = parse_command(user_input)

                # Handle built-in commands
                if command in BUILTIN_COMMANDS:
                    result = self.handle_command(command, args)
                    if result is False:
                        break
                    continue

                # UX guardrail: suggest likely command typos before threat detection
                if command and not args:
                    suggestion = self.suggest_command(command)
                    if suggestion:
                        console.print(
                            f"[yellow]Unknown command:[/yellow] '{command}'. "
                            f"Did you mean [cyan]{suggestion}[/cyan]?"
                        )
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
