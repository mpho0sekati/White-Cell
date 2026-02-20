"""
White Cell Enhanced CLI: Improved User Interface and Experience

This module provides an enhanced interactive shell with:
- Beautiful visual formatting with Rich components
- Intuitive command system with smart prompts
- Interactive menus for complex operations
- Real-time progress indicators
- Context-aware help and suggestions
- Dashboard-style status displays

Author: White Cell Project
"""

import json
import csv
import time
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.spinner import Spinner
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.align import Align

from whitecell.engine import handle_input, parse_command, initialize_logging, get_session_logs
from whitecell.detection import get_all_threats, get_threat_description
from whitecell.state import global_state
from whitecell.command_mode import create_risk_table
from whitecell.agent import agent_manager
from whitecell.crew import crew_manager
from whitecell.config import (
    load_config,
    set_groq_api_key,
    get_groq_api_key,
    validate_groq_api_key,
    get_scan_allowlist,
    set_scan_allowlist,
    get_governance_role,
    set_governance_role,
    get_approval_required_actions,
    set_approval_required_actions,
)
from whitecell.groq_client import groq_client
from whitecell.self_improve import self_improver
from whitecell.website_scanner import website_scanner
from whitecell import governance

try:
    from whitecell.logging_config import get_logger
except ImportError:
    def get_logger(name: str):
        return logging.getLogger(name)

try:
    from whitecell.constants import (
        COMMAND_ALIASES,
        DEFAULT_LOG_LINES,
        MAX_EXPORT_LINES,
        AGENT_CHECK_INTERVAL_MIN,
        AGENT_CHECK_INTERVAL_MAX,
        SUCCESS_AGENT_STARTED,
        ERROR_INVALID_INPUT,
        WARN_NO_DATA,
        WARN_CANCELLED,
    )
except ImportError:
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
    }
    DEFAULT_LOG_LINES = 10
    MAX_EXPORT_LINES = 10000
    AGENT_CHECK_INTERVAL_MIN = 5
    AGENT_CHECK_INTERVAL_MAX = 3600
    SUCCESS_AGENT_STARTED = "Agent started successfully."
    ERROR_INVALID_INPUT = "Invalid input."
    WARN_NO_DATA = "No data available."
    WARN_CANCELLED = "Cancelled."

console = Console()
logger = get_logger(__name__)

WHITECELL_LOGO = r"""
 __        ___     _ _         ____     _ _
 \ \      / / |__ (_) |_ ___  / ___|___| | |
  \ \ /\ / /| '_ \| | __/ _ \| |   / _ \ | |
   \ V  V / | | | | | ||  __/| |__|  __/ | |
    \_/\_/  |_| |_|_|\__\___| \____\___|_|_|
"""

# Quick command suggestions based on context
CONTEXT_SUGGESTIONS = {
    "threat": "Try 'analyze <threat>' or 'search <term>'",
    "logs": "Try 'export csv' or 'search <threat>'",
    "agent": "Try 'agent blue <scenario>' or 'agent red <scenario>'",
    "help": "Type 'help' for full command list",
}


class EnhancedWhiteCellCLI:
    """Enhanced interactive CLI with improved UX and visual design."""

    def __init__(self) -> None:
        """Initialize the enhanced CLI."""
        self.state = global_state
        self.session_threats = []
        self.command_history = []
        initialize_logging()
        self.show_tips = True
        self._menu_hint_shown = False
        self.role = get_governance_role()

    def expand_alias(self, command: str) -> str:
        """Expand command aliases."""
        return COMMAND_ALIASES.get(command, command)

    def _section_header(self, title: str, subtitle: Optional[str] = None) -> None:
        """Render consistent section header style."""
        body = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            body += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(body, border_style="cyan", expand=False))

    def _check_permission(self, capability: str, action_name: str) -> bool:
        """Enforce RBAC for command capabilities."""
        self.role = get_governance_role()
        if governance.has_permission(capability, self.role):
            governance.audit_event("rbac", action_name, self.role, "allowed", {"capability": capability})
            return True
        governance.audit_event("rbac", action_name, self.role, "denied", {"capability": capability})
        console.print(f"[red]Access denied for role '{self.role}' on '{action_name}'.[/red]")
        return False

    def get_prompt(self) -> str:
        """Get dynamic prompt based on state."""
        if self.state.command_mode:
            return "[bold red]WHITE CELL [CRISIS MODE] >[/bold red] "
        
        threat_count = len(self.session_threats)
        if threat_count > 5:
            return f"[bold red]WHITE CELL ({threat_count} critical) >[/bold red] "
        elif threat_count > 0:
            return f"[bold yellow]WHITE CELL ({threat_count} threats) >[/bold yellow] "
        
        return "[bold cyan]WHITE CELL >[/bold cyan] "

    def display_logo(self) -> None:
        """Render the White Cell logo."""
        console.print(Panel(
            f"[bold cyan]{WHITECELL_LOGO}[/bold cyan]",
            title="WHITE CELL",
            border_style="blue",
            expand=False,
        ))

    def display_banner(self) -> None:
        """Display startup banner with logo and quick guidance."""
        console.clear()
        self.display_logo()
        console.print(Panel(
            "[bold cyan]Detection | Prevention | Intelligence | Protection[/bold cyan]\n"
            "[dim]Type 'help' for command map, 'triage' to start SOC flow, 'peek' for live monitoring.[/dim]",
            title="Cybersecurity Assistant",
            border_style="cyan",
            expand=False,
        ))

    def display_dashboard(self) -> None:
        """Display a dashboard-style status view."""
        console.clear()
        # Get statistics
        logs = get_session_logs()
        agent_stats = agent_manager.get_global_statistics()
        threat_types = [log.get('threat_type', 'unknown') for log in logs]
        threat_counts = Counter(threat_types)
        
        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_text = "[bold cyan]WHITE CELL SECURITY DASHBOARD[/bold cyan]"
        layout["header"].update(Panel(header_text, style="cyan"))
        
        # Body - split into sections
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Left side - Statistics
        stats_text = f"""
[bold]System Statistics[/bold]
━━━━━━━━━━━━━━━━━━━━━━
Session Threats:    {len(logs)}
Total Detected:     {agent_stats['total_threats_detected']}
Threats Prevented:  {agent_stats['total_prevented']}
Active Agents:      {agent_stats['running_agents']}/{agent_stats['total_agents']}

[bold]Top Threats[/bold]
━━━━━━━━━━━━━━━━━━━━━━
"""
        for threat_type, count in threat_counts.most_common(3):
            stats_text += f"{threat_type}: {count}\n"
        
        layout["left"].update(Panel(stats_text, style="cyan", title="Dashboard"))
        
        # Right side - Agent Status
        agent_text = "[bold]Agent Status[/bold]\n"
        agent_text += "━━━━━━━━━━━━━━━━━━━━━━\n"
        
        for agent_id, status in agent_manager.get_all_status().items():
            running = "UP" if status['running'] else "DOWN"
            agent_text += f"{running} {agent_id[:15]}\n"
            agent_text += f"   Checks: {status['checks_performed']}\n"
            agent_text += f"   Threats: {status['threats_detected']}\n"
        
        if not agent_manager.agents:
            agent_text += "[yellow]No agents deployed[/yellow]\n"
        
        layout["right"].update(Panel(agent_text, style="green", title="Agents"))
        
        # Footer
        footer_text = "[dim]Press Ctrl+C to exit dashboard | Dashboard updates every 5 seconds[/dim]"
        layout["footer"].update(Align.center(footer_text))
        
        console.print(layout)

    def display_peek_window(self, refresh_seconds: float = 1.0) -> None:
        """Display a continuously updating live monitoring window."""
        if refresh_seconds <= 0:
            refresh_seconds = 1.0

        def build_layout() -> Layout:
            logs = get_session_logs()
            recent_logs = logs[-6:]
            recent_events = agent_manager.global_log[-8:]
            agent_stats = agent_manager.get_global_statistics()
            running_agents = agent_stats.get("running_agents", 0)
            total_agents = agent_stats.get("total_agents", 0)
            command_mode = "ACTIVE" if self.state.command_mode else "INACTIVE"

            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3),
            )
            layout["body"].split_row(
                Layout(name="left", ratio=1),
                Layout(name="right", ratio=2),
            )
            layout["right"].split_column(
                Layout(name="logs"),
                Layout(name="events"),
            )

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            header_text = f"[bold cyan]WHITE CELL PEEK WINDOW[/bold cyan]  [dim]{now}[/dim]"
            layout["header"].update(Panel(header_text, border_style="cyan"))

            summary = (
                f"[bold]System Snapshot[/bold]\n"
                f"Command Mode: [yellow]{command_mode}[/yellow]\n"
                f"Running Agents: [green]{running_agents}/{total_agents}[/green]\n"
                f"Threat Logs: [red]{len(logs)}[/red]\n"
                f"Preventions: [green]{agent_stats.get('total_prevented', 0)}[/green]\n"
                f"Checks Performed: [cyan]{agent_stats.get('total_checks_performed', 0)}[/cyan]"
            )
            layout["left"].update(Panel(summary, title="Live Status", border_style="green"))

            logs_table = Table(title="Recent Threat Logs", show_header=True, header_style="bold magenta", expand=True)
            logs_table.add_column("Time", style="cyan", width=19, no_wrap=True)
            logs_table.add_column("Type", style="yellow", min_width=12, overflow="ellipsis")
            logs_table.add_column("Risk", style="red", width=6, no_wrap=True)
            logs_table.add_column("Input", overflow="ellipsis")
            if recent_logs:
                for log in recent_logs:
                    logs_table.add_row(
                        str(log.get("timestamp", ""))[:19],
                        str(log.get("threat_type", "unknown")),
                        str(log.get("risk_score", "-")),
                        str(log.get("user_input", ""))[:40],
                    )
            else:
                logs_table.add_row("-", "No threats logged yet", "-", "-")
            layout["right"]["logs"].update(logs_table)

            events_table = Table(title="Recent Agent Events", show_header=True, header_style="bold magenta", expand=True)
            events_table.add_column("Time", style="cyan", width=19, no_wrap=True)
            events_table.add_column("Event", style="yellow", min_width=12, overflow="ellipsis")
            events_table.add_column("Agent", style="green", min_width=10, overflow="ellipsis")
            events_table.add_column("Detail", overflow="ellipsis")
            if recent_events:
                for ev in recent_events:
                    data = ev.get("data", {}) if isinstance(ev.get("data", {}), dict) else {}
                    detail = ev.get("action") or ev.get("threat_type") or data.get("threat_type") or ""
                    agent_id = ev.get("agent_id") or data.get("agent_id") or "-"
                    events_table.add_row(
                        str(ev.get("timestamp", ""))[:19],
                        str(ev.get("event", "unknown")),
                        str(agent_id),
                        str(detail)[:36],
                    )
            else:
                events_table.add_row("-", "No agent events yet", "-", "-")
            layout["right"]["events"].update(events_table)

            footer_text = f"[dim]Refresh: {refresh_seconds:.1f}s | Press Ctrl+C to close peek window[/dim]"
            layout["footer"].update(Align.center(footer_text))
            return layout

        try:
            with Live(build_layout(), refresh_per_second=4, console=console, screen=True) as live:
                while True:
                    time.sleep(refresh_seconds)
                    live.update(build_layout())
        except KeyboardInterrupt:
            console.print("\n[yellow]Peek window closed[/yellow]")

    def display_help(self) -> None:
        """Display comprehensive help with categories."""
        console.clear()

        self._section_header("WHITE CELL COMMAND REFERENCE", "SOC-first workflow enabled")

        console.print()
        self._section_header("CORE COMMANDS")
        core_table = Table(show_header=True, header_style="bold magenta", show_lines=False)
        core_table.add_column("Command", style="cyan", width=15)
        core_table.add_column("Alias", style="yellow", width=8)
        core_table.add_column("Description", width=40)
        core_commands = [
            ("help", "h, ?", "Show this help message"),
            ("logo", "lg", "Show White Cell logo"),
            ("exit", "q", "Exit the application"),
            ("status", "st", "Display system status"),
            ("dashboard", "d", "Show live dashboard view"),
            ("peek", "p", "Open live peek monitoring window"),
            ("clear", "c", "Exit Command Mode"),
        ]
        for cmd, alias, desc in core_commands:
            core_table.add_row(cmd, alias, desc)
        console.print(core_table)

        console.print()
        self._section_header("SOC WORKFLOW")
        soc_table = Table(show_header=True, header_style="bold magenta")
        soc_table.add_column("Command", style="cyan", width=30)
        soc_table.add_column("Description", width=40)
        soc_commands = [
            ("triage (tr) <alert_text>", "Classify alert and recommend next steps"),
            ("investigate (inv) <threat|index>", "Build context from matching logs"),
            ("respond (rsp) recommend <incident>", "Generate response plan"),
            ("respond (rsp) execute <action> <target>", "Queue/execute governed response action"),
            ("soc (sf) run <alert> [--execute a t]", "Run triage -> investigate -> respond"),
        ]
        for cmd, desc in soc_commands:
            soc_table.add_row(cmd, desc)
        console.print(soc_table)

        console.print()
        self._section_header("THREAT MANAGEMENT")
        threat_table = Table(show_header=True, header_style="bold magenta")
        threat_table.add_column("Command", style="cyan", width=25)
        threat_table.add_column("Description", width=45)
        threat_commands = [
            ("threats (t)", "View all 9 threat types"),
            ("logs (l) [limit]", "Show latest threat logs"),
            ("search (s) <term>", "Search logs by threat type"),
            ("analyze (a) <type>", "Analyze specific threat"),
            ("export (e) [csv|json]", "Export logs to file"),
            ("scan website <url> [--active]", "Authorized website security analysis"),
            ("scan allowlist show", "List domains approved for active probing"),
            ("scan allowlist add <domain>", "Approve a domain for active probing"),
            ("scan allowlist remove <domain>", "Remove a domain from active probing allowlist"),
        ]
        for cmd, desc in threat_commands:
            threat_table.add_row(cmd, desc)
        console.print(threat_table)

        console.print()
        self._section_header("AGENT MANAGEMENT")
        agent_table = Table(show_header=True, header_style="bold magenta")
        agent_table.add_column("Command", style="cyan", width=35)
        agent_table.add_column("Description", width=35)
        agent_commands = [
            ("agent deploy <name> [interval]", "Deploy a new agent"),
            ("agent (ag) stop <name>", "Stop a running agent"),
            ("agent status", "View all agents status"),
            ("agent threats <name> [limit]", "View agent-specific threats"),
            ("agent configure", "Setup GROQ API key"),
            ("agent blue <scenario>", "Run Blue Team defensive strategy"),
            ("agent red <scenario>", "Run Red Team authorized simulation"),
            ("agent battle <scenario>", "Run Blue vs Red scenario"),
            ("agent ask <prompt>", "General AI cybersecurity prompt"),
            ("agent crewai <objective>", "Run CrewAI mission with current API key"),
            ("agent evolve <cmd>", "Autonomous self-improvement controls"),
        ]
        for cmd, desc in agent_commands:
            agent_table.add_row(cmd, desc)
        console.print(agent_table)

        console.print()
        self._section_header("GOVERNANCE")
        gov_table = Table(show_header=True, header_style="bold magenta")
        gov_table.add_column("Command", style="cyan", width=40)
        gov_table.add_column("Description", width=30)
        gov_commands = [
            ("governance (gov) status", "Show role, policy, and pending approvals"),
            ("governance role <admin|analyst|viewer>", "Set active operator role"),
            ("governance approvals list", "List approval requests"),
            ("governance approvals approve <id>", "Approve pending request"),
            ("governance approvals reject <id>", "Reject pending request"),
        ]
        for cmd, desc in gov_commands:
            gov_table.add_row(cmd, desc)
        console.print(gov_table)

        console.print()
        self._section_header("QUICK TIPS")
        tips = [
            "[cyan]-[/cyan] Type partial commands - they auto-complete",
            "[cyan]-[/cyan] Use aliases for faster typing: 't' for 'threats', 's' for 'search'",
            "[cyan]-[/cyan] SOC default flow: triage -> investigate -> respond",
            "[cyan]-[/cyan] Try 'dashboard' or 'peek' for live visibility",
            "[cyan]-[/cyan] Commands are case-insensitive",
            "[cyan]-[/cyan] 'agent configure' is optional - system works without GROQ",
        ]
        for tip in tips:
            console.print(f"  {tip}")
        console.print()
    def display_quick_menu(self) -> Optional[str]:
        """Display a quick interactive menu."""
        console.print()
        self._section_header("QUICK MENU")
        menu_options = [
            ("1", "View Threats", "See all threat types"),
            ("2", "Check Status", "System status report"),
            ("3", "Deploy Agent", "Start new agent"),
            ("4", "View Dashboard", "Live threat dashboard"),
            ("5", "Configure GROQ AI", "Setup API key (optional)"),
            ("6", "View Logs", "Recent threat logs"),
            ("7", "Export Data", "Save logs to file"),
            ("8", "Peek Window", "Continuous live monitoring"),
            ("9", "Show Logo", "Display White Cell logo"),
            ("0", "Back to CLI", "Return to command line"),
        ]
        
        menu_table = Table(show_header=False, show_lines=False)
        for key, option, desc in menu_options:
            menu_table.add_row(f"[yellow]{key}[/yellow]", f"[cyan]{option}[/cyan]", f"[dim]{desc}[/dim]")
        
        console.print(menu_table)
        
        choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])
        return choice

    def handle_menu_selection(self, choice: str) -> bool:
        """Handle menu selection."""
        if choice == "1":
            self.display_threat_types()
        elif choice == "2":
            self.display_status()
        elif choice == "3":
            self.deploy_agent_interactive()
        elif choice == "4":
            try:
                self.display_dashboard()
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard closed[/yellow]")
        elif choice == "5":
            self.configure_groq_api()
        elif choice == "6":
            self.display_logs(10)
        elif choice == "7":
            self.export_logs_interactive()
        elif choice == "8":
            self.display_peek_window()
        elif choice == "9":
            self.display_logo()
        elif choice == "0":
            return True
        
        return False

    def display_threat_types(self) -> None:
        """Display all threat types with enhanced formatting."""
        threats = get_all_threats()
        
        console.print()
        self._section_header("THREAT TYPES", "9 total known classes")
        
        table = Table(show_header=True, header_style="bold white on red", padding=(0, 1))
        table.add_column("Type", style="red", width=18)
        table.add_column("Severity", width=12)
        table.add_column("Financial Risk", style="green", width=15)
        table.add_column("POPIA", width=8)
        table.add_column("Description", width=30)
        
        for threat in threats:
            severity = threat['severity']
            severity_color = "red" if severity >= 8 else "yellow" if severity >= 6 else "green"
            severity_bar = "#" * severity + "-" * (10 - severity)
            
            popia = "[red]YES[/red]" if threat['popia_exposure'] else "[green]NO[/green]"
            
            table.add_row(
                f"[bold]{threat['threat_type']}[/bold]",
                f"[{severity_color}]{severity_bar}[/{severity_color}]",
                f"${threat['financial_impact']:,}",
                popia,
                threat['description'][:28] + "..." if len(threat['description']) > 28 else threat['description']
            )
        
        console.print(table)

    def display_status(self) -> None:
        """Display enhanced status report."""
        logs = get_session_logs()  # Reads from persistent threats.json file
        threat_types = [log.get('threat_type', 'unknown') for log in logs]
        threat_counts = Counter(threat_types)
        agent_stats = agent_manager.get_global_statistics()
        
        console.print("\n[bold cyan]SYSTEM STATUS[/bold cyan]\n")
        
        # System Health Panel
        health_level = "HEALTHY" if len(logs) == 0 else "MONITORING" if len(logs) < 5 else "CRITICAL"
        health_color = "green" if len(logs) == 0 else "yellow" if len(logs) < 5 else "red"
        
        console.print(Panel(
            f"[bold {health_color}]{health_level}[/bold {health_color}]",
            title="System Health",
            style=health_color,
            expand=False
        ))
        
        # Statistics
        stats_table = Table(show_header=False, show_lines=False, padding=(0, 2))
        stats_table.add_column("Metric", style="cyan", width=20)
        stats_table.add_column("Value", style="green", width=20)
        
        stats_data = [
            ("Threats Logged", str(len(logs))),  # Changed from "Session Threats" - now clearly shows persisted log count
            ("Unique Types", str(len(threat_counts))),
            ("Total Agents", str(agent_stats['total_agents'])),
            ("Running Agents", f"{agent_stats['running_agents']}/{agent_stats['total_agents']}"),
            ("Total Checks", str(agent_stats['total_checks_performed'])),
            ("Threats Prevented", str(agent_stats['total_prevented'])),
            ("Role", get_governance_role()),
            ("Pending Approvals", str(len(governance.list_approvals(status="pending")))),
            ("Command Mode", "ACTIVE" if self.state.command_mode else "INACTIVE"),
        ]
        
        for metric, value in stats_data:
            stats_table.add_row(metric, value)
        
        console.print(stats_table)
        
        # Top threats
        if threat_counts:
            console.print("\n[bold]Top Detected Threats:[/bold]")
            for threat_type, count in threat_counts.most_common(3):
                bar = "#" * min(count, 5) + "-" * (5 - min(count, 5))
                console.print(f"  {threat_type:20} {bar} {count}")

    def display_logs(self, limit: int = 10) -> None:
        """Display logs with enhanced formatting."""
        logs = get_session_logs()
        
        if not logs:
            console.print("[yellow]No threat logs yet[/yellow]")
            return
        
        logs_to_show = logs[-limit:]
        
        console.print(f"\n[bold cyan]RECENT LOGS (Latest {len(logs_to_show)})[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta", padding=(0, 1), expand=True)
        table.add_column("Time", style="cyan", width=19, no_wrap=True)
        table.add_column("Type", style="yellow", min_width=12, overflow="ellipsis")
        table.add_column("Risk", width=6, no_wrap=True)
        table.add_column("Status", width=8, no_wrap=True)
        table.add_column("Details", overflow="ellipsis")
        
        for log in logs_to_show:
            timestamp = log.get('timestamp', 'N/A')[:19]
            threat_type = log.get('threat_type', 'Unknown')
            risk_score = log.get('risk_score', 0)
            risk_color = "red" if risk_score >= 70 else "yellow" if risk_score >= 40 else "green"
            risk_text = f"[{risk_color}]{risk_score}[/{risk_color}]"
            
            status = "[green]LOGGED[/green]"
            alert_text = log.get('user_input', '')[:33] + "..." if len(log.get('user_input', '')) > 33 else log.get('user_input', '')
            
            table.add_row(timestamp, threat_type, risk_text, status, alert_text)
        
        console.print(table)

    def deploy_agent_interactive(self) -> None:
        """Interactive agent deployment."""
        console.print()
        self._section_header("DEPLOY NEW AGENT")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")
        
        agent_id = Prompt.ask("[cyan]Agent name[/cyan]", default="monitor-1")
        if agent_id.lower() == 'cancel':
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        interval = Prompt.ask("[cyan]Check interval (seconds)[/cyan]", default="60")
        if interval.lower() == 'cancel':
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        try:
            interval = int(interval)
            if interval < 10 or interval > 3600:
                console.print("[red]Interval must be between 10-3600 seconds[/red]")
                return
            
            agent = agent_manager.create_agent(agent_id, interval)
            
            if agent_manager.start_agent(agent_id):
                console.print(f"\n[green]✓ Agent '[bold]{agent_id}[/bold]' deployed and running[/green]")
                console.print(f"[cyan]  Interval: {interval}s[/cyan]")
                console.print(f"[cyan]  Status: Running[/cyan]")
            else:
                console.print("[red]✗ Failed to start agent[/red]")
        except ValueError:
            console.print("[red]Invalid interval value[/red]")
        
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()

    def export_logs_interactive(self) -> None:
        """Interactive log export."""
        console.print()
        self._section_header("EXPORT LOGS")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")
        
        format_choice = Prompt.ask("[cyan]Export format[/cyan]", choices=["csv", "json"], default="csv")
        
        if format_choice.lower() == 'cancel':
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        logs = get_session_logs()
        
        if not logs:
            console.print("[yellow]No logs to export[/yellow]")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/threats_{timestamp}.{format_choice}"
        filepath = Path(filename)
        filepath.parent.mkdir(exist_ok=True)
        
        try:
            if format_choice == "csv":
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                    writer.writeheader()
                    writer.writerows(logs)
            else:
                with open(filepath, 'w') as f:
                    json.dump(logs, f, indent=2)
            
            console.print(f"[green]✓ Exported {len(logs)} logs to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")
        
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()

    def configure_groq_api(self) -> None:
        """Interactive GROQ configuration."""
        console.print()
        self._section_header("GROQ API CONFIGURATION")
        console.print("[dim]Get your free API key: https://console.groq.com/keys[/dim]")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")
        
        current_key = get_groq_api_key()
        
        if current_key:
            console.print("[yellow]⚠ GROQ API key already configured[/yellow]")
            if not Confirm.ask("Update it?"):
                return
        
        api_key = Prompt.ask("[cyan]Enter your GROQ API key[/cyan]", password=True).strip()
        if api_key and api_key.lower() != 'cancel':
            console.print(f"[dim]Input received ({len(api_key)} characters).[/dim]")
        
        if not api_key or api_key.lower() == 'cancel':
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        if not validate_groq_api_key(api_key):
            console.print("[red]✗ Invalid API key format[/red]")
            return
        
        if set_groq_api_key(api_key):
            console.print("[green]✓ GROQ API key configured successfully[/green]")
            from whitecell.groq_client import groq_client
            # Reload the client with the newly stored API key
            if groq_client.reload_from_config():
                console.print("[green]✓ AI features are now active and ready to use[/green]")
            else:
                console.print("[yellow]⚠ API key saved but client not yet initialized. Check your connection.[/yellow]")
        else:
            console.print("[red]✗ Failed to save API key[/red]")
        
        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()

    def show_suggestion(self, context: str) -> None:
        """Show context-aware suggestion."""
        if context in CONTEXT_SUGGESTIONS and self.show_tips:
            console.print(f"[dim]Tip: {CONTEXT_SUGGESTIONS[context]}[/dim]")

    def process_threat_input(self, user_input: str) -> None:
        """Process threat detection input with visual feedback."""
        if not user_input.strip():
            return
        
        with console.status("[cyan]Analyzing input...", spinner="dots"):
            time.sleep(0.3)  # Brief analysis time
            response = handle_input(user_input)
        
        console.print(response)
        
        # Track threat if detected
        from whitecell.detection import detect_threat
        threat = detect_threat(user_input)
        if threat:
            self.session_threats.append(threat)

    def start(self) -> None:
        """Start the enhanced interactive CLI."""
        self.display_banner()
        
        try:
            while self.state.session_active:
                try:
                    # Show menu hint once to keep the view clean
                    if not self._menu_hint_shown:
                        console.print("[dim]Type [cyan]?[/cyan] for menu or [cyan]help[/cyan] for commands[/dim]")
                        self._menu_hint_shown = True
                    
                    user_input = console.input(self.get_prompt())
                    
                    if not user_input.strip():
                        continue
                    
                    # Add to history
                    self.command_history.append(user_input)
                    
                    # Check for menu
                    if user_input.lower() in ['?', 'menu']:
                        choice = self.display_quick_menu()
                        if choice and choice != "0":
                            self.handle_menu_selection(choice)
                        continue
                    
                    # Parse command
                    command, args = parse_command(user_input)
                    command = self.expand_alias(command)
                    
                    # Handle built-in commands
                    if command in [
                        "exit", "help", "logo", "threats", "status", "logs", "search", "analyze",
                        "export", "clear", "agent", "dashboard", "peek", "scan",
                        "triage", "investigate", "respond", "governance", "soc",
                    ]:
                        result = self.handle_command(command, args)
                        if result is False:
                            break
                        continue
                    
                    # Process as threat input
                    self.process_threat_input(user_input)
                
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid input or parameter: {e}")
                    console.print(f"[red]Error:[/red] Invalid input - {e}")
                    continue
                except KeyError as e:
                    logger.error(f"Configuration error: {e}")
                    console.print(f"[red]Configuration error:[/red] Missing setting {e}")
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error in CLI loop: {e}", exc_info=True)
                    console.print(f"[red]Error:[/red] {e}")
                    console.print("[yellow]Continuing... Type 'help' for commands[/yellow]")
                    continue
        
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold green]Exiting White Cell. Stay secure![/bold green]")
            self.state.session_active = False
        except Exception as e:
            logger.critical(f"Critical error in CLI: {e}", exc_info=True)
            console.print(f"\n[bold red]Critical error:[/bold red] {e}")
            console.print("[yellow]Exiting....[/yellow]")
            self.state.session_active = False

    def handle_command(self, command: str, args: list) -> bool:
        """Handle CLI commands."""
        command = self.expand_alias(command)
        
        if command == "exit":
            console.print("[bold green]✓ Goodbye![/bold green]")
            return False
        elif command == "help":
            if not self._check_permission("view.help", "help"):
                return True
            self.display_help()
        elif command == "logo":
            self.display_logo()
        elif command == "threats":
            if not self._check_permission("view.status", "threats"):
                return True
            self.display_threat_types()
        elif command == "status":
            if not self._check_permission("view.status", "status"):
                return True
            self.display_status()
        elif command == "dashboard":
            if not self._check_permission("view.dashboard", "dashboard"):
                return True
            try:
                self.display_dashboard()
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard closed[/yellow]")
        elif command == "peek":
            if not self._check_permission("view.dashboard", "peek"):
                return True
            try:
                refresh_seconds = float(args[0]) if args else 1.0
            except ValueError:
                console.print("[yellow]Usage: peek [refresh_seconds][/yellow]")
                return True
            self.display_peek_window(refresh_seconds)
        elif command == "logs":
            if not self._check_permission("view.logs", "logs"):
                return True
            limit = int(args[0]) if args and args[0].isdigit() else 10
            self.display_logs(limit)
        elif command == "search":
            if not self._check_permission("view.logs", "search"):
                return True
            if not args:
                console.print("[yellow]Usage: search <threat_type>[/yellow]")
            # Search logic here (simplified)
        elif command == "analyze":
            if not self._check_permission("view.logs", "analyze"):
                return True
            if not args:
                console.print("[yellow]Usage: analyze <threat_type>[/yellow]")
            # Analysis logic here
        elif command == "export":
            if not self._check_permission("view.logs", "export"):
                return True
            self.export_logs_interactive()
        elif command == "scan":
            if not self._check_permission("scan.website.passive", "scan"):
                return True
            self.handle_scan_command(args)
        elif command == "agent":
            if not self._check_permission("agent.use", "agent"):
                return True
            self.handle_agent_command(args)
        elif command == "triage":
            if not self._check_permission("soc.triage", "triage"):
                return True
            self.handle_triage_command(args)
        elif command == "investigate":
            if not self._check_permission("soc.investigate", "investigate"):
                return True
            self.handle_investigate_command(args)
        elif command == "respond":
            if not self._check_permission("soc.respond", "respond"):
                return True
            self.handle_respond_command(args)
        elif command == "governance":
            self.handle_governance_command(args)
        elif command == "soc":
            if not self._check_permission("soc.triage", "soc"):
                return True
            self.handle_soc_command(args)
        elif command == "task":
            self.handle_task_command(args)
        elif command == "clear":
            if self.state.command_mode:
                self.state.deactivate_command_mode()
                console.print("[green]✓ Command Mode deactivated[/green]")
            else:
                console.print("[yellow]Command Mode is not active[/yellow]")
        
        return True

    def handle_triage_command(self, args: list) -> None:
        """SOC triage: classify incoming alert and provide next steps."""
        alert_text = " ".join(args).strip()
        if not alert_text:
            alert_text = Prompt.ask("[cyan]Enter alert text to triage[/cyan]").strip()
            if not alert_text:
                console.print("[yellow]No alert text provided.[/yellow]")
                return

        from whitecell.detection import detect_threat, get_threat_context
        from whitecell.risk import calculate_risk, get_threat_mitigations

        threat_info = detect_threat(alert_text)
        if not threat_info:
            governance.audit_event("soc", "triage", self.role, "no-threat", {"input": alert_text[:80]})
            console.print(Panel("No known threat signature detected.\nRecommendation: monitor and collect more telemetry.", title="Triage Result", border_style="green"))
            return

        threat_info.update(get_threat_context(threat_info["threat_type"]))
        risk_info = calculate_risk(threat_info)
        mitigations = get_threat_mitigations(threat_info["threat_type"])[:4]
        mitigation_text = "\n".join(f"- {m}" for m in mitigations) if mitigations else "- No predefined mitigations."

        body = (
            f"[bold]Threat Type:[/bold] {threat_info.get('threat_type')}\n"
            f"[bold]Risk Score:[/bold] {risk_info.get('risk_score')}\n"
            f"[bold]Risk Level:[/bold] {risk_info.get('risk_level')}\n"
            f"[bold]Severity:[/bold] {threat_info.get('severity')}\n\n"
            f"[bold]Recommended Immediate Actions[/bold]\n{mitigation_text}"
        )
        governance.audit_event(
            "soc",
            "triage",
            self.role,
            "completed",
            {"threat_type": threat_info.get("threat_type"), "risk_score": risk_info.get("risk_score")},
        )
        console.print(Panel(body, title="Triage Result", border_style="cyan"))

    def handle_investigate_command(self, args: list) -> None:
        """SOC investigate: pivot on threat type or log index."""
        selector = " ".join(args).strip()
        if not selector:
            selector = Prompt.ask("[cyan]Threat type or log index[/cyan]").strip()
            if not selector:
                console.print("[yellow]No investigation selector provided.[/yellow]")
                return

        logs = get_session_logs()
        if not logs:
            console.print("[yellow]No logs available for investigation.[/yellow]")
            return

        matches = []
        if selector.isdigit():
            idx = int(selector)
            if 0 <= idx < len(logs):
                matches = [logs[idx]]
        else:
            query = selector.lower()
            matches = [l for l in logs if query in str(l.get("threat_type", "")).lower()]

        if not matches:
            console.print(f"[yellow]No logs matched '{selector}'.[/yellow]")
            return

        table = Table(title=f"Investigation Matches ({len(matches)})", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Time", style="cyan", width=19, no_wrap=True)
        table.add_column("Threat", style="yellow", min_width=12)
        table.add_column("Risk", style="red", width=6, no_wrap=True)
        table.add_column("Input", overflow="ellipsis")
        for row in matches[-10:]:
            table.add_row(
                str(row.get("timestamp", ""))[:19],
                str(row.get("threat_type", "unknown")),
                str(row.get("risk_score", "-")),
                str(row.get("user_input", ""))[:60],
            )
        governance.audit_event("soc", "investigate", self.role, "completed", {"selector": selector, "matches": len(matches)})
        console.print(table)

    def handle_respond_command(self, args: list) -> None:
        """SOC respond: recommend or execute actions with governance controls."""
        if not args:
            console.print("[yellow]Usage: respond <recommend|execute> ...[/yellow]")
            return

        mode = args[0].lower()
        if mode == "recommend":
            incident = " ".join(args[1:]).strip() or Prompt.ask("[cyan]Incident summary[/cyan]").strip()
            if not incident:
                console.print("[yellow]Incident summary is required.[/yellow]")
                return
            recommendations = [
                "Contain impacted assets and isolate affected hosts.",
                "Collect volatile evidence and preserve logs.",
                "Rotate exposed credentials and tokens.",
                "Apply IOCs to detection and blocklists.",
            ]
            body = "\n".join(f"- {item}" for item in recommendations)
            governance.audit_event("soc", "respond.recommend", self.role, "completed", {"incident": incident[:80]})
            console.print(Panel(body, title="Response Recommendations", border_style="green"))
            return

        if mode != "execute":
            console.print("[yellow]Usage: respond <recommend|execute> ...[/yellow]")
            return

        if len(args) < 3:
            console.print("[yellow]Usage: respond execute <action> <target>[/yellow]")
            console.print("[dim]Actions: isolate_host, block_ip, disable_user, collect_forensics[/dim]")
            return

        action = args[1].strip().lower()
        target = " ".join(args[2:]).strip()
        action_key = f"respond.{action}"
        reason = f"CLI response action on target '{target}'"

        if governance.is_approval_required(action_key):
            approved = [
                req for req in governance.list_approvals(status="approved")
                if req.get("action") == action_key and req.get("target") == target
            ]
            if approved:
                governance.audit_event(
                    "soc",
                    action_key,
                    self.role,
                    "executed",
                    {"target": target, "approval_id": approved[-1].get("id")},
                )
                console.print(
                    Panel(
                        f"Executed action '{action}' for target '{target}' using approval {approved[-1].get('id')}.",
                        title="Response Execution",
                        border_style="green",
                    )
                )
                return
            req = governance.request_approval(action_key, target, reason, self.role)
            console.print(f"[yellow]Approval required before execution.[/yellow] Request ID: [cyan]{req['id']}[/cyan]")
            console.print("[dim]Approve with: governance approvals approve <id>[/dim]")
            return

        governance.audit_event("soc", action_key, self.role, "executed", {"target": target})
        console.print(Panel(f"Executed action '{action}' for target '{target}'.", title="Response Execution", border_style="green"))

    def handle_governance_command(self, args: list) -> None:
        """Governance controls for role, policy, approvals, and status."""
        if not args:
            args = ["status"]

        sub = args[0].lower()

        if sub == "status":
            pending = governance.list_approvals(status="pending")
            table = Table(title="Governance Status", show_header=True, header_style="bold magenta")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Role", get_governance_role())
            table.add_row("Pending Approvals", str(len(pending)))
            table.add_row("Approval Rules", ", ".join(get_approval_required_actions()) or "-")
            console.print(table)
            return

        if sub == "role":
            if not self._check_permission("governance.manage", "governance role"):
                return
            if len(args) < 2:
                console.print("[yellow]Usage: governance role <admin|analyst|viewer>[/yellow]")
                return
            role = args[1].lower()
            if set_governance_role(role):
                self.role = role
                governance.audit_event("governance", "role.set", self.role, "completed", {"role": role})
                console.print(f"[green]Role updated to {role}.[/green]")
            else:
                console.print("[red]Invalid role. Choose admin, analyst, or viewer.[/red]")
            return

        if sub == "policy":
            if not self._check_permission("governance.manage", "governance policy"):
                return
            if len(args) < 3:
                console.print("[yellow]Usage: governance policy <add|remove> <action>[/yellow]")
                return
            action = args[1].lower()
            action_name = args[2].strip().lower()
            rules = get_approval_required_actions()
            if action == "add":
                if action_name not in rules:
                    rules.append(action_name)
                set_approval_required_actions(rules)
                console.print(f"[green]Approval rule added: {action_name}[/green]")
                return
            if action == "remove":
                rules = [r for r in rules if r != action_name]
                set_approval_required_actions(rules)
                console.print(f"[green]Approval rule removed: {action_name}[/green]")
                return
            console.print("[yellow]Usage: governance policy <add|remove> <action>[/yellow]")
            return

        if sub == "approvals":
            if len(args) < 2:
                console.print("[yellow]Usage: governance approvals <list|approve|reject> [id][/yellow]")
                return
            action = args[1].lower()
            if action == "list":
                rows = governance.list_approvals()
                if not rows:
                    console.print("[yellow]No approval requests found.[/yellow]")
                    return
                table = Table(title="Approval Requests", show_header=True, header_style="bold magenta")
                table.add_column("ID", style="cyan")
                table.add_column("Status", style="yellow")
                table.add_column("Action", style="red")
                table.add_column("Target", style="green")
                table.add_column("Requested By", style="white")
                for req in rows[-15:]:
                    table.add_row(req.get("id", "-"), req.get("status", "-"), req.get("action", "-"), req.get("target", "-"), req.get("requested_by", "-"))
                console.print(table)
                return

            if action in {"approve", "reject"}:
                if not self._check_permission("governance.manage", f"governance approvals {action}"):
                    return
                if len(args) < 3:
                    console.print(f"[yellow]Usage: governance approvals {action} <id>[/yellow]")
                    return
                ok = governance.review_approval(args[2], action, self.role)
                if ok:
                    console.print(f"[green]Request {args[2]} {action}d.[/green]")
                else:
                    console.print("[red]Unable to update request. Check ID and current status.[/red]")
                return

            console.print("[yellow]Usage: governance approvals <list|approve|reject> [id][/yellow]")
            return

        console.print("[yellow]Usage: governance <status|role|policy|approvals> ...[/yellow]")

    def _parse_soc_run(self, args: list[str]) -> tuple[str, Optional[str], Optional[str]]:
        """Parse `soc run` args into alert text and optional execute action/target."""
        if not args:
            return "", None, None
        if "--execute" not in args:
            return " ".join(args).strip(), None, None

        idx = args.index("--execute")
        alert_text = " ".join(args[:idx]).strip()
        remaining = args[idx + 1:]
        if len(remaining) < 2:
            return alert_text, None, None
        action = remaining[0].strip().lower()
        target = " ".join(remaining[1:]).strip()
        return alert_text, action, target

    def handle_soc_command(self, args: list) -> None:
        """Run SOC-first chained workflows."""
        if not args or args[0].lower() != "run":
            console.print("[yellow]Usage: soc run <alert_text> [--execute <action> <target>][/yellow]")
            return

        alert_text, action, target = self._parse_soc_run(args[1:])
        if not alert_text:
            alert_text = Prompt.ask("[cyan]Enter alert text[/cyan]").strip()
            if not alert_text:
                console.print("[yellow]Alert text is required.[/yellow]")
                return

        self._section_header("SOC RUN", "triage -> investigate -> respond")
        self.handle_triage_command([alert_text])

        from whitecell.detection import detect_threat
        threat_info = detect_threat(alert_text)
        if threat_info and threat_info.get("threat_type"):
            self.handle_investigate_command([str(threat_info["threat_type"])])
        else:
            self.handle_investigate_command([alert_text])

        self.handle_respond_command(["recommend", alert_text])

        if action and target:
            self.handle_respond_command(["execute", action, target])

    def handle_agent_command(self, args: list) -> None:
        """Handle agent commands."""
        if not args:
            console.print("[cyan]Agent commands: deploy, stop, status, threats, configure, blue, red, battle, ask, crewai, evolve[/cyan]")
            console.print("[dim]Evolve cmds: start [sec], stop, status, generate, review [id], approve <id>, apply <id> <token>, reject <id>[/dim]")
            return
        
        subcommand = args[0]
        prompt_text = " ".join(args[1:]).strip()
        
        if subcommand == "deploy":
            self.deploy_agent_interactive()
        elif subcommand == "configure":
            self.configure_groq_api()
        elif subcommand == "status":
            self.display_status()
        elif subcommand == "blue":
            self.run_agent_ai_prompt("blue", prompt_text)
        elif subcommand == "red":
            self.run_agent_ai_prompt("red", prompt_text)
        elif subcommand == "battle":
            self.run_agent_ai_prompt("battle", prompt_text)
        elif subcommand == "ask":
            self.run_agent_ai_prompt("ask", prompt_text)
        elif subcommand == "crewai":
            self.run_crewai_objective(prompt_text)
        elif subcommand == "evolve":
            self.handle_self_improve_command(args[1:])
        else:
            console.print(f"[yellow]Unknown agent subcommand: {subcommand}[/yellow]")

    def run_crewai_objective(self, objective: str) -> None:
        """Execute objective using CrewAI framework with active API key."""
        if not objective:
            objective = Prompt.ask("[cyan]Enter CrewAI objective[/cyan]").strip()
            if not objective:
                console.print("[yellow]Objective cannot be empty.[/yellow]")
                return

        with console.status("[cyan]Running CrewAI mission...[/cyan]", spinner="dots"):
            result = crew_manager.run_crewai_mission(objective)

        status = result.get("status")
        if status == "success":
            console.print(Panel(result.get("result", ""), title="CrewAI Result", border_style="green"))
            return

        if status == "unavailable":
            console.print("[yellow]CrewAI framework not installed.[/yellow]")
            console.print("[dim]Install with: pip install crewai[/dim]")
            return

        console.print(Panel(result.get("message", "CrewAI mission failed."), title="CrewAI", border_style="red"))

    def handle_self_improve_command(self, args: list) -> None:
        """Handle guarded autonomous self-improvement commands."""
        if not args:
            console.print("[yellow]Usage: agent evolve <start|stop|status|generate|review|approve|apply|reject>[/yellow]")
            return

        cmd = args[0].lower()

        if cmd == "start":
            interval = 120
            if len(args) > 1 and args[1].isdigit():
                interval = int(args[1])
            self_improver.start(interval)
            console.print(f"[green]Self-improvement started[/green] (interval={interval}s).")
            return

        if cmd == "stop":
            self_improver.stop()
            console.print("[yellow]Self-improvement stopped.[/yellow]")
            return

        if cmd == "status":
            status = self_improver.status()
            table = Table(title="Self-Improvement Status", show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            for key in ["running", "interval_seconds", "last_cycle", "total_proposals", "pending", "approved", "applied"]:
                table.add_row(key, str(status.get(key)))
            console.print(table)
            return

        if cmd == "generate":
            proposal = self_improver.generate_proposal()
            if not proposal:
                console.print("[yellow]No new proposal generated right now.[/yellow]")
                return
            console.print(f"[green]Generated proposal:[/green] {proposal['id']} - {proposal['title']}")
            return

        if cmd == "review":
            if len(args) > 1:
                proposal = self_improver.get_proposal(args[1])
                if not proposal:
                    console.print(f"[yellow]Proposal not found: {args[1]}[/yellow]")
                    return
                console.print(json.dumps(proposal, indent=2))
                return

            proposals = self_improver.list_proposals(limit=10)
            if not proposals:
                console.print("[yellow]No proposals available.[/yellow]")
                return
            table = Table(title="Recent Self-Improvement Proposals", show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Risk", style="red")
            table.add_column("Title", width=60)
            for p in proposals:
                table.add_row(p.get("id", "-"), p.get("status", "-"), p.get("risk", "-"), p.get("title", "-"))
            console.print(table)
            return

        if cmd == "approve":
            if len(args) < 2:
                console.print("[yellow]Usage: agent evolve approve <proposal_id>[/yellow]")
                return
            token = self_improver.approve_proposal(args[1])
            if not token:
                console.print("[red]Approval failed. Check proposal ID and status.[/red]")
                return
            console.print(f"[green]Approved[/green] {args[1]}")
            console.print(f"[bold yellow]Approval token:[/bold yellow] {token}")
            console.print("[dim]Apply with: agent evolve apply <proposal_id> <token>[/dim]")
            return

        if cmd == "apply":
            if len(args) < 3:
                console.print("[yellow]Usage: agent evolve apply <proposal_id> <approval_token>[/yellow]")
                return
            if self_improver.apply_proposal(args[1], args[2]):
                console.print(f"[green]Applied proposal[/green] {args[1]}.")
            else:
                console.print("[red]Apply failed. Verify approval token, status, and safety checks.[/red]")
            return

        if cmd == "reject":
            if len(args) < 2:
                console.print("[yellow]Usage: agent evolve reject <proposal_id>[/yellow]")
                return
            if self_improver.reject_proposal(args[1]):
                console.print(f"[green]Rejected proposal[/green] {args[1]}.")
            else:
                console.print("[red]Reject failed. Check proposal ID and status.[/red]")
            return

        console.print(f"[yellow]Unknown evolve command: {cmd}[/yellow]")

    def run_agent_ai_prompt(self, mode: str, prompt_text: str) -> None:
        """Run AI-powered agent prompts for blue/red/battle/general scenarios."""
        if not prompt_text:
            prompt_text = Prompt.ask("[cyan]Enter scenario/prompt[/cyan]").strip()
            if not prompt_text:
                console.print("[yellow]Prompt cannot be empty.[/yellow]")
                return

        if not groq_client.is_configured():
            console.print("[yellow]Groq API is not configured. Run 'agent configure' first.[/yellow]")
            return

        if mode == "blue":
            with console.status("[cyan]Running Blue Team exercise...[/cyan]", spinner="dots"):
                result = groq_client.blue_team_exercise(prompt_text)
            console.print(Panel(result, title="Blue Team Strategy", border_style="cyan"))
            return

        if mode == "red":
            with console.status("[cyan]Running Red Team exercise...[/cyan]", spinner="dots"):
                result = groq_client.red_team_exercise(prompt_text)
            console.print(Panel(result, title="Red Team Strategy", border_style="red"))
            return

        if mode == "battle":
            with console.status("[cyan]Running Blue vs Red scenario...[/cyan]", spinner="dots"):
                result = groq_client.team_battle_scenario(prompt_text)
            if not isinstance(result, dict):
                console.print(Panel(str(result), title="Battle Scenario", border_style="yellow"))
                return
            if result.get("status") != "success":
                console.print(Panel(result.get("message", "Failed to run team battle scenario."), title="Battle Scenario Error", border_style="red"))
                return

            blue_strategy = result.get("blue_team", {}).get("strategy", "No blue team strategy returned.")
            red_strategy = result.get("red_team", {}).get("strategy", "No red team strategy returned.")
            console.print(Panel(blue_strategy, title="Blue Team (Defense)", border_style="cyan"))
            console.print(Panel(red_strategy, title="Red Team (Offense)", border_style="red"))
            return

        with console.status("[cyan]Querying cybersecurity assistant...[/cyan]", spinner="dots"):
            result = groq_client.get_explanation(prompt_text)
        console.print(Panel(result, title="Agent Response", border_style="green"))

    def handle_scan_command(self, args: list) -> None:
        """Handle security scan commands.

        Usage:
          scan website <url> [--active]
          scan allowlist <show|add|remove> [domain]
        """
        if not args:
            console.print("[yellow]Usage: scan website <url> [--active][/yellow]")
            console.print("[yellow]       scan allowlist <show|add|remove> [domain][/yellow]")
            return

        sub = args[0].lower()
        remaining = args[1:]

        if sub == "website":
            self.scan_website(remaining)
            return

        if sub == "allowlist":
            self.handle_scan_allowlist_command(remaining)
            return

        console.print("[yellow]Usage: scan website <url> [--active][/yellow]")
        console.print("[yellow]       scan allowlist <show|add|remove> [domain][/yellow]")

    def _normalize_domain(self, domain_or_url: str) -> str:
        """Normalize URL/domain into lowercase hostname for allowlist matching."""
        raw = (domain_or_url or "").strip().lower()
        if not raw:
            return ""

        host = website_scanner.extract_domain(raw)
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host

    def _is_domain_allowlisted(self, domain: str) -> bool:
        """Return True if domain is explicitly allowlisted or subdomain of an allowlisted root."""
        normalized = self._normalize_domain(domain)
        if not normalized:
            return False

        for item in get_scan_allowlist():
            allowed = self._normalize_domain(str(item))
            if not allowed:
                continue
            if normalized == allowed or normalized.endswith(f".{allowed}"):
                return True
        return False

    def handle_scan_allowlist_command(self, args: list) -> None:
        """Manage domain allowlist for active website probing."""
        if not args:
            console.print("[yellow]Usage: scan allowlist <show|add|remove> [domain][/yellow]")
            return

        action = args[0].lower()
        current = list(get_scan_allowlist())

        if action == "show":
            if not current:
                console.print("[yellow]Scan allowlist is empty. Active probing will be blocked.[/yellow]")
                return
            table = Table(title="Scan Allowlist", show_header=True, header_style="bold magenta")
            table.add_column("Approved Domain", style="cyan")
            for domain in sorted(current):
                table.add_row(domain)
            console.print(table)
            return

        if action not in {"add", "remove"}:
            console.print("[yellow]Usage: scan allowlist <show|add|remove> [domain][/yellow]")
            return

        if len(args) < 2:
            console.print(f"[yellow]Usage: scan allowlist {action} <domain>[/yellow]")
            return

        domain = self._normalize_domain(args[1])
        if not domain:
            console.print("[red]Invalid domain.[/red]")
            return

        if action == "add":
            if domain in current:
                console.print(f"[yellow]{domain} is already allowlisted.[/yellow]")
                return
            current.append(domain)
            if set_scan_allowlist(sorted(set(current))):
                console.print(f"[green]Added {domain} to scan allowlist.[/green]")
            else:
                console.print("[red]Failed to update scan allowlist.[/red]")
            return

        # remove
        if domain not in current:
            console.print(f"[yellow]{domain} is not in scan allowlist.[/yellow]")
            return
        current = [d for d in current if d != domain]
        if set_scan_allowlist(current):
            console.print(f"[green]Removed {domain} from scan allowlist.[/green]")
        else:
            console.print("[red]Failed to update scan allowlist.[/red]")

    def scan_website(self, args: list) -> None:
        """Run passive scan and optional active probing on authorized targets only."""
        if not args:
            console.print("[yellow]Usage: scan website <url> [--active][/yellow]")
            return

        url = args[0]
        active_requested = "--active" in args[1:]
        domain = self._normalize_domain(url)

        console.print("[bold yellow]Authorized testing only.[/bold yellow] You must own the target or have explicit permission.")
        if not Confirm.ask("Do you confirm you are authorized to test this website?", default=False):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return

        with console.status(f"[cyan]Running passive analysis for {url}...[/cyan]", spinner="dots"):
            passive_result = website_scanner.passive_scan(url)
        console.print(website_scanner.format_report(passive_result))
        governance.audit_event("scan", "scan.website.passive", self.role, "completed", {"url": url, "domain": domain})

        if not active_requested and passive_result.get("risk_level") not in {"high", "critical"}:
            return

        if not self._is_domain_allowlisted(domain):
            console.print(f"[red]Active probing blocked for {domain}.[/red]")
            console.print("[yellow]Pre-approve target with:[/yellow] [cyan]scan allowlist add <domain>[/cyan]")
            governance.audit_event("scan", "scan.website.active", self.role, "blocked", {"url": url, "reason": "domain_not_allowlisted"})
            return

        if governance.is_approval_required("scan.website.active"):
            req = governance.request_approval(
                "scan.website.active",
                domain,
                "Active website probing request",
                self.role,
                {"url": url},
            )
            console.print(f"[yellow]Active probing requires approval.[/yellow] Request ID: [cyan]{req['id']}[/cyan]")
            console.print("[dim]Approve with: governance approvals approve <id>[/dim]")
            return

        console.print("\n[bold yellow]Active probing can trigger alerts on target infrastructure.[/bold yellow]")
        if not Confirm.ask("Proceed with active probing?", default=False):
            console.print("[yellow]Active probing skipped.[/yellow]")
            return

        with console.status(f"[cyan]Running active probing for {url}...[/cyan]", spinner="dots"):
            active_result = website_scanner.active_scan(url)
        governance.audit_event("scan", "scan.website.active", self.role, "completed", {"url": url, "domain": domain})
        console.print(website_scanner.format_report(active_result))

    def handle_task_command(self, args: list) -> None:
        """Handle task commands."""
        if not args:
            console.print("[cyan]Task commands: assign, list, results[/cyan]")
            return
        
        subcommand = args[0]
        
        if subcommand == "assign":
            self.assign_task_interactive()
        elif subcommand == "list":
            self.list_tasks()
        elif subcommand == "results":
            agent_id = args[1] if len(args) > 1 else None
            self.show_task_results(agent_id)
        else:
            console.print(f"[yellow]Unknown task command: {subcommand}[/yellow]")

    def assign_task_interactive(self) -> None:
        """Interactively assign a task to an agent."""
        console.print()
        self._section_header("TASK ASSIGNMENT")
        console.print()
        
        # Get available agents
        available_agents = [
            agent_id for agent_id, agent in agent_manager.agents.items()
            if agent.running
        ]
        
        if not available_agents:
            console.print("[red]✗ No running agents available[/red]")
            return
        
        # Select agent
        console.print("[cyan]Running agents:[/cyan]")
        for i, agent_id in enumerate(available_agents, 1):
            console.print(f"  {i}. {agent_id}")
        
        choice = Prompt.ask("[cyan]Select agent (number or all)[/cyan]", default="1")
        
        if choice.lower() == "all":
            target_agents = available_agents
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(available_agents):
                    target_agents = [available_agents[idx]]
                else:
                    console.print("[red]Invalid selection[/red]")
                    return
            except ValueError:
                console.print("[red]Invalid input[/red]")
                return
        
        # Select task type
        console.print("\n[cyan]Task types:[/cyan]")
        task_types = [
            ("1", "check", "Run a specific security check"),
            ("2", "scan", "Comprehensive threat scan"),
            ("3", "threat_analysis", "Analyze a threat with AI"),
            ("4", "remediate", "Execute threat remediation"),
            ("5", "custom", "Run custom action"),
        ]
        
        for num, task_type, desc in task_types:
            console.print(f"  {num}. {task_type}: {desc}")
        
        task_choice = Prompt.ask("[cyan]Select task type[/cyan]", default="1")
        
        # Map selection to task type
        task_map = {
            "1": "check",
            "2": "scan",
            "3": "threat_analysis",
            "4": "remediate",
            "5": "custom"
        }
        
        task_type = task_map.get(task_choice)
        if not task_type:
            console.print("[red]Invalid task type[/red]")
            return
        
        # Get task parameters based on type
        parameters = {}
        description = ""
        
        if task_type == "check":
            check_name = Prompt.ask("[cyan]Enter check name[/cyan] (process, port, file, logs, firewall, malware)", default="process")
            parameters["check_name"] = check_name
            description = f"Run {check_name} security check"
            
        elif task_type == "scan":
            threat_data = Prompt.ask("[cyan]Enter threat data to scan[/cyan]")
            parameters["threat_data"] = threat_data
            description = f"Scan: {threat_data[:50]}..."
            
        elif task_type == "threat_analysis":
            threat_desc = Prompt.ask("[cyan]Enter threat description[/cyan]")
            parameters["threat_description"] = threat_desc
            description = f"Analyze threat: {threat_desc[:50]}..."
            
        elif task_type == "remediate":
            threat_type = Prompt.ask("[cyan]Enter threat type[/cyan] (ransomware, malware, exploit, denial_of_service)")
            parameters["threat_type"] = threat_type
            description = f"Remediate {threat_type}"
            
        elif task_type == "custom":
            action = Prompt.ask("[cyan]Enter custom action[/cyan]")
            parameters["action"] = action
            description = f"Custom: {action}"
        
        # Create and assign task
        task = agent_manager.create_task(task_type, description, parameters)
        
        assigned_count = 0
        for agent_id in target_agents:
            if agent_manager.assign_task_to_agent(agent_id, task):
                assigned_count += 1
        
        if assigned_count > 0:
            console.print(f"\n[green]✓ Task assigned to {assigned_count} agent(s)[/green]")
            console.print(f"  Task ID: {task.task_id}")
            console.print(f"  Type: {task_type}")
            console.print(f"  Description: {description}")
        else:
            console.print("[red]✗ Failed to assign task[/red]")

    def list_tasks(self) -> None:
        """List pending and completed tasks."""
        console.print()
        self._section_header("TASK STATUS")
        console.print()
        
        tasks_by_agent = agent_manager.get_all_completed_tasks()
        
        if not tasks_by_agent:
            console.print("[yellow]No tasks completed yet[/yellow]")
            return
        
        for agent_id, tasks in tasks_by_agent.items():
            if tasks:
                console.print(f"\n[bold]{agent_id}:[/bold]")
                for task in tasks[-5:]:  # Show last 5
                    status_color = "green" if task["status"] == "completed" else "red" if task["status"] == "failed" else "yellow"
                    console.print(f"  [{status_color}]{task['status']}[/{status_color}] [{task['task_type']}] {task['description']}")

    def show_task_results(self, agent_id: str = None) -> None:
        """Show detailed task results."""
        console.print()
        self._section_header("TASK RESULTS")
        console.print()
        
        if agent_id:
            if agent_id not in agent_manager.agents:
                console.print(f"[red]Agent {agent_id} not found[/red]")
                return
            
            tasks = agent_manager.get_agent_completed_tasks(agent_id, limit=10)
            agents_to_show = {agent_id: tasks}
        else:
            agents_to_show = agent_manager.get_all_completed_tasks()
        
        for agent_id, tasks in agents_to_show.items():
            if tasks:
                console.print(f"\n[bold cyan]{agent_id}:[/bold cyan]")
                for task in tasks[-3:]:  # Show last 3
                    console.print(f"\n  Task: {task['task_id']}")
                    console.print(f"  Type: {task['task_type']}")
                    console.print(f"  Status: {task['status']}")
                    console.print(f"  Description: {task['description']}")
                    if task['error']:
                        console.print(f"  Error: {task['error']}")
                    if task['result']:
                        console.print(f"  Result: {json.dumps(task['result'], indent=2)[:200]}...")


def main() -> None:
    """Entry point for enhanced CLI."""
    cli = EnhancedWhiteCellCLI()
    cli.start()


if __name__ == "__main__":
    main()



