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
from whitecell.config import load_config, set_groq_api_key, get_groq_api_key, validate_groq_api_key
from whitecell.groq_client import groq_client
from whitecell.self_improve import self_improver

console = Console()

# Command aliases for faster navigation
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
    "ag": "agent",
    "d": "dashboard",
    "p": "peek",
}

# Quick command suggestions based on context
CONTEXT_SUGGESTIONS = {
    "threat": "Try 'analyze <threat>' or 'search <term>'",
    "logs": "Try 'export csv' or 'search <threat>'",
    "agent": "Try 'agent blue <scenario>' or 'agent red <scenario>'",
    "help": "Type 'help' for full command list",
}


class EnhancedWhiteCellCLI:
    """Enhanced interactive CLI with improved UX and visual design."""

    def __init__(self):
        """Initialize the enhanced CLI."""
        self.state = global_state
        self.session_threats = []
        self.command_history = []
        initialize_logging()
        self.show_tips = True

    def expand_alias(self, command: str) -> str:
        """Expand command aliases."""
        return COMMAND_ALIASES.get(command, command)

    def get_prompt(self) -> str:
        """Get dynamic prompt based on state."""
        if self.state.command_mode:
            return "[bold red]⚠ [CRISIS MODE] WhiteCell >[/bold red] "
        
        threat_count = len(self.session_threats)
        if threat_count > 5:
            return f"[bold red]WhiteCell ({threat_count} critical) >[/bold red] "
        elif threat_count > 0:
            return f"[bold yellow]WhiteCell ({threat_count} threats) >[/bold yellow] "
        
        return "[bold cyan]WhiteCell >[/bold cyan] "

    def display_banner(self) -> None:
        """Display an attractive banner on startup."""
        banner = """
 ╔══════════════════════════════════════════════════════════════╗
 ║                                                              ║
 ║         [bold cyan]WHITE CELL[/bold cyan] - Cybersecurity Assistant            ║
 ║                                                              ║
 ║    Detection | Prevention | Intelligence | Protection       ║
 ║                                                              ║
 ║               Type [bold yellow]help[/bold yellow] for commands or [bold yellow]?[/bold yellow] for quick tips      ║
 ║              Type [bold yellow]dashboard[/bold yellow] for live threat view          ║
 ║                                                              ║
 ╚══════════════════════════════════════════════════════════════╝
"""
        console.print(banner)

    def display_dashboard(self) -> None:
        """Display a dashboard-style status view."""
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
            running = "🟢" if status['running'] else "🔴"
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

            logs_table = Table(title="Recent Threat Logs", show_header=True, header_style="bold magenta")
            logs_table.add_column("Time", style="cyan", width=19)
            logs_table.add_column("Type", style="yellow", width=18)
            logs_table.add_column("Risk", style="red", width=8)
            logs_table.add_column("Input", width=40)
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

            events_table = Table(title="Recent Agent Events", show_header=True, header_style="bold magenta")
            events_table.add_column("Time", style="cyan", width=19)
            events_table.add_column("Event", style="yellow", width=18)
            events_table.add_column("Agent", style="green", width=16)
            events_table.add_column("Detail", width=36)
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
            with Live(build_layout(), refresh_per_second=4, console=console, screen=False) as live:
                while True:
                    time.sleep(refresh_seconds)
                    live.update(build_layout())
        except KeyboardInterrupt:
            console.print("\n[yellow]Peek window closed[/yellow]")

    def display_help(self) -> None:
        """Display comprehensive help with categories."""
        console.clear()
        
        # Header
        console.print(Panel(
            "[bold cyan]WHITE CELL - COMMAND REFERENCE[/bold cyan]",
            style="cyan",
            expand=False
        ))
        
        # Core Commands
        console.print("\n[bold green]═ CORE COMMANDS ═[/bold green]")
        core_table = Table(show_header=True, header_style="bold magenta", show_lines=False)
        core_table.add_column("Command", style="cyan", width=15)
        core_table.add_column("Alias", style="yellow", width=8)
        core_table.add_column("Description", width=40)
        
        core_commands = [
            ("help", "h, ?", "Show this help message"),
            ("exit", "q", "Exit the application"),
            ("status", "st", "Display system status"),
            ("dashboard", "d", "Show live dashboard view"),
            ("peek", "p", "Open live peek monitoring window"),
            ("clear", "c", "Exit Command Mode"),
        ]
        
        for cmd, alias, desc in core_commands:
            core_table.add_row(cmd, alias, desc)
        
        console.print(core_table)
        
        # Threat Commands
        console.print("\n[bold green]═ THREAT MANAGEMENT ═[/bold green]")
        threat_table = Table(show_header=True, header_style="bold magenta")
        threat_table.add_column("Command", style="cyan", width=25)
        threat_table.add_column("Description", width=45)
        
        threat_commands = [
            ("threats (t)", "View all 9 threat types"),
            ("logs (l) [limit]", "Show latest threat logs"),
            ("search (s) <term>", "Search logs by threat type"),
            ("analyze (a) <type>", "Analyze specific threat"),
            ("export (e) [csv|json]", "Export logs to file"),
        ]
        
        for cmd, desc in threat_commands:
            threat_table.add_row(cmd, desc)
        
        console.print(threat_table)
        
        # Agent Commands
        console.print("\n[bold green]═ AGENT MANAGEMENT ═[/bold green]")
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
            ("agent evolve <cmd>", "Autonomous self-improvement controls"),
        ]
        
        for cmd, desc in agent_commands:
            agent_table.add_row(cmd, desc)
        
        console.print(agent_table)
        
        # Tips
        console.print("\n[bold green]═ QUICK TIPS ═[/bold green]")
        tips = [
            "[cyan]•[/cyan] Type partial commands - they auto-complete",
            "[cyan]•[/cyan] Use aliases for faster typing: 't' for 'threats', 's' for 'search'",
            "[cyan]•[/cyan] Try 'dashboard' for a live threat view",
            "[cyan]•[/cyan] Commands are case-insensitive",
            "[cyan]•[/cyan] 'agent configure' is optional - system works without GROQ",
        ]
        
        for tip in tips:
            console.print(f"  {tip}")
        
        console.print()

    def display_quick_menu(self) -> Optional[str]:
        """Display a quick interactive menu."""
        console.print("\n[bold cyan]═ QUICK MENU ═[/bold cyan]")
        menu_options = [
            ("1", "View Threats", "See all threat types"),
            ("2", "Check Status", "System status report"),
            ("3", "Deploy Agent", "Start new agent"),
            ("4", "View Dashboard", "Live threat dashboard"),
            ("5", "Configure GROQ AI", "Setup API key (optional)"),
            ("6", "View Logs", "Recent threat logs"),
            ("7", "Export Data", "Save logs to file"),
            ("8", "Peek Window", "Continuous live monitoring"),
            ("0", "Back to CLI", "Return to command line"),
        ]
        
        menu_table = Table(show_header=False, show_lines=False)
        for key, option, desc in menu_options:
            menu_table.add_row(f"[yellow]{key}[/yellow]", f"[cyan]{option}[/cyan]", f"[dim]{desc}[/dim]")
        
        console.print(menu_table)
        
        choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])
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
        elif choice == "0":
            return True
        
        return False

    def display_threat_types(self) -> None:
        """Display all threat types with enhanced formatting."""
        threats = get_all_threats()
        
        console.print("\n[bold cyan]═ THREAT TYPES (9 Total) ═[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold white on red", padding=(0, 1))
        table.add_column("Type", style="red", width=18)
        table.add_column("Severity", width=12)
        table.add_column("Financial Risk", style="green", width=15)
        table.add_column("POPIA", width=8)
        table.add_column("Description", width=30)
        
        for threat in threats:
            severity = threat['severity']
            severity_color = "red" if severity >= 8 else "yellow" if severity >= 6 else "green"
            severity_bar = "█" * severity + "░" * (10 - severity)
            
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
        
        console.print("\n[bold cyan]═ SYSTEM STATUS ═[/bold cyan]\n")
        
        # System Health Panel
        health_level = "🟢 HEALTHY" if len(logs) == 0 else "🟡 MONITORING" if len(logs) < 5 else "🔴 CRITICAL"
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
            ("Command Mode", "🔴 ACTIVE" if self.state.command_mode else "🟢 INACTIVE"),
        ]
        
        for metric, value in stats_data:
            stats_table.add_row(metric, value)
        
        console.print(stats_table)
        
        # Top threats
        if threat_counts:
            console.print("\n[bold]Top Detected Threats:[/bold]")
            for threat_type, count in threat_counts.most_common(3):
                bar = "▰" * count + "▱" * (5 - min(count, 5))
                console.print(f"  {threat_type:20} {bar} {count}")

    def display_logs(self, limit: int = 10) -> None:
        """Display logs with enhanced formatting."""
        logs = get_session_logs()
        
        if not logs:
            console.print("[yellow]No threat logs yet[/yellow]")
            return
        
        logs_to_show = logs[-limit:]
        
        console.print(f"\n[bold cyan]═ RECENT LOGS (Latest {len(logs_to_show)}) ═[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold magenta", padding=(0, 1))
        table.add_column("Time", style="cyan", width=19)
        table.add_column("Type", style="yellow", width=16)
        table.add_column("Risk", width=8)
        table.add_column("Status", width=12)
        table.add_column("Details", width=35)
        
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
        console.print("\n[bold cyan]═ DEPLOY NEW AGENT ═[/bold cyan]")
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
        console.print("\n[bold cyan]═ EXPORT LOGS ═[/bold cyan]")
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
        console.print("\n[bold cyan]═ GROQ API CONFIGURATION ═[/bold cyan]")
        console.print("[dim]Get your free API key: https://console.groq.com/keys[/dim]")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")
        
        current_key = get_groq_api_key()
        
        if current_key:
            console.print("[yellow]⚠ GROQ API key already configured[/yellow]")
            if not Confirm.ask("Update it?"):
                return
        
        api_key = Prompt.ask("[cyan]Enter your GROQ API key[/cyan]", password=True)
        
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
                # Show menu option hint
                menu_hint = "[dim]Type [cyan]?[/cyan] for menu or [cyan]help[/cyan] for commands[/dim]"
                console.print(menu_hint)
                
                user_input = input(self.get_prompt())
                
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
                if command in ["exit", "help", "threats", "status", "logs", "search", "analyze", "export", "clear", "agent", "dashboard", "peek"]:
                    result = self.handle_command(command, args)
                    if result is False:
                        break
                    continue
                
                # Process as threat input
                self.process_threat_input(user_input)
        
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold green]Exiting White Cell. Stay secure![/bold green]")
            self.state.session_active = False

    def handle_command(self, command: str, args: list) -> bool:
        """Handle CLI commands."""
        command = self.expand_alias(command)
        
        if command == "exit":
            console.print("[bold green]✓ Goodbye![/bold green]")
            return False
        elif command == "help":
            self.display_help()
        elif command == "threats":
            self.display_threat_types()
        elif command == "status":
            self.display_status()
        elif command == "dashboard":
            try:
                self.display_dashboard()
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard closed[/yellow]")
        elif command == "peek":
            try:
                refresh_seconds = float(args[0]) if args else 1.0
            except ValueError:
                console.print("[yellow]Usage: peek [refresh_seconds][/yellow]")
                return True
            self.display_peek_window(refresh_seconds)
        elif command == "logs":
            limit = int(args[0]) if args and args[0].isdigit() else 10
            self.display_logs(limit)
        elif command == "search":
            if not args:
                console.print("[yellow]Usage: search <threat_type>[/yellow]")
            # Search logic here (simplified)
        elif command == "analyze":
            if not args:
                console.print("[yellow]Usage: analyze <threat_type>[/yellow]")
            # Analysis logic here
        elif command == "export":
            self.export_logs_interactive()
        elif command == "agent":
            self.handle_agent_command(args)
        elif command == "task":
            self.handle_task_command(args)
        elif command == "clear":
            if self.state.command_mode:
                self.state.deactivate_command_mode()
                console.print("[green]✓ Command Mode deactivated[/green]")
            else:
                console.print("[yellow]Command Mode is not active[/yellow]")
        
        return True

    def handle_agent_command(self, args: list) -> None:
        """Handle agent commands."""
        if not args:
            console.print("[cyan]Agent commands: deploy, stop, status, threats, configure, blue, red, battle, ask, evolve[/cyan]")
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
        elif subcommand == "evolve":
            self.handle_self_improve_command(args[1:])
        else:
            console.print(f"[yellow]Unknown agent subcommand: {subcommand}[/yellow]")

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
        console.print("\n[bold cyan]═ TASK ASSIGNMENT ═[/bold cyan]\n")
        
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
        console.print("\n[bold cyan]═ TASK STATUS ═[/bold cyan]\n")
        
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
        console.print("\n[bold cyan]═ TASK RESULTS ═[/bold cyan]\n")
        
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
