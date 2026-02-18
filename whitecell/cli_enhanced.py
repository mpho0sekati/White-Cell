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
}

# Quick command suggestions based on context
CONTEXT_SUGGESTIONS = {
    "threat": "Try 'analyze <threat>' or 'search <term>'",
    "logs": "Try 'export csv' or 'search <threat>'",
    "agent": "Try 'agent deploy <name>' or 'agent status'",
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
            ("0", "Back to CLI", "Return to command line"),
        ]
        
        menu_table = Table(show_header=False, show_lines=False)
        for key, option, desc in menu_options:
            menu_table.add_row(f"[yellow]{key}[/yellow]", f"[cyan]{option}[/cyan]", f"[dim]{desc}[/dim]")
        
        console.print(menu_table)
        
        choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7"])
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
        logs = get_session_logs()
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
            ("Session Threats", str(len(logs))),
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
        
        agent_id = Prompt.ask("[cyan]Agent name[/cyan]", default="monitor-1")
        interval = Prompt.ask("[cyan]Check interval (seconds)[/cyan]", default="60")
        
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

    def export_logs_interactive(self) -> None:
        """Interactive log export."""
        console.print("\n[bold cyan]═ EXPORT LOGS ═[/bold cyan]")
        
        format_choice = Prompt.ask("[cyan]Export format[/cyan]", choices=["csv", "json"], default="csv")
        
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

    def configure_groq_api(self) -> None:
        """Interactive GROQ configuration."""
        console.print("\n[bold cyan]═ GROQ API CONFIGURATION ═[/bold cyan]")
        console.print("[dim]Get your free API key: https://console.groq.com/keys[/dim]\n")
        
        current_key = get_groq_api_key()
        
        if current_key:
            console.print("[yellow]⚠ GROQ API key already configured[/yellow]")
            if not Confirm.ask("Update it?"):
                return
        
        api_key = Prompt.ask("[cyan]Enter your GROQ API key[/cyan]", password=True)
        
        if not api_key:
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        if not validate_groq_api_key(api_key):
            console.print("[red]✗ Invalid API key format[/red]")
            return
        
        if set_groq_api_key(api_key):
            console.print("[green]✓ GROQ API key configured successfully[/green]")
            from whitecell.groq_client import groq_client
            if groq_client.set_api_key(api_key):
                console.print("[green]✓ AI features are now active[/green]")
        else:
            console.print("[red]✗ Failed to save API key[/red]")

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
                if command in ["exit", "help", "threats", "status", "logs", "search", "analyze", "export", "clear", "agent", "dashboard"]:
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
            console.print("[cyan]Agent commands: deploy, stop, status, threats, configure[/cyan]")
            return
        
        subcommand = args[0]
        
        if subcommand == "deploy":
            self.deploy_agent_interactive()
        elif subcommand == "configure":
            self.configure_groq_api()
        elif subcommand == "status":
            self.display_status()
        # Add more as needed


def main() -> None:
    """Entry point for enhanced CLI."""
    cli = EnhancedWhiteCellCLI()
    cli.start()


if __name__ == "__main__":
    main()
