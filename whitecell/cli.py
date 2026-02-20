"""
White Cell CLI: Command-line interface

This module provides the interactive shell for the White Cell cybersecurity assistant.
It uses Rich for beautiful terminal formatting and provides an intuitive command system
with aliases, search, export, and analytics capabilities.

Author: White Cell Project
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from collections import Counter
import threading

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from whitecell.engine import handle_input, parse_command, initialize_logging, get_session_logs
from whitecell.detection import get_all_threats, get_threat_description
from whitecell.state import global_state
from whitecell.command_mode import create_risk_table
from whitecell.agent import agent_manager
from whitecell.crew import crew_manager
from whitecell.website_scanner import website_scanner
from whitecell.config import load_config, set_groq_api_key, get_groq_api_key, validate_groq_api_key, set_config_value, get_guardian_config, get_groq_api_status
from whitecell.guardian import start_guardian_from_config, stop_guardian, get_guardian_status, create_and_start_guardian

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
}


class WhiteCellCLI:
    """Interactive command-line interface for White Cell cybersecurity assistant."""

    def __init__(self):
        """Initialize the CLI with global state and session history."""
        self.state = global_state
        self.session_threats = []  # Track threats in current session
        self.command_history = []  # Track command history
        initialize_logging()

    def expand_alias(self, command: str) -> str:
        """
        Expand command aliases to full commands.
        
        Args:
            command: Potentially abbreviated command
            
        Returns:
            Full command name
        """
        return COMMAND_ALIASES.get(command, command)

    def get_prompt(self) -> str:
        """
        Get the current prompt based on system state.

        Returns:
            Formatted prompt string
        """
        if self.state.command_mode:
            return "[bold red][CRISIS MODE] WhiteCell>[/bold red] "
        threat_count = len(self.session_threats)
        if threat_count > 0:
            return f"[bold cyan]WhiteCell ({threat_count} threats) >[/bold cyan] "
        return "[bold cyan]WhiteCell>[/bold cyan] "

    def display_help(self) -> None:
        """Display comprehensive help information and available commands."""
        help_text = """
[bold green]═══════════════════════════════════════════════════════════════[/bold green]
[bold yellow]White Cell - Cybersecurity Assistant v1.1[/bold yellow]
[bold green]═══════════════════════════════════════════════════════════════[/bold green]

[bold cyan]Core Commands:[/bold cyan]
  [yellow]help[/yellow] (h, ?)          - Show this help message
  [yellow]exit[/yellow] (q)              - Exit the application
  [yellow]status[/yellow] (st)           - Show current system status
  [yellow]clear[/yellow] (c)             - Clear Command Mode

[bold cyan]Threat Management:[/bold cyan]
  [yellow]threats[/yellow] (t)           - View all known threat types
  [yellow]logs[/yellow] (l)              - Display threat detection logs
  [yellow]search[/yellow] (s) <term>    - Search logs by threat type
  [yellow]analyze[/yellow] (a) <type>   - Analyze specific threat
  [yellow]export[/yellow] (e) [csv|json]- Export logs to file

[bold cyan]Website Security:[/bold cyan]
  [yellow]scan website[/yellow] <url>   - Scan a website for security weaknesses
                        Use --active flag to enable active probing (requires permission)

[bold cyan]Usage Examples:[/bold cyan]
  Simply type a security scenario or question:
  • "We detected ransomware on 3 servers"
  • "Possible DDoS attack - packet flood detected"
  • "Multiple failed login attempts"
  
  The system will:
  • Detect potential threats using keyword analysis
  • Calculate risk scores (0-100)
  • Provide recommended actions
  • Log all detected threats

[bold cyan]Command Mode:[/bold cyan]
  When a threat is detected:
  • The system enters CRISIS MODE (shown in red)
  • A risk assessment is displayed
  • Suggested actions are provided
  • Use 'clear' to exit Command Mode

[bold cyan]Tips:[/bold cyan]
  • Use aliases: 'h' for 'help', 'l' for 'logs'
  • Type 'threats' to see all threat types
  • Use 'search ransomware' to find specific threats
  • Export logs as CSV: 'export csv'

[bold green]═══════════════════════════════════════════════════════════════[/bold green]
"""
        console.print(help_text)

    def display_threat_types(self) -> None:
        """Display all available threat types with descriptions."""
        threats = get_all_threats()
        table = Table(title="Available Threat Types", show_header=True, header_style="bold magenta")
        table.add_column("Threat Type", style="cyan", width=20)
        table.add_column("Severity", style="yellow", width=10)
        table.add_column("Financial Impact", style="red", width=18)
        table.add_column("POPIA Exposure", style="red", width=15)
        table.add_column("Description", width=35)

        for threat in threats:
            severity_color = "red" if threat['severity'] >= 8 else "yellow" if threat['severity'] >= 6 else "green"
            popia_text = "[red]YES[/red]" if threat['popia_exposure'] else "[green]NO[/green]"
            table.add_row(
                threat['threat_type'],
                f"[{severity_color}]{threat['severity']}/10[/{severity_color}]",
                f"${threat['financial_impact']:,}",
                popia_text,
                threat['description'][:32] + "..." if len(threat['description']) > 32 else threat['description']
            )

        console.print(table)

    def display_status(self) -> None:
        """Display current system status with statistics."""
        logs = get_session_logs()
        threat_types = [log.get('threat_type', 'unknown') for log in logs]
        threat_counts = Counter(threat_types)
        
        status_table = Table(title="System Status", show_header=True, header_style="bold magenta")
        status_table.add_column("Parameter", style="cyan")
        status_table.add_column("Value", style="green")

        status_table.add_row("Command Mode", "[red]ACTIVE[/red]" if self.state.command_mode else "[green]INACTIVE[/green]")
        status_table.add_row("Total Logs", str(len(logs)))
        status_table.add_row("Session Threats", str(len(self.session_threats)))
        status_table.add_row("Last Threat", self.state.last_threat.get("threat_type", "None"))
        
        if logs:
            avg_risk = sum(log.get('risk_score', 0) for log in logs) / len(logs)
            high_risk_count = sum(1 for log in logs if log.get('risk_level') == 'high')
            status_table.add_row("Avg Risk Score", f"{avg_risk:.1f}/100")
            status_table.add_row("High Risk Events", str(high_risk_count))

        console.print(status_table)

    def search_logs(self, query: str) -> None:
        """
        Search logs by threat type or keyword.
        
        Args:
            query: Search term (threat type or keyword)
        """
        logs = get_session_logs()
        results = [
            log for log in logs 
            if query.lower() in log.get('threat_type', '').lower() or 
               query.lower() in log.get('user_input', '').lower()
        ]

        if not results:
            console.print(f"[yellow]No logs found matching '[/yellow]{query}[yellow]'[/yellow]")
            return

        console.print(f"\n[bold cyan]Search Results for '{query}' ({len(results)} found):[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Threat Type", style="yellow")
        table.add_column("Risk Score", style="red")
        table.add_column("Risk Level", style="red")
        table.add_column("Input", width=40)

        for log in results[-10:]:
            table.add_row(
                log['threat_type'],
                str(log['risk_score']),
                log['risk_level'],
                log.get('user_input', '')[:37] + "..." if len(log.get('user_input', '')) > 37 else log.get('user_input', '')
            )

        console.print(table)

    def export_logs(self, format_type: str = "csv") -> None:
        """
        Export logs to file.
        
        Args:
            format_type: Export format ('csv' or 'json')
        """
        logs = get_session_logs()
        if not logs:
            console.print("[yellow]No logs to export.[/yellow]")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type.lower() == "csv":
            filename = f"whitecell_logs_{timestamp}.csv"
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                    writer.writeheader()
                    writer.writerows(logs)
                console.print(f"[green]Logs exported to [/green][cyan]{filename}[/cyan]")
            except Exception as e:
                console.print(f"[red]Export failed: {e}[/red]")
        
        elif format_type.lower() == "json":
            filename = f"whitecell_logs_{timestamp}.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(logs, f, indent=2)
                console.print(f"[green]Logs exported to [/green][cyan]{filename}[/cyan]")
            except Exception as e:
                console.print(f"[red]Export failed: {e}[/red]")
        
        else:
            console.print("[red]Unsupported format. Use 'csv' or 'json'[/red]")

    def display_logs(self, limit: int = 10) -> None:
        """
        Display threat detection logs from file.
        
        Args:
            limit: Number of logs to display
        """
        logs = get_session_logs()
        if not logs:
            console.print("[yellow]No threats have been detected yet.[/yellow]")
            return

        console.print(f"\n[bold cyan]Threat Detection Logs ({len(logs)} total):[/bold cyan]\n")

        logs_table = Table(show_header=True, header_style="bold magenta")
        logs_table.add_column("Timestamp", style="cyan", width=19)
        logs_table.add_column("Threat Type", style="yellow", width=18)
        logs_table.add_column("Risk Score", style="red", width=12)
        logs_table.add_column("Risk Level", style="red", width=12)
        logs_table.add_column("Financial Loss", style="red", width=15)

        for log in logs[-limit:]:
            timestamp = log.get("timestamp", "")[-19:]
            threat_type = log.get("threat_type", "unknown")
            risk_score = str(log.get("risk_score", 0))
            risk_level = log.get("risk_level", "unknown")
            financial = f"${log.get('estimated_financial_loss', 0):,}"

            logs_table.add_row(timestamp, threat_type, risk_score, risk_level, financial)

        console.print(logs_table)

    def analyze_threat(self, threat_type: str) -> None:
        """
        Analyze a specific threat type.
        
        Args:
            threat_type: The threat type to analyze
        """
        logs = get_session_logs()
        threat_logs = [log for log in logs if log['threat_type'] == threat_type]
        
        if not threat_logs:
            console.print(f"[yellow]No logs found for threat type '{threat_type}'[/yellow]")
            return

        description = get_threat_description(threat_type)
        avg_risk = sum(log['risk_score'] for log in threat_logs) / len(threat_logs)
        max_risk = max(log['risk_score'] for log in threat_logs)
        
        console.print(f"\n[bold cyan]Threat Analysis: {threat_type.upper()}[/bold cyan]\n")
        
        analysis_table = Table(show_header=True, header_style="bold magenta")
        analysis_table.add_column("Metric", style="cyan")
        analysis_table.add_column("Value", style="green")
        
        analysis_table.add_row("Description", description)
        analysis_table.add_row("Occurrences", str(len(threat_logs)))
        analysis_table.add_row("Avg Risk Score", f"{avg_risk:.1f}/100")
        analysis_table.add_row("Max Risk Score", f"{max_risk}/100")
        analysis_table.add_row("Total Financial Impact", f"${sum(log['estimated_financial_loss'] for log in threat_logs):,}")

        console.print(analysis_table)

    def configure_groq_api(self) -> None:
        """Configure Groq API key for agent AI-powered decisions."""
        current_key = get_groq_api_key()
        
        if current_key:
            api_status = get_groq_api_status()
            console.print("[cyan]Groq API key is already configured.[/cyan]")
            console.print(f"  Masked Key: [yellow]{api_status['masked_key']}[/yellow]")
            console.print(f"  Hash: [green]{api_status['hash']}[/green]")
            response = input("\nDo you want to update it? (y/n): ").strip().lower()
            if response != 'y':
                return
        
        console.print("\n[bold cyan]Groq API Key Configuration[/bold cyan]")
        console.print("[yellow]Get your API key from: https://console.groq.com/keys[/yellow]\n")
        
        api_key = input("Enter your Groq API key: ").strip()
        if api_key:
            console.print(f"[dim]Input received ({len(api_key)} characters).[/dim]")
        
        if not api_key:
            console.print("[red]API key cannot be empty.[/red]")
            return
        
        if not validate_groq_api_key(api_key):
            console.print("[red]Invalid API key format.[/red]")
            return
        
        if set_groq_api_key(api_key):
            # Get the stored status to display
            api_status = get_groq_api_status()
            console.print("[green]Groq API key configured successfully![/green]")
            console.print(f"[cyan]Masked Key: {api_status['masked_key']}[/cyan]")
            console.print(f"[cyan]Hash: {api_status['hash']}[/cyan]")
            # Reinitialize groq_client with new key
            from whitecell.groq_client import groq_client
            groq_client.set_api_key(api_key)
        else:
            console.print("[red]Failed to save API key.[/red]")

    def display_agent_status(self) -> None:
        """Display status of all agents."""
        status = agent_manager.get_all_status()
        stats = agent_manager.get_global_statistics()
        
        # Display API configuration status
        api_status = get_groq_api_status()
        if api_status['configured']:
            console.print(f"[green]✓ Groq API Configured[/green]: {api_status['masked_key']} | Hash: {api_status['hash']}")
        else:
            console.print("[yellow]! Groq API Not Configured[/yellow]")
        console.print()
        
        if not status:
            console.print("[yellow]No agents available.[/yellow]")
            return
        
        # Global statistics
        stats_table = Table(title="Global Agent Statistics", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Total Agents", str(stats['total_agents']))
        stats_table.add_row("Running Agents", str(stats['running_agents']))
        stats_table.add_row("Total Checks", str(stats['total_checks_performed']))
        stats_table.add_row("Threats Detected", str(stats['total_threats_detected']))
        stats_table.add_row("Threats Prevented", str(stats['total_prevented']))
        
        console.print(stats_table)
        
        # Individual agent status
        console.print("\n")
        agent_table = Table(title="Individual Agent Status", show_header=True, header_style="bold magenta")
        agent_table.add_column("Agent ID", style="cyan")
        agent_table.add_column("Running", style="yellow")
        agent_table.add_column("Checks", style="green")
        agent_table.add_column("Threats", style="red")
        agent_table.add_column("Prevented", style="green")
        
        for agent_id, agent_status in status.items():
            running = "[green]Yes[/green]" if agent_status['running'] else "[yellow]No[/yellow]"
            agent_table.add_row(
                agent_id,
                running,
                str(agent_status['checks_performed']),
                str(agent_status['threats_detected']),
                str(agent_status['prevented_count'])
            )
        
        console.print(agent_table)

    def display_guardian_status(self) -> None:
        """Display status for the guardian agent."""
        status = get_guardian_status()
        if not status or not status.get('running'):
            console.print("[yellow]Guardian is not running.[/yellow]")
            return

        stats_table = Table(title="Guardian Status", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        stats_table.add_row("Running", str(status.get('running')))
        stats_table.add_row("Audit Entries", str(status.get('audit_log_count', 0)))
        stats_table.add_row("Monitored Agents", ", ".join(status.get('prevention_history_agents', []) or []))
        console.print(stats_table)

    def start_guardian(self, args: list[str]) -> None:
        """Start guardian using config or provided overrides."""
        if args:
            # allow overriding basic params: interval limit window
            try:
                ci = float(args[0])
                rl = int(args[1]) if len(args) > 1 else None
                ws = int(args[2]) if len(args) > 2 else None
                create_and_start_guardian(check_interval=ci, prevention_rate_limit=rl, window_seconds=ws, use_config=False)
                console.print(f"[green]Guardian started with interval={ci}, rate_limit={rl}, window={ws}[/green]")
                return
            except Exception:
                console.print("[red]Invalid arguments. Usage: guardian start [check_interval] [rate_limit] [window_seconds][/red]")
                return

        start_guardian_from_config()
        console.print("[green]Guardian started using configuration.[/green]")

    def stop_guardian(self, args: list[str]) -> None:
        if stop_guardian():
            console.print("[green]Guardian stopped.[/green]")
        else:
            console.print("[yellow]Guardian was not running.[/yellow]")

    def configure_guardian(self, args: list[str]) -> None:
        """Manage guardian configuration.

        Usage:
          guardian config show
          guardian config set <key> <value>
        """
        if not args:
            console.print("[yellow]Usage: guardian config <show|set> ...[/yellow]")
            return

        sub = args[0]
        if sub == "show":
            cfg = get_guardian_config()
            console.print(cfg)
        elif sub == "set":
            if len(args) < 3:
                console.print("[yellow]Usage: guardian config set <key> <value>[/yellow]")
                return
            key = args[1]
            val = args[2]
            # Try to coerce numeric/bool
            if val.lower() in ("true", "false"):
                v = val.lower() == "true"
            else:
                try:
                    v = int(val)
                except Exception:
                    try:
                        v = float(val)
                    except Exception:
                        v = val

            cfg = get_guardian_config()
            cfg[key] = v
            set_config_value("guardian", cfg)
            console.print(f"[green]Guardian config updated: {key} = {v}[/green]")
        else:
            console.print(f"[yellow]Unknown guardian subcommand: {sub}[/yellow]")

    def deploy_agent(self, args: list[str]) -> None:
        """
        Deploy a new security agent.
        
        Args:
            args: Command arguments [agent_id, interval (optional)]
        """
        if not args:
            console.print("[yellow]Usage: agent deploy <agent_id> [check_interval][/yellow]")
            return
        
        agent_id = args[0]
        check_interval = int(args[1]) if len(args) > 1 and args[1].isdigit() else 60
        
        # Create and start agent
        agent = agent_manager.create_agent(agent_id, check_interval)
        
        if agent_manager.start_agent(agent_id):
            console.print(f"[green]Agent '{agent_id}' deployed and running![/green]")
            console.print(f"[cyan]Check interval: {check_interval} seconds[/cyan]")
        else:
            console.print(f"[red]Failed to start agent '{agent_id}'[/red]")

    def stop_agent(self, args: list[str]) -> None:
        """
        Stop a running agent.
        
        Args:
            args: Command arguments [agent_id]
        """
        if not args:
            console.print("[yellow]Usage: agent stop <agent_id>[/yellow]")
            return
        
        agent_id = args[0]
        if agent_manager.stop_agent(agent_id):
            console.print(f"[green]Agent '{agent_id}' stopped.[/green]")
        else:
            console.print(f"[red]Failed to stop agent '{agent_id}'[/red]")

    def view_agent_threats(self, args: list[str]) -> None:
        """
        View threats detected by an agent.
        
        Args:
            args: Command arguments [agent_id, limit (optional)]
        """
        if not args:
            console.print("[yellow]Usage: agent threats <agent_id> [limit][/yellow]")
            return
        
        agent_id = args[0]
        limit = int(args[1]) if len(args) > 1 and args[1].isdigit() else 10
        
        if agent_id not in agent_manager.agents:
            console.print(f"[red]Agent '{agent_id}' not found.[/red]")
            return
        
        agent = agent_manager.agents[agent_id]
        threats = agent.get_recent_threats(limit)
        
        if not threats:
            console.print(f"[yellow]No threats detected by agent '{agent_id}'[/yellow]")
            return
        
        console.print(f"\n[bold cyan]Recent Threats - Agent '{agent_id}' ({len(threats)}):[/bold cyan]\n")
        
        threats_table = Table(show_header=True, header_style="bold magenta")
        threats_table.add_column("Timestamp", style="cyan")
        threats_table.add_column("Threat Type", style="yellow")
        threats_table.add_column("Risk Score", style="red")
        threats_table.add_column("Prevented", style="green")
        threats_table.add_column("Threat Details", width=40)
        
        for threat in threats:
            prevented = "[green]YES[/green]" if threat.get('prevented') else "[yellow]NO[/yellow]"
            timestamp = threat.get('timestamp', 'N/A')[:19]  # Format: YYYY-MM-DD HH:MM:SS
            threat_text = threat.get('threat', '')[:40]
            
            threats_table.add_row(
                timestamp,
                threat.get('threat_type', 'Unknown'),
                str(threat.get('risk_score', 0)),
                prevented,
                threat_text
            )
        
        console.print(threats_table)

    def spawn_helper(self, args: list[str]) -> None:
        """Spawn a temporary helper agent to run a short task.

        Usage: crew spawn <description> [duration_seconds]
        """
        if not args:
            console.print("[yellow]Usage: crew spawn <description> [duration_seconds][/yellow]")
            return

        description = args[0]
        duration = int(args[1]) if len(args) > 1 and args[1].isdigit() else 10

        helper_id = crew_manager.spawn_helper(description, duration=duration)
        console.print(f"[green]Spawned helper {helper_id} (duration={duration}s). Use 'crew report {helper_id}' to fetch report.[/green]")

    def crew_report(self, args: list[str]) -> None:
        """Fetch report for a helper agent.

        Usage: crew report <helper_id>
        """
        if not args:
            console.print("[yellow]Usage: crew report <helper_id>[/yellow]")
            return

        helper_id = args[0]
        report = crew_manager.get_report(helper_id)
        if not report:
            console.print(f"[yellow]No report found for {helper_id} yet.[/yellow]")
            return

        console.print(f"\n[bold cyan]Helper Report: {helper_id}[/bold cyan]\n")
        console.print(report)

    def list_helpers(self, args: list[str]) -> None:
        """List currently tracked helper agents."""
        helpers = crew_manager.list_helpers()
        if not helpers:
            console.print("[yellow]No helpers active.[/yellow]")
            return
        console.print(f"[cyan]Helpers ({len(helpers)}):[/cyan] {', '.join(helpers)}")

    def crew_watch(self, args: list[str]) -> None:
        """Start a live watch that streams helper events. Usage: crew watch [helper_id]

        Press Enter to stop watching.
        """
        helper_id = args[0] if args else None
        helpers = [helper_id] if helper_id else None

        stop_event = threading.Event()

        def print_event(ev):
            # Minimal formatted output
            ts = ev.get('timestamp', '')
            ev_type = ev.get('event')
            console.print(f"[magenta]{ts}[/magenta] [yellow]{ev_type}[/yellow] {ev.get('data') or ev.get('action') or ''}")

        thread = threading.Thread(target=crew_manager.watch_helpers, args=(helpers, print_event, 0.5, stop_event), daemon=True)
        thread.start()

        console.print("[green]Watching helper events. Press Enter to stop.[/green]")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass

        stop_event.set()
        thread.join(timeout=2)
        console.print("[green]Stopped watching helpers.[/green]")

    def scan_website(self, args: list[str]) -> None:
        """Scan a website for security weaknesses.
        
        Usage: scan website <url> [--active]
        """
        if not args:
            console.print("[yellow]Usage: scan website <url> [--active][/yellow]")
            return

        url = args[0]
        active = len(args) > 1 and "--active" in args

        console.print(f"[cyan]Scanning {url}...[/cyan]")

        # First run passive scan (always safe, no permission needed)
        passive_result = website_scanner.passive_scan(url)
        passive_report = website_scanner.format_report(passive_result)
        console.print(passive_report)

        # If user requested active or if passive found critical issues, ask about active
        if active or (passive_result["risk_level"] in ["critical", "high"]):
            console.print("\n[bold yellow]WARNING: Active probing requires connecting to the target website.[/bold yellow]")
            console.print("[yellow]This may trigger security alerts or be detected by the target.[/yellow]\n")
            
            response = input("[bold]Do you authorize active probing on this website? (yes/no): [/bold]").strip().lower()
            
            if response in ["yes", "y"]:
                console.print("\n[cyan]Running active security tests...[/cyan]\n")
                active_result = website_scanner.active_scan(url)
                active_report = website_scanner.format_report(active_result)
                console.print(active_report)
            else:
                console.print("[yellow]Active probing cancelled. Use results from passive scan above.[/yellow]")

    def view_learned_techniques(self, args: list[str]) -> None:
        """View techniques learned from agent interactions.
        
        Usage: learn techniques <threat_type>
        """
        if not args:
            console.print("[yellow]Usage: learn techniques <threat_type>[/yellow]")
            return
        
        threat_type = args[0]
        techniques = agent_manager.get_learned_techniques(threat_type)
        
        if not techniques:
            console.print(f"[yellow]No learned techniques for {threat_type}[/yellow]")
            return
        
        console.print(f"\n[bold cyan]Learned Techniques for {threat_type}:[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Technique", style="cyan")
        table.add_column("Effectiveness", style="green")
        table.add_column("Uses", style="yellow")
        table.add_column("Successes", style="green")
        
        for t in techniques:
            table.add_row(
                t["technique"],
                f"{t['effectiveness']:.0f}%",
                str(t["uses"]),
                str(t["successes"])
            )
        
        console.print(table)

    def view_learned_rules(self, args: list[str]) -> None:
        """View decision rules extracted from learned patterns.
        
        Usage: learn rules
        """
        rules = agent_manager.get_learned_rules()
        
        if not rules:
            console.print("[yellow]No learned rules yet. Agents need more interactions to learn.[/yellow]")
            return
        
        console.print(f"\n[bold cyan]Learned Decision Rules ({len(rules)}):[/bold cyan]\n")
        
        for i, rule in enumerate(rules, 1):
            severity_color = "red" if rule.get("confidence", 0) >= 90 else "yellow" if rule.get("confidence", 0) >= 70 else "green"
            confidence = f"[{severity_color}]{rule.get('confidence', 0):.0f}%[/{severity_color}]" if "confidence" in rule else ""
            console.print(f"{i}. {rule['rule']}")
            if confidence:
                console.print(f"   Confidence: {confidence}")
            console.print()

    def get_threat_recommendation(self, args: list[str]) -> None:
        """Get AI recommendation for handling a threat.
        
        Usage: learn recommend <threat_type> [task_type]
        """
        if not args:
            console.print("[yellow]Usage: learn recommend <threat_type> [task_type][/yellow]")
            return
        
        threat_type = args[0]
        task_type = args[1] if len(args) > 1 else "remediate"
        
        recommendation = agent_manager.get_recommendation_for_threat(threat_type, task_type)
        
        if not recommendation:
            console.print(f"[yellow]No learned patterns for {threat_type}. Deploy agents to gather data.[/yellow]")
            return
        
        console.print(f"\n[bold cyan]Recommendation for {threat_type}:[/bold cyan]\n")
        console.print(f"Task Type: [yellow]{task_type}[/yellow]")
        console.print(f"Confidence: [green]{recommendation['confidence']:.0f}%[/green]\n")
        
        if "recommended_techniques" in recommendation:
            console.print("[bold]Recommended Techniques:[/bold]")
            for i, tech in enumerate(recommendation["recommended_techniques"], 1):
                console.print(f"  {i}. {tech['technique']} ({tech['effectiveness']:.0f}% effective)")
        
        if "ai_recommendation" in recommendation:
            console.print(f"\n[bold]AI Analysis:[/bold]\n{recommendation['ai_recommendation']}")

    def view_learning_summary(self, args: list[str]) -> None:
        """View summary of what agents have learned.
        
        Usage: learn summary [agent_id]
        """
        agent_id = args[0] if args else None
        summary = agent_manager.get_learning_summary(agent_id)
        console.print(summary)

    def handle_agent_command(self, args: list[str]) -> bool:
        """
        Handle agent-related commands.
        
        Args:
            args: Command arguments
            
        Returns:
            True to continue session
        """
        if not args:
            console.print("[yellow]Agent Commands:[/yellow]")
            console.print("  agent deploy <id> [interval] - Deploy a new agent")
            console.print("  agent stop <id>              - Stop an agent")
            console.print("  agent status                 - Show agent status")
            console.print("  agent threats <id> [limit]   - View agent threats")
            console.print("  agent configure              - Set Groq API key")
            return True
        
        subcommand = args[0]
        remaining_args = args[1:]
        
        if subcommand == "deploy":
            self.deploy_agent(remaining_args)
        elif subcommand == "stop":
            self.stop_agent(remaining_args)
        elif subcommand == "status":
            self.display_agent_status()
        elif subcommand == "threats":
            self.view_agent_threats(remaining_args)
        elif subcommand == "configure":
            self.configure_groq_api()
        else:
            console.print(f"[yellow]Unknown agent subcommand: {subcommand}[/yellow]")
        
        return True

    def handle_crew_command(self, args: list[str]) -> bool:
        """Handle crew-related commands.

        Usage:
          crew spawn <description> [duration_seconds]
          crew report <helper_id>
          crew list
          crew watch [helper_id]
        """
        if not args:
            console.print("[yellow]Crew Commands:[/yellow]")
            console.print("  crew spawn <description> [duration] - Spawn a helper agent")
            console.print("  crew report <helper_id>              - Fetch helper report")
            console.print("  crew list                           - List helpers")
            console.print("  crew watch [helper_id]              - Watch helper events live")
            return True

        sub = args[0]
        remaining = args[1:]
        if sub == "spawn":
            self.spawn_helper(remaining)
        elif sub == "report":
            self.crew_report(remaining)
        elif sub == "list":
            self.list_helpers(remaining)
        elif sub == "watch":
            self.crew_watch(remaining)
        else:
            console.print(f"[yellow]Unknown crew subcommand: {sub}[/yellow]")

        return True

    def handle_guardian_command(self, args: list[str]) -> bool:
        """Handle guardian-related commands.

        Usage:
          guardian start [interval rate_limit window]
          guardian stop
          guardian status
          guardian config <show|set>
        """
        if not args:
            console.print("[yellow]Guardian Commands:[/yellow]")
            console.print("  guardian start [interval rate_limit window] - Start guardian")
            console.print("  guardian stop                         - Stop guardian")
            console.print("  guardian status                       - Show guardian status")
            console.print("  guardian config show|set              - View or change guardian config")
            return True

        sub = args[0]
        remaining = args[1:]
        if sub == "start":
            self.start_guardian(remaining)
        elif sub == "stop":
            self.stop_guardian(remaining)
        elif sub == "status":
            self.display_guardian_status()
        elif sub == "config":
            self.configure_guardian(remaining)
        else:
            console.print(f"[yellow]Unknown guardian subcommand: {sub}[/yellow]")

        return True

    def handle_scan_command(self, args: list[str]) -> bool:
        """Handle security scanning commands.
        
        Usage:
          scan website <url> [--active]
        """
        if not args:
            console.print("[yellow]Scan Commands:[/yellow]")
            console.print("  scan website <url> [--active]  - Scan website for vulnerabilities")
            return True
        
        sub = args[0]
        remaining = args[1:]
        
        if sub == "website":
            self.scan_website(remaining)
        else:
            console.print(f"[yellow]Unknown scan subcommand: {sub}[/yellow]")
        
        return True

    def handle_learn_command(self, args: list[str]) -> bool:
        """Handle agent learning commands.
        
        Usage:
          learn summary [agent_id]
          learn techniques <threat_type>
          learn rules
          learn recommend <threat_type> [task_type]
        """
        if not args:
            console.print("[yellow]Learning Commands:[/yellow]")
            console.print("  learn summary [agent_id]           - View learning summary")
            console.print("  learn techniques <threat_type>     - View learned techniques")
            console.print("  learn rules                        - View extracted decision rules")
            console.print("  learn recommend <threat_type>      - Get recommendation for threat")
            return True
        
        sub = args[0]
        remaining = args[1:]
        
        if sub == "summary":
            self.view_learning_summary(remaining)
        elif sub == "techniques":
            self.view_learned_techniques(remaining)
        elif sub == "rules":
            self.view_learned_rules(remaining)
        elif sub == "recommend":
            self.get_threat_recommendation(remaining)
        else:
            console.print(f"[yellow]Unknown learn subcommand: {sub}[/yellow]")
        
        return True

    def handle_command(self, command: str, args: list[str]) -> bool:
        """
        Handle built-in CLI commands.

        Args:
            command: The command to execute
            args: Command arguments

        Returns:
            True to continue the session, False to exit
        """
        # Expand aliases
        command = self.expand_alias(command)

        if command == "exit":
            console.print("[bold green]Exiting White Cell. Stay secure![/bold green]")
            return False

        elif command == "help":
            self.display_help()

        elif command == "threats":
            self.display_threat_types()

        elif command == "status":
            self.display_status()

        elif command == "logs":
            limit = int(args[0]) if args and args[0].isdigit() else 10
            self.display_logs(limit)

        elif command == "search":
            if not args:
                console.print("[yellow]Usage: search <threat_type>[/yellow]")
            else:
                self.search_logs(args[0])

        elif command == "analyze":
            if not args:
                console.print("[yellow]Usage: analyze <threat_type>[/yellow]")
            else:
                self.analyze_threat(args[0])

        elif command == "export":
            format_type = args[0] if args else "csv"
            self.export_logs(format_type)

        elif command == "clear":
            if self.state.command_mode:
                self.state.deactivate_command_mode()
                console.print("[green]Command Mode deactivated.[/green]")
            else:
                console.print("[yellow]Command Mode is not active.[/yellow]")

        elif command == "agent":
            return self.handle_agent_command(args)
        elif command == "guardian":
            return self.handle_guardian_command(args)
        elif command == "crew":
            return self.handle_crew_command(args)
        elif command == "scan":
            return self.handle_scan_command(args)
        elif command == "learn":
            return self.handle_learn_command(args)

        else:
            return None  # Not a recognized command

        return True

    def start(self) -> None:
        """Start the interactive CLI session."""
        console.print("\n[green]" + "─"*60 + "[/green]")
        console.print("[bold green]White Cell - Cybersecurity Assistant v1.1[/bold green]")
        console.print("[green]" + "─"*60 + "[/green]")
        console.print("[yellow]Type 'help' for commands or ask about threats[/yellow]\n")

        try:
            while self.state.session_active:
                # Get user input
                user_input = input(self.get_prompt())

                if not user_input.strip():
                    continue

                # Add to history
                self.command_history.append(user_input)

                # Parse the input
                command, args = parse_command(user_input)

                # Handle built-in commands
                if command in ["exit", "help", "threats", "status", "logs", "search", "analyze", "export", "clear", "agent", "guardian", "crew", "scan", "learn"] or command in COMMAND_ALIASES:
                    result = self.handle_command(command, args)
                    if result is False:
                        break
                    continue

                # Process as threat detection / reasoning input
                response = handle_input(user_input)
                console.print(response)
                
                # Track threat if one was detected
                from whitecell.detection import detect_threat
                threat = detect_threat(user_input)
                if threat:
                    self.session_threats.append(threat)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold green]Exiting White Cell. Stay secure![/bold green]")
            self.state.session_active = False


def main() -> None:
    """Entry point for the White Cell CLI."""
    cli = WhiteCellCLI()
    cli.start()


if __name__ == "__main__":
    main()
