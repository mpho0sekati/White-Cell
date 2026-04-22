"""View and presentation mixin for the enhanced CLI."""

from collections import Counter
from datetime import datetime
from typing import Optional

from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from whitecell.agent import agent_manager
from whitecell.config import get_governance_role
from whitecell.engine import get_session_logs
from whitecell.detection import get_all_threats
from whitecell import governance
from whitecell.cli_shared import WHITECELL_LOGO, console


class CLIViewsMixin:
    """Render CLI views, dashboards, and menus."""

    def display_logo(self) -> None:
        """Render the White Cell logo."""
        console.print(
            Panel(
                f"[bold cyan]{WHITECELL_LOGO}[/bold cyan]",
                title="WHITE CELL",
                border_style="blue",
                expand=False,
            )
        )

    def display_banner(self) -> None:
        """Display startup banner with logo and quick guidance."""
        console.clear()
        self.display_logo()
        console.print(
            Panel(
                "[bold cyan]Detection | Prevention | Intelligence | Protection[/bold cyan]\n"
                "[dim]Type 'help' for command map, 'triage' to start SOC flow, 'peek' for live monitoring.[/dim]",
                title="Cybersecurity Assistant",
                border_style="cyan",
                expand=False,
            )
        )

    def display_dashboard(self) -> None:
        """Display a dashboard-style status view."""
        console.clear()
        logs = get_session_logs()
        agent_stats = agent_manager.get_global_statistics()
        threat_types = [log.get("threat_type", "unknown") for log in logs]
        threat_counts = Counter(threat_types)

        layout = Layout()
        layout.split_column(Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3))
        layout["body"].split_row(Layout(name="left"), Layout(name="right"))

        header_text = "[bold cyan]WHITE CELL SECURITY DASHBOARD[/bold cyan]"
        layout["header"].update(Panel(header_text, style="cyan"))

        stats_text = f"""
[bold]System Statistics[/bold]
----------------------
Session Threats:    {len(logs)}
Total Detected:     {agent_stats['total_threats_detected']}
Threats Prevented:  {agent_stats['total_prevented']}
Active Agents:      {agent_stats['running_agents']}/{agent_stats['total_agents']}

[bold]Top Threats[/bold]
----------------------
"""
        for threat_type, count in threat_counts.most_common(3):
            stats_text += f"{threat_type}: {count}\n"
        layout["left"].update(Panel(stats_text, style="cyan", title="Dashboard"))

        agent_text = "[bold]Agent Status[/bold]\n----------------------\n"
        for agent_id, status in agent_manager.get_all_status().items():
            running = "UP" if status["running"] else "DOWN"
            agent_text += f"{running} {agent_id[:15]}\n"
            agent_text += f"   Checks: {status['checks_performed']}\n"
            agent_text += f"   Threats: {status['threats_detected']}\n"
        if not agent_manager.agents:
            agent_text += "[yellow]No agents deployed[/yellow]\n"
        layout["right"].update(Panel(agent_text, style="green", title="Agents"))

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
            layout.split_column(Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3))
            layout["body"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=2))
            layout["right"].split_column(Layout(name="logs"), Layout(name="events"))

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
                    import time

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
        for cmd, alias, desc in [
            ("help", "h, ?", "Show this help message"),
            ("logo", "lg", "Show White Cell logo"),
            ("exit", "q", "Exit the application"),
            ("status", "st", "Display system status"),
            ("dashboard", "d", "Show live dashboard view"),
            ("peek", "p", "Open live peek monitoring window"),
            ("clear", "c", "Exit Command Mode"),
        ]:
            core_table.add_row(cmd, alias, desc)
        console.print(core_table)

        console.print()
        self._section_header("SOC WORKFLOW")
        soc_table = Table(show_header=True, header_style="bold magenta")
        soc_table.add_column("Command", style="cyan", width=30)
        soc_table.add_column("Description", width=40)
        for cmd, desc in [
            ("triage (tr) <alert_text>", "Classify alert and recommend next steps"),
            ("investigate (inv) <threat|index>", "Build context from matching logs"),
            ("respond (rsp) recommend <incident>", "Generate response plan"),
            ("respond (rsp) execute <action> <target>", "Queue/execute governed response action"),
            ("soc (sf) run <alert> [--execute a t]", "Run triage -> investigate -> respond"),
        ]:
            soc_table.add_row(cmd, desc)
        console.print(soc_table)

        console.print()
        self._section_header("THREAT MANAGEMENT")
        threat_table = Table(show_header=True, header_style="bold magenta")
        threat_table.add_column("Command", style="cyan", width=25)
        threat_table.add_column("Description", width=45)
        for cmd, desc in [
            ("threats (t)", "View all known threat types"),
            ("logs (l) [limit]", "Show latest threat logs"),
            ("search (s) <term>", "Search logs by threat type"),
            ("analyze (a) <type>", "Analyze specific threat"),
            ("export (e) [csv|json]", "Export logs to file"),
            ("scan website <url> [--active]", "Authorized website security analysis"),
            ("scan allowlist show", "List domains approved for active probing"),
            ("scan allowlist add <domain>", "Approve a domain for active probing"),
            ("scan allowlist remove <domain>", "Remove a domain from active probing allowlist"),
            ("trace [options]", "Identify attack source and generate attribution report"),
        ]:
            threat_table.add_row(cmd, desc)
        console.print(threat_table)

        console.print()
        self._section_header("AGENT MANAGEMENT")
        agent_table = Table(show_header=True, header_style="bold magenta")
        agent_table.add_column("Command", style="cyan", width=35)
        agent_table.add_column("Description", width=35)
        for cmd, desc in [
            ("agent deploy <name> [interval]", "Deploy a new agent"),
            ("agent stop <name>", "Stop a running agent"),
            ("agent status", "View all agents status"),
            ("agent threats <name> [limit]", "View agent-specific threats"),
            ("agent configure", "Setup GROQ API key"),
            ("agent blue <scenario>", "Run Blue Team defensive strategy"),
            ("agent red <scenario>", "Run Red Team authorized simulation"),
            ("agent battle <scenario>", "Run Blue vs Red scenario"),
            ("agent ask <prompt>", "General AI cybersecurity prompt"),
            ("agent crewai <objective>", "Run CrewAI mission with current API key"),
            ("agent evolve <cmd>", "Autonomous self-improvement controls"),
        ]:
            agent_table.add_row(cmd, desc)
        console.print(agent_table)

        console.print()
        self._section_header("GOVERNANCE")
        gov_table = Table(show_header=True, header_style="bold magenta")
        gov_table.add_column("Command", style="cyan", width=40)
        gov_table.add_column("Description", width=30)
        for cmd, desc in [
            ("governance (gov) status", "Show role, policy, and pending approvals"),
            ("governance role <admin|analyst|viewer>", "Set active operator role"),
            ("governance approvals list", "List approval requests"),
            ("governance approvals approve <id>", "Approve pending request"),
            ("governance approvals reject <id>", "Reject pending request"),
        ]:
            gov_table.add_row(cmd, desc)
        console.print(gov_table)

        console.print()
        self._section_header("QUICK TIPS")
        for tip in [
            "[cyan]-[/cyan] Type partial commands - they auto-complete",
            "[cyan]-[/cyan] Use aliases for faster typing: 't' for 'threats', 's' for 'search'",
            "[cyan]-[/cyan] SOC default flow: triage -> investigate -> respond",
            "[cyan]-[/cyan] Try 'dashboard' or 'peek' for live visibility",
            "[cyan]-[/cyan] Commands are case-insensitive",
            "[cyan]-[/cyan] 'agent configure' is optional - system works without GROQ",
        ]:
            console.print(f"  {tip}")
        console.print()

    def display_quick_menu(self) -> Optional[str]:
        """Display a quick interactive menu."""
        console.print()
        self._section_header("QUICK MENU")
        menu_table = Table(show_header=False, show_lines=False)
        for key, option, desc in [
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
        ]:
            menu_table.add_row(f"[yellow]{key}[/yellow]", f"[cyan]{option}[/cyan]", f"[dim]{desc}[/dim]")
        console.print(menu_table)
        return Prompt.ask("\n[cyan]Select option[/cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])

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
        self._section_header("THREAT TYPES", "known detection classes")

        table = Table(show_header=True, header_style="bold white on red", padding=(0, 1))
        table.add_column("Type", style="red", width=18)
        table.add_column("Severity", width=12)
        table.add_column("Financial Risk", style="green", width=15)
        table.add_column("POPIA", width=8)
        table.add_column("Description", width=30)

        for threat in threats:
            severity = threat["severity"]
            severity_color = "red" if severity >= 8 else "yellow" if severity >= 6 else "green"
            severity_bar = "#" * severity + "-" * (10 - severity)
            popia = "[red]YES[/red]" if threat["popia_exposure"] else "[green]NO[/green]"
            description = threat["description"]
            if len(description) > 28:
                description = description[:28] + "..."
            table.add_row(
                f"[bold]{threat['threat_type']}[/bold]",
                f"[{severity_color}]{severity_bar}[/{severity_color}]",
                f"${threat['financial_impact']:,}",
                popia,
                description,
            )
        console.print(table)

    def display_status(self) -> None:
        """Display enhanced status report."""
        logs = get_session_logs()
        threat_counts = Counter([log.get("threat_type", "unknown") for log in logs])
        agent_stats = agent_manager.get_global_statistics()

        console.print("\n[bold cyan]SYSTEM STATUS[/bold cyan]\n")

        health_level = "HEALTHY" if len(logs) == 0 else "MONITORING" if len(logs) < 5 else "CRITICAL"
        health_color = "green" if len(logs) == 0 else "yellow" if len(logs) < 5 else "red"
        console.print(Panel(f"[bold {health_color}]{health_level}[/bold {health_color}]", title="System Health", style=health_color, expand=False))

        stats_table = Table(show_header=False, show_lines=False, padding=(0, 2))
        stats_table.add_column("Metric", style="cyan", width=20)
        stats_table.add_column("Value", style="green", width=20)
        for metric, value in [
            ("Threats Logged", str(len(logs))),
            ("Unique Types", str(len(threat_counts))),
            ("Total Agents", str(agent_stats["total_agents"])),
            ("Running Agents", f"{agent_stats['running_agents']}/{agent_stats['total_agents']}"),
            ("Total Checks", str(agent_stats["total_checks_performed"])),
            ("Threats Prevented", str(agent_stats["total_prevented"])),
            ("Role", get_governance_role()),
            ("Pending Approvals", str(len(governance.list_approvals(status="pending")))),
            ("Command Mode", "ACTIVE" if self.state.command_mode else "INACTIVE"),
        ]:
            stats_table.add_row(metric, value)
        console.print(stats_table)

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
            timestamp = log.get("timestamp", "N/A")[:19]
            threat_type = log.get("threat_type", "Unknown")
            risk_score = log.get("risk_score", 0)
            risk_color = "red" if risk_score >= 70 else "yellow" if risk_score >= 40 else "green"
            risk_text = f"[{risk_color}]{risk_score}[/{risk_color}]"
            alert_text = log.get("user_input", "")
            if len(alert_text) > 33:
                alert_text = alert_text[:33] + "..."
            table.add_row(timestamp, threat_type, risk_text, "[green]LOGGED[/green]", alert_text)

        console.print(table)
