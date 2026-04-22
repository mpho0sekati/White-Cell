"""Agent, AI, and task-oriented mixin for the enhanced CLI."""

import csv
import json
from datetime import datetime
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from whitecell.agent import agent_manager
from whitecell.config import get_groq_api_key, set_groq_api_key, validate_groq_api_key
from whitecell.crew import crew_manager
from whitecell.engine import get_session_logs
from whitecell.groq_client import groq_client
from whitecell.self_improve import self_improver
from whitecell.cli_shared import console


class CLIAgentsMixin:
    """Agent deployment, AI prompts, and task management."""

    def deploy_agent_interactive(self) -> None:
        """Interactive agent deployment."""
        console.print()
        self._section_header("DEPLOY NEW AGENT")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")

        agent_id = Prompt.ask("[cyan]Agent name[/cyan]", default="monitor-1")
        if agent_id.lower() == "cancel":
            console.print("[yellow]Cancelled[/yellow]")
            return

        interval = Prompt.ask("[cyan]Check interval (seconds)[/cyan]", default="60")
        if interval.lower() == "cancel":
            console.print("[yellow]Cancelled[/yellow]")
            return

        try:
            interval_int = int(interval)
            if interval_int < 10 or interval_int > 3600:
                console.print("[red]Interval must be between 10-3600 seconds[/red]")
                return

            agent_manager.create_agent(agent_id, interval_int)
            if agent_manager.start_agent(agent_id):
                self._notify("ok", f"Agent '[bold]{agent_id}[/bold]' deployed and running")
                console.print(f"[cyan]  Interval: {interval_int}s[/cyan]")
                console.print("[cyan]  Status: Running[/cyan]")
            else:
                self._notify("error", "Failed to start agent")
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
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                    writer.writeheader()
                    writer.writerows(logs)
            else:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=2)
            self._notify("ok", f"Exported {len(logs)} logs to {filename}")
        except Exception as e:
            self._notify("error", f"Export failed: {e}")

        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()

    def configure_groq_api(self) -> None:
        """Interactive GROQ configuration."""
        console.print()
        self._section_header("GROQ API CONFIGURATION")
        console.print("[dim]Get your free API key: https://console.groq.com/keys[/dim]")
        console.print("[dim](Type 'cancel' to go back)[/dim]\n")

        import whitecell.cli_enhanced as cli_mod

        current_key = cli_mod.get_groq_api_key()
        if current_key:
            self._notify("warn", "GROQ API key already configured")
            if not Confirm.ask("Update it?"):
                return

        api_key = Prompt.ask("[cyan]Enter your GROQ API key[/cyan]", password=True).strip()
        if api_key and api_key.lower() != "cancel":
            console.print(f"[dim]Input received ({len(api_key)} characters).[/dim]")
        if not api_key or api_key.lower() == "cancel":
            console.print("[yellow]Cancelled[/yellow]")
            return
        if not cli_mod.validate_groq_api_key(api_key):
            self._notify("error", "Invalid API key format")
            return

        if cli_mod.set_groq_api_key(api_key):
            self._notify("ok", "GROQ API key configured successfully")
            if cli_mod.groq_client.reload_from_config():
                self._notify("ok", "AI features are now active and ready to use")
            else:
                self._notify("warn", "API key saved but client not yet initialized. Check your connection.")
        else:
            self._notify("error", "Failed to save API key")

        console.print("\n[dim]Press Enter to return to main menu...[/dim]")
        input()

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
            interval = int(args[1]) if len(args) > 1 and args[1].isdigit() else 120
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
            for proposal in proposals:
                table.add_row(proposal.get("id", "-"), proposal.get("status", "-"), proposal.get("risk", "-"), proposal.get("title", "-"))
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

    def run_agent_ai_prompt(self, mode: str, prompt_text: str) -> None:
        """Run AI-powered agent prompts for blue/red/battle/general scenarios."""
        if not prompt_text:
            prompt_text = Prompt.ask("[cyan]Enter scenario/prompt[/cyan]").strip()
            if not prompt_text:
                console.print("[yellow]Prompt cannot be empty.[/yellow]")
                return

        import whitecell.cli_enhanced as cli_mod

        if not cli_mod.groq_client.is_configured():
            console.print("[yellow]Groq API is not configured. Run 'agent configure' first.[/yellow]")
            return

        if mode == "blue":
            with console.status("[cyan]Running Blue Team exercise...[/cyan]", spinner="dots"):
                result = cli_mod.groq_client.blue_team_exercise(prompt_text)
            console.print(Panel(result, title="Blue Team Strategy", border_style="cyan"))
            return
        if mode == "red":
            with console.status("[cyan]Running Red Team exercise...[/cyan]", spinner="dots"):
                result = cli_mod.groq_client.red_team_exercise(prompt_text)
            console.print(Panel(result, title="Red Team Strategy", border_style="red"))
            return
        if mode == "battle":
            with console.status("[cyan]Running Blue vs Red scenario...[/cyan]", spinner="dots"):
                result = cli_mod.groq_client.team_battle_scenario(prompt_text)
            if not isinstance(result, dict):
                console.print(Panel(str(result), title="Battle Scenario", border_style="yellow"))
                return
            if result.get("status") != "success":
                console.print(Panel(result.get("message", "Failed to run team battle scenario."), title="Battle Scenario Error", border_style="red"))
                return
            console.print(Panel(result.get("blue_team", {}).get("strategy", "No blue team strategy returned."), title="Blue Team (Defense)", border_style="cyan"))
            console.print(Panel(result.get("red_team", {}).get("strategy", "No red team strategy returned."), title="Red Team (Offense)", border_style="red"))
            return

        with console.status("[cyan]Querying cybersecurity assistant...[/cyan]", spinner="dots"):
            result = cli_mod.groq_client.get_explanation(prompt_text)
        console.print(Panel(result, title="Agent Response", border_style="green"))

    def handle_task_command(self, args: list) -> None:
        """Handle task-related commands."""
        if not args:
            console.print("[yellow]Usage: task (list|show|assign) [options][/yellow]")
            return
        subcommand = args[0].lower()
        if subcommand == "list":
            self.list_tasks()
        elif subcommand == "show" and len(args) > 1:
            self.show_task_results(args[1])
        elif subcommand == "show":
            self.show_task_results()
        elif subcommand == "assign":
            self.assign_task_interactive()
        else:
            console.print(f"[yellow]Unknown task subcommand: {subcommand}[/yellow]")
            console.print("[yellow]Usage: task (list|show|assign) [options][/yellow]")

    def assign_task_interactive(self) -> None:
        """Interactively assign a task to an agent."""
        console.print()
        self._section_header("TASK ASSIGNMENT")
        console.print()

        available_agents = [agent_id for agent_id, agent in agent_manager.agents.items() if agent.running]
        if not available_agents:
            self._notify("error", "No running agents available")
            return

        console.print("[cyan]Running agents:[/cyan]")
        for index, agent_id in enumerate(available_agents, 1):
            console.print(f"  {index}. {agent_id}")

        choice = Prompt.ask("[cyan]Select agent (number or all)[/cyan]", default="1")
        if choice.lower() == "all":
            target_agents = available_agents
        else:
            try:
                idx = int(choice) - 1
                if not 0 <= idx < len(available_agents):
                    console.print("[red]Invalid selection[/red]")
                    return
                target_agents = [available_agents[idx]]
            except ValueError:
                console.print("[red]Invalid input[/red]")
                return

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

        task_type = {
            "1": "check",
            "2": "scan",
            "3": "threat_analysis",
            "4": "remediate",
            "5": "custom",
        }.get(Prompt.ask("[cyan]Select task type[/cyan]", default="1"))
        if not task_type:
            console.print("[red]Invalid task type[/red]")
            return

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
            threat_name = Prompt.ask("[cyan]Enter threat type[/cyan] (ransomware, malware, exploit, denial_of_service)")
            parameters["threat_type"] = threat_name
            description = f"Remediate {threat_name}"
        elif task_type == "custom":
            action = Prompt.ask("[cyan]Enter custom action[/cyan]")
            parameters["action"] = action
            description = f"Custom: {action}"

        task = agent_manager.create_task(task_type, description, parameters)
        assigned_count = 0
        for agent_id in target_agents:
            if agent_manager.assign_task_to_agent(agent_id, task):
                assigned_count += 1

        if assigned_count > 0:
            self._notify("ok", f"Task assigned to {assigned_count} agent(s)")
            console.print(f"  Task ID: {task.task_id}")
            console.print(f"  Type: {task_type}")
            console.print(f"  Description: {description}")
        else:
            self._notify("error", "Failed to assign task")

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
                for task in tasks[-5:]:
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
            agents_to_show = {agent_id: agent_manager.get_agent_completed_tasks(agent_id, limit=10)}
        else:
            agents_to_show = agent_manager.get_all_completed_tasks()

        for current_agent_id, tasks in agents_to_show.items():
            if tasks:
                console.print(f"\n[bold cyan]{current_agent_id}:[/bold cyan]")
                for task in tasks[-3:]:
                    console.print(f"\n  Task: {task['task_id']}")
                    console.print(f"  Type: {task['task_type']}")
                    console.print(f"  Status: {task['status']}")
                    console.print(f"  Description: {task['description']}")
                    if task["error"]:
                        console.print(f"  Error: {task['error']}")
                    if task["result"]:
                        console.print(f"  Result: {json.dumps(task['result'], indent=2)[:200]}...")
