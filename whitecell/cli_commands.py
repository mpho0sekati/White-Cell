"""Command routing and workflow mixin for the enhanced CLI."""

import inspect
from dataclasses import dataclass
from typing import Optional

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from whitecell.engine import get_session_logs
from whitecell.cli_shared import console


RESPONSE_ACTIONS = {
    "contain": "Network containment initiated for {target}.",
    "isolate": "Host isolation in progress for {target}.",
    "reboot": "Remote reboot initiated for {target}.",
    "patch": "Patch deployment queued for {target}.",
    "block_ip": "IP blocking activated for {target}.",
    "block_domain": "Domain blocking activated for {target}.",
    "reset_password": "Password reset initiated for {target}.",
    "quarantine_email": "Email quarantine activated for {target}.",
}


@dataclass(frozen=True)
class CommandSpec:
    """Registered command metadata."""

    handler_name: str
    permission: Optional[str] = None
    action_name: Optional[str] = None


COMMAND_REGISTRY = {
    "exit": CommandSpec("_command_exit"),
    "help": CommandSpec("display_help", permission="view.help", action_name="help"),
    "logo": CommandSpec("display_logo"),
    "threats": CommandSpec("display_threat_types", permission="view.status", action_name="threats"),
    "status": CommandSpec("display_status", permission="view.status", action_name="status"),
    "dashboard": CommandSpec("_command_dashboard", permission="view.dashboard", action_name="dashboard"),
    "peek": CommandSpec("_command_peek", permission="view.dashboard", action_name="peek"),
    "logs": CommandSpec("_command_logs", permission="view.logs", action_name="logs"),
    "search": CommandSpec("_command_search", permission="view.logs", action_name="search"),
    "analyze": CommandSpec("_command_analyze", permission="view.logs", action_name="analyze"),
    "export": CommandSpec("export_logs_interactive", permission="view.logs", action_name="export"),
    "scan": CommandSpec("handle_scan_command", permission="scan.website.passive", action_name="scan"),
    "agent": CommandSpec("handle_agent_command", permission="agent.use", action_name="agent"),
    "triage": CommandSpec("handle_triage_command", permission="soc.triage", action_name="triage"),
    "investigate": CommandSpec("handle_investigate_command", permission="soc.investigate", action_name="investigate"),
    "respond": CommandSpec("handle_respond_command", permission="soc.respond", action_name="respond"),
    "governance": CommandSpec("handle_governance_command"),
    "soc": CommandSpec("handle_soc_command", permission="soc.triage", action_name="soc"),
    "task": CommandSpec("handle_task_command"),
    "trace": CommandSpec("handle_trace_command", permission="scan.network", action_name="trace"),
    "clear": CommandSpec("_command_clear"),
}


class CLICommandsMixin:
    """Command registry and workflow handlers."""

    def get_command_registry(self) -> dict[str, CommandSpec]:
        """Return the CLI command registry."""
        return COMMAND_REGISTRY

    def handle_command(self, command: str, args: list) -> bool:
        """Dispatch a command through the registry."""
        spec = self.get_command_registry().get(self.expand_alias(command))
        if not spec:
            return True
        if spec.permission and not self._check_permission(spec.permission, spec.action_name or command):
            return True
        handler = getattr(self, spec.handler_name)
        parameter_count = len(inspect.signature(handler).parameters)
        result = handler(args) if parameter_count else handler()
        return True if result is None else result

    def _command_exit(self, args: list) -> bool:
        self._notify("ok", "Goodbye!")
        return False

    def _command_dashboard(self, args: list) -> None:
        try:
            self.display_dashboard()
        except KeyboardInterrupt:
            console.print("\n[yellow]Dashboard closed[/yellow]")

    def _command_peek(self, args: list) -> None:
        try:
            refresh_seconds = float(args[0]) if args else 1.0
        except ValueError:
            console.print("[yellow]Usage: peek [refresh_seconds][/yellow]")
            return
        self.display_peek_window(refresh_seconds)

    def _command_logs(self, args: list) -> None:
        limit = int(args[0]) if args and args[0].isdigit() else 10
        self.display_logs(limit)

    def _command_search(self, args: list) -> None:
        if not args:
            console.print("[yellow]Usage: search <threat_type>[/yellow]")

    def _command_analyze(self, args: list) -> None:
        if not args:
            console.print("[yellow]Usage: analyze <threat_type>[/yellow]")

    def _command_clear(self, args: list) -> None:
        if self.state.command_mode:
            self.state.deactivate_command_mode()
            self._notify("ok", "Command Mode deactivated")
        else:
            console.print("[yellow]Command Mode is not active[/yellow]")

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
        import whitecell.cli_enhanced as cli_mod

        threat_info = detect_threat(alert_text)
        if not threat_info:
            cli_mod.governance.audit_event("soc", "triage", self.role, "no-threat", {"input": alert_text[:80]})
            console.print(Panel("No known threat signature detected.\nRecommendation: monitor and collect more telemetry.", title="Triage Result", border_style="green"))
            return

        threat_info.update(get_threat_context(threat_info["threat_type"]))
        risk_info = calculate_risk(threat_info)
        mitigations = get_threat_mitigations(threat_info["threat_type"])[:4]
        mitigation_text = "\n".join(f"- {item}" for item in mitigations) if mitigations else "- No predefined mitigations."
        body = (
            f"[bold]Threat Type:[/bold] {threat_info.get('threat_type')}\n"
            f"[bold]Risk Score:[/bold] {risk_info.get('risk_score')}\n"
            f"[bold]Risk Level:[/bold] {risk_info.get('risk_level')}\n"
            f"[bold]Severity:[/bold] {threat_info.get('severity')}\n\n"
            f"[bold]Recommended Immediate Actions[/bold]\n{mitigation_text}"
        )
        cli_mod.governance.audit_event("soc", "triage", self.role, "completed", {"threat_type": threat_info.get("threat_type"), "risk_score": risk_info.get("risk_score")})
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

        matches = [logs[int(selector)]] if selector.isdigit() and 0 <= int(selector) < len(logs) else [row for row in logs if selector.lower() in str(row.get("threat_type", "")).lower()]
        if not matches:
            console.print(f"[yellow]No logs matched '{selector}'.[/yellow]")
            return

        table = Table(title=f"Investigation Matches ({len(matches)})", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Time", style="cyan", width=19, no_wrap=True)
        table.add_column("Threat", style="yellow", min_width=12)
        table.add_column("Risk", style="red", width=6, no_wrap=True)
        table.add_column("Input", overflow="ellipsis")
        for row in matches[-10:]:
            table.add_row(str(row.get("timestamp", ""))[:19], str(row.get("threat_type", "unknown")), str(row.get("risk_score", "-")), str(row.get("user_input", ""))[:60])
        import whitecell.cli_enhanced as cli_mod

        cli_mod.governance.audit_event("soc", "investigate", self.role, "completed", {"selector": selector, "matches": len(matches)})
        console.print(table)

    def handle_respond_command(self, args: list) -> None:
        """SOC respond: recommend or execute actions with governance controls."""
        if not args:
            console.print("[yellow]Usage: respond <recommend|execute> ...[/yellow]")
            return

        import whitecell.cli_enhanced as cli_mod

        mode = args[0].lower()
        if mode == "recommend":
            incident = " ".join(args[1:]).strip() or Prompt.ask("[cyan]Incident summary[/cyan]").strip()
            if not incident:
                console.print("[yellow]Incident summary is required.[/yellow]")
                return
            body = "\n".join(
                [
                    "- Contain impacted assets and isolate affected hosts.",
                    "- Collect volatile evidence and preserve logs.",
                    "- Rotate exposed credentials and tokens.",
                    "- Apply IOCs to detection and blocklists.",
                ]
            )
            cli_mod.governance.audit_event("soc", "respond.recommend", self.role, "completed", {"incident": incident[:80]})
            console.print(Panel(body, title="Response Recommendations", border_style="green"))
            return
        if mode != "execute":
            console.print("[yellow]Usage: respond <recommend|execute> ...[/yellow]")
            return
        if len(args) < 3:
            console.print("[yellow]Usage: respond execute <action> <target>[/yellow]")
            return

        action = args[1].strip().lower()
        target = " ".join(args[2:]).strip()
        action_key = f"respond.{action}"
        if action not in RESPONSE_ACTIONS:
            console.print(f"[red]Unsupported response action: {action}[/red]")
            cli_mod.governance.audit_event("soc", "respond.execute", self.role, "invalid-action", {"action": action, "target": target})
            return

        if cli_mod.governance.is_approval_required(action_key):
            approved = [req for req in cli_mod.governance.list_approvals(status="approved") if req.get("action") == action_key and req.get("target") == target]
            if approved:
                approval_id = approved[-1].get("id")
                cli_mod.governance.audit_event("soc", action_key, self.role, "executed", {"target": target, "approval_id": approval_id})
                console.print(Panel(f"Executed action '{action}' for target '{target}' using approval {approval_id}.", title="Response Execution", border_style="green"))
                return
            req = cli_mod.governance.request_approval(action_key, target, f"CLI response action on target '{target}'", self.role)
            console.print(f"[yellow]Approval required before execution.[/yellow] Request ID: [cyan]{req['id']}[/cyan]")
            console.print("[dim]Approve with: governance approvals approve <id>[/dim]")
            return

        result = RESPONSE_ACTIONS[action].format(target=target)
        cli_mod.governance.audit_event("soc", action_key, self.role, "executed", {"target": target})
        console.print(Panel(result, title="Response Execution", border_style="green"))

    def handle_governance_command(self, args: list) -> None:
        """Governance controls for role, policy, approvals, and status."""
        import whitecell.cli_enhanced as cli_mod

        if not args:
            args = ["status"]
        sub = args[0].lower()
        if sub == "status":
            pending = cli_mod.governance.list_approvals(status="pending")
            table = Table(title="Governance Status", show_header=True, header_style="bold magenta")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Role", cli_mod.get_governance_role())
            table.add_row("Pending Approvals", str(len(pending)))
            table.add_row("Approval Rules", ", ".join(cli_mod.get_approval_required_actions()) or "-")
            console.print(table)
            return
        if sub == "role":
            if not self._check_permission("governance.manage", "governance role"):
                return
            if len(args) < 2:
                console.print("[yellow]Usage: governance role <admin|analyst|viewer>[/yellow]")
                return
            role = args[1].lower()
            if cli_mod.set_governance_role(role):
                self.role = role
                cli_mod.governance.audit_event("governance", "role.set", self.role, "completed", {"role": role})
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
            rules = cli_mod.get_approval_required_actions()
            if action == "add":
                if action_name not in rules:
                    rules.append(action_name)
                cli_mod.set_approval_required_actions(rules)
                console.print(f"[green]Approval rule added: {action_name}[/green]")
                return
            if action == "remove":
                cli_mod.set_approval_required_actions([rule for rule in rules if rule != action_name])
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
                rows = cli_mod.governance.list_approvals()
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
                if cli_mod.governance.review_approval(args[2], action, self.role):
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
        remaining = args[idx + 1 :]
        if len(remaining) < 2:
            return alert_text, None, None
        return alert_text, remaining[0].strip().lower(), " ".join(remaining[1:]).strip()

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
        self.handle_investigate_command([str(threat_info["threat_type"])] if threat_info and threat_info.get("threat_type") else [alert_text])
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

    def handle_scan_command(self, args: list) -> None:
        """Handle website scanning commands."""
        if not args:
            console.print("[yellow]Usage: scan (website|allowlist) [options][/yellow]")
            return
        scan_type = args[0].lower()
        if scan_type == "website":
            self._handle_website_scan(args[1:])
        elif scan_type == "allowlist":
            self._handle_allowlist_command(args[1:])
        else:
            console.print(f"[yellow]Unknown scan type: {scan_type}[/yellow]")
            console.print("[yellow]Usage: scan (website|allowlist) [options][/yellow]")

    def _handle_website_scan(self, args: list) -> None:
        """Handle website security scanning."""
        if not args:
            console.print("[yellow]Usage: scan website <url> [--active][/yellow]")
            return
        import whitecell.cli_enhanced as cli_mod

        url = args[0]
        active_scan = "--active" in args
        if active_scan and not any(domain in url for domain in cli_mod.get_scan_allowlist()):
            console.print(f"[red]URL {url} is not in the active scan allowlist.[/red]")
            console.print("[yellow]Add it first with: scan allowlist add <domain>[/yellow]")
            return
        try:
            with console.status(f"[cyan]Scanning {url}{' (active)' if active_scan else ' (passive)'}...[/cyan]", spinner="dots"):
                results = cli_mod.website_scanner.scan_website(url, active=active_scan)
            if results:
                self._notify("ok", f"Scan completed for {url}")
                result_table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
                result_table.add_column("Test", style="cyan", width=20)
                result_table.add_column("Status", style="green", width=15)
                result_table.add_column("Details", width=40)
                for test_name, result in results.items():
                    status = "[green]PASS[/green]" if result.get("passed", True) else "[red]FAIL[/red]"
                    result_table.add_row(test_name, status, result.get("details", ""))
                console.print(result_table)
            else:
                console.print(f"[yellow]No results returned for {url}[/yellow]")
        except Exception as e:
            console.print(f"[red]Error scanning {url}: {e}[/red]")

    def _handle_allowlist_command(self, args: list) -> None:
        """Handle scan allowlist management commands."""
        if not args:
            console.print("[yellow]Usage: scan allowlist (show|add|remove) [domain][/yellow]")
            return
        action = args[0].lower()
        if action == "show":
            self._show_allowlist()
        elif action == "add" and len(args) > 1:
            self._add_to_allowlist(args[1])
        elif action == "remove" and len(args) > 1:
            self._remove_from_allowlist(args[1])
        else:
            console.print(f"[yellow]Unknown allowlist command: {action}[/yellow]")
            console.print("[yellow]Usage: scan allowlist (show|add|remove) [domain][/yellow]")

    def _show_allowlist(self) -> None:
        """Display the current scan allowlist."""
        import whitecell.cli_enhanced as cli_mod

        allowlist = cli_mod.get_scan_allowlist()
        if not allowlist:
            console.print("[yellow]No domains in scan allowlist[/yellow]")
            return
        console.print("[cyan]Scan Allowlist:[/cyan]")
        for domain in allowlist:
            console.print(f"  - {domain}")

    def _add_to_allowlist(self, domain: str) -> None:
        """Add a domain to the scan allowlist."""
        import whitecell.cli_enhanced as cli_mod

        current = cli_mod.get_scan_allowlist()
        if domain not in current:
            current.append(domain)
        if cli_mod.set_scan_allowlist(sorted(set(current))):
            self._notify("ok", f"Added {domain} to scan allowlist")
        else:
            self._notify("error", f"Failed to add {domain} to scan allowlist")

    def _remove_from_allowlist(self, domain: str) -> None:
        """Remove a domain from the scan allowlist."""
        import whitecell.cli_enhanced as cli_mod

        current = [item for item in cli_mod.get_scan_allowlist() if item != domain]
        if cli_mod.set_scan_allowlist(current):
            self._notify("ok", f"Removed {domain} from scan allowlist")
        else:
            self._notify("error", f"Failed to remove {domain} from scan allowlist")

    def handle_trace_command(self, args: list) -> None:
        """Network trace: identify attack source and generate attribution report."""
        try:
            from whitecell.attribution import SCAPY_AVAILABLE, run_attribution_scan
        except ImportError as e:
            console.print(f"[red]Attribution module not available: {e}[/red]")
            console.print("[yellow]Install scapy to enable network tracing: pip install scapy[/yellow]")
            return

        if not SCAPY_AVAILABLE:
            console.print("[red]Scapy is not installed. Network tracing requires scapy.[/red]")
            console.print("[yellow]Install scapy to enable network tracing: pip install scapy[/yellow]")
            return

        interface = None
        duration = 30
        index = 0
        while index < len(args):
            if args[index] == "--interface" and index + 1 < len(args):
                interface = args[index + 1]
                index += 2
            elif args[index] == "--duration" and index + 1 < len(args):
                try:
                    duration = int(args[index + 1])
                    if duration <= 0:
                        raise ValueError
                    index += 2
                except ValueError:
                    console.print("[red]Duration must be a positive integer[/red]")
                    return
            else:
                console.print(f"[yellow]Unknown argument: {args[index]}[/yellow]")
                return

        console.print(f"[cyan]Starting network trace on {interface or 'default interface'} for {duration}s...[/cyan]")
        console.print("[dim]This may require administrator/root privileges[/dim]")

        import whitecell.cli_enhanced as cli_mod

        try:
            with console.status("[cyan]Performing network trace and attribution analysis...", spinner="dots"):
                report = run_attribution_scan(interface=interface, timeout=duration)
            console.print("\n[bold green]Attribution scan completed![/bold green]")
            console.print(report)
            cli_mod.governance.audit_event("attribution", "trace", self.role, "completed", {"duration": duration, "interface": interface})
        except PermissionError:
            console.print("[red]Permission denied. Network tracing requires administrator/root privileges.[/red]")
            cli_mod.governance.audit_event("attribution", "trace", self.role, "failed", {"error": "permission_denied", "duration": duration})
        except Exception as e:
            console.print(f"[red]Error during network trace: {e}[/red]")
            cli_mod.governance.audit_event("attribution", "trace", self.role, "failed", {"error": str(e), "duration": duration})
