"""White Cell enhanced CLI entry point and coordinator."""

import logging
from typing import Optional

from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from whitecell.agent import agent_manager
from whitecell.command_mode import create_risk_table
from whitecell.config import (
    get_approval_required_actions,
    get_governance_role,
    get_groq_api_key,
    get_scan_allowlist,
    load_config,
    set_approval_required_actions,
    set_governance_role,
    set_groq_api_key,
    set_scan_allowlist,
    validate_groq_api_key,
)
from whitecell.crew import crew_manager
from whitecell.engine import get_session_logs, handle_input, initialize_logging, parse_command
from whitecell.groq_client import groq_client
from whitecell.self_improve import self_improver
from whitecell.state import global_state
from whitecell.website_scanner import website_scanner
from whitecell import governance
from whitecell.cli_agents import CLIAgentsMixin
from whitecell.cli_commands import CLICommandsMixin
from whitecell.cli_shared import CONTEXT_SUGGESTIONS, STATUS_LABELS, STATUS_STYLES, console
from whitecell.cli_views import CLIViewsMixin

try:
    from whitecell.logging_config import get_logger
except ImportError:
    def get_logger(name: str):
        return logging.getLogger(name)

try:
    from whitecell.constants import COMMAND_ALIASES
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

logger = get_logger(__name__)


class EnhancedWhiteCellCLI(CLIViewsMixin, CLICommandsMixin, CLIAgentsMixin):
    """Enhanced interactive CLI with split modules and command registry."""

    def __init__(self) -> None:
        self.state = global_state
        self.session_threats = []
        self.command_history = []
        self.show_tips = True
        self._menu_hint_shown = False
        self.role = get_governance_role()
        initialize_logging()

    def expand_alias(self, command: str) -> str:
        """Expand command aliases."""
        return COMMAND_ALIASES.get(command, command)

    def _section_header(self, title: str, subtitle: Optional[str] = None) -> None:
        """Render consistent section header style."""
        body = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            body += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(body, border_style="cyan", expand=False))

    def _notify(self, level: str, message: str) -> None:
        """Render a standardized status message."""
        color = STATUS_STYLES.get(level, "white")
        label = STATUS_LABELS.get(level, "[INFO]")
        console.print(f"[{color}]{label} {message}[/{color}]")

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
        if threat_count > 0:
            return f"[bold yellow]WHITE CELL ({threat_count} threats) >[/bold yellow] "
        return "[bold cyan]WHITE CELL >[/bold cyan] "

    def show_suggestion(self, context: str) -> None:
        """Show context-aware suggestion."""
        if context in CONTEXT_SUGGESTIONS and self.show_tips:
            console.print(f"[dim]Tip: {CONTEXT_SUGGESTIONS[context]}[/dim]")

    def process_threat_input(self, user_input: str) -> None:
        """Process threat detection input with visual feedback."""
        if not user_input.strip():
            return
        import time

        with console.status("[cyan]Analyzing input...", spinner="dots"):
            time.sleep(0.3)
            response = handle_input(user_input)
        console.print(response)
        self.session_threats = get_session_logs()
        self.show_suggestion("threat")
        if self.state.command_mode:
            try:
                risk_table = create_risk_table(self.state.command_mode_data)
                console.print(risk_table)
            except Exception:
                pass

    def start(self) -> None:
        """Start the enhanced interactive shell."""
        self.state.session_active = True
        self.display_banner()
        try:
            while self.state.session_active:
                try:
                    user_input = Prompt.ask(self.get_prompt()).strip()
                    if not user_input:
                        continue
                    self.command_history.append(user_input)

                    if user_input.lower() in ["?", "menu"]:
                        choice = self.display_quick_menu()
                        if choice and choice != "0":
                            self.handle_menu_selection(choice)
                        continue

                    command, args = parse_command(user_input)
                    command = self.expand_alias(command)
                    if command in self.get_command_registry():
                        if self.handle_command(command, args) is False:
                            break
                        continue

                    self.process_threat_input(user_input)
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid input or parameter: {e}")
                    console.print(f"[red]Error:[/red] Invalid input - {e}")
                except KeyError as e:
                    logger.error(f"Configuration error: {e}")
                    console.print(f"[red]Configuration error:[/red] Missing setting {e}")
                except Exception as e:
                    logger.error(f"Unexpected error in CLI loop: {e}", exc_info=True)
                    console.print(f"[red]Error:[/red] {e}")
                    console.print("[yellow]Continuing... Type 'help' for commands[/yellow]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold green]Exiting White Cell. Stay secure![/bold green]")
            self.state.session_active = False
        except Exception as e:
            logger.critical(f"Critical error in CLI: {e}", exc_info=True)
            console.print(f"\n[bold red]Critical error:[/bold red] {e}")
            console.print("[yellow]Exiting....[/yellow]")
            self.state.session_active = False


def main() -> None:
    """Entry point for enhanced CLI."""
    cli = EnhancedWhiteCellCLI()
    cli.start()


if __name__ == "__main__":
    main()
