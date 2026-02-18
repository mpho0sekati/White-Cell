"""
White Cell Command Mode

This module handles the display and management of Command Mode,
which is activated when threats are detected. Provides detailed
action plans and mitigation recommendations.

Author: White Cell Project
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def display_command_mode_activation(threat_info: dict, risk_info: dict) -> str:
    """
    Display threat detection and risk information when entering Command Mode.

    Args:
        threat_info: Dictionary with threat detection details
        risk_info: Dictionary with risk scoring details

    Returns:
        Formatted string for display
    """
    threat_type = threat_info.get("threat_type", "unknown")
    keywords = threat_info.get("keywords_matched", "")
    risk_score = risk_info.get("risk_score", 0)
    risk_level = risk_info.get("risk_level", "unknown")

    color = "red" if risk_level == "high" else "yellow" if risk_level == "medium" else "green"

    output = f"""
[bold red]━━━━━━━━━━━━━━━━━ THREAT DETECTED ━━━━━━━━━━━━━━━━━[/bold red]
[bold #FF6B6B]Threat Type:[/bold #FF6B6B] {threat_type.upper()}
[bold #FF6B6B]Trigger:[/bold #FF6B6B] "{keywords}"
[bold #FF6B6B]Risk Level:[/bold #FF6B6B] [{color}]{risk_level.upper()}[/{color}] ({risk_score}/100)
[bold red]━━━━━━━━━━━━━━━━━ COMMAND MODE ACTIVE ━━━━━━━━━━━━━━━━━[/bold red]
"""
    return output.strip()


def display_suggested_actions(risk_level: str) -> str:
    """
    Display suggested actions based on risk level.

    Args:
        risk_level: One of 'low', 'medium', 'high'

    Returns:
        Formatted string with suggested actions
    """
    actions = {
        "low": [
            "• Monitor system logs for suspicious activity",
            "• Verify the legitimacy of the alert",
            "• Document the incident",
        ],
        "medium": [
            "• Enable enhanced logging and monitoring",
            "• Prepare incident response procedures",
            "• Alert security team",
            "• Isolate potentially affected systems if necessary",
        ],
        "high": [
            "• IMMEDIATELY isolate affected systems from the network",
            "• Activate incident response team",
            "• Contact cybersecurity experts",
            "• Begin forensic data collection",
            "• Notify management and legal if data breach suspected",
            "• Preserve evidence for investigation",
        ],
    }

    suggested = actions.get(risk_level, actions["low"])
    output = "[bold yellow]Suggested Actions:[/bold yellow]\n"
    for action in suggested:
        output += f"{action}\n"

    return output.strip()


def create_risk_table(risk_info: dict) -> Table:
    """
    Create a Rich Table displaying risk details.

    Args:
        risk_info: Dictionary with risk scoring details

    Returns:
        Rich Table object
    """
    table = Table(title="Risk Assessment", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    risk_level = risk_info.get("risk_level", "unknown")
    color = "red" if risk_level == "high" else "yellow" if risk_level == "medium" else "green"

    table.add_row("Risk Score", f"[{color}]{risk_info.get('risk_score', 0)}/100[/{color}]")
    table.add_row("Risk Level", f"[{color}]{risk_level.upper()}[/{color}]")
    table.add_row("Financial Loss Est.", f"${risk_info.get('estimated_financial_loss', 0):,}")
    table.add_row("POPIA Exposure", "[red]YES[/red]" if risk_info.get("popia_exposure", False) else "[green]NO[/green]")

    return table


def display_mitigation_plan(threat_type: str, mitigation_steps: list[str]) -> str:
    """
    Display detailed mitigation plan for the detected threat.

    Args:
        threat_type: Type of threat
        mitigation_steps: List of recommended mitigation steps

    Returns:
        Formatted string with mitigation plan
    """
    output = f"\n[bold blue]Mitigation Plan for {threat_type.upper()}:[/bold blue]\n"
    
    for i, step in enumerate(mitigation_steps, 1):
        output += f"[bold cyan]{i}.[/bold cyan] {step}\n"

    return output.strip()
