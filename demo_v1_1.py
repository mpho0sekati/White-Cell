#!/usr/bin/env python3
"""
White Cell V1.1 - Feature Demonstration Script

This script demonstrates the new V1.1 features:
1. Threat detection
2. Risk scoring
3. Command Mode activation
4. Threat logging
5. Rich formatting

Author: White Cell Project
"""

import sys
import json
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from whitecell.detection import detect_threat, get_threat_context
from whitecell.risk import calculate_risk, format_risk_summary, get_risk_color
from whitecell.command_mode import display_command_mode_activation, display_suggested_actions, create_risk_table
from whitecell.engine import handle_input, initialize_logging, get_session_logs

console = Console()


def demo_header(title: str) -> None:
    """Display a demo section header."""
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold yellow]{title}[/bold yellow]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]\n")


def demo_1_threat_detection():
    """Demonstrate threat detection capabilities."""
    demo_header("DEMO 1: Threat Detection")

    test_cases = [
        ("We have a ransomware attack!", "ransomware"),
        ("Phishing email detected", "phishing"),
        ("DDoS attack in progress", "denial_of_service"),
        ("SQL injection attempt blocked", "exploit"),
        ("How do I secure my password?", None),
    ]

    for user_input, expected in test_cases:
        console.print(f"[cyan]Input:[/cyan] {user_input}")
        threat = detect_threat(user_input)
        
        if threat:
            console.print(f"[green]Threat Detected:[/green] {threat['threat_type']}")
            console.print(f"  - Keyword: {threat['keywords_matched']}")
            console.print(f"  - Severity: {threat['severity']}/10")
        else:
            console.print("[green]No threat detected.[/green]")
        
        console.print()


def demo_2_risk_scoring():
    """Demonstrate risk scoring system."""
    demo_header("DEMO 2: Risk Scoring")

    threats_to_score = [
        "ransomware",
        "phishing",
        "data breach",
        "lateral movement",
        "ddos attack",
    ]

    for threat_name in threats_to_score:
        # Create a mock threat
        threat = detect_threat(threat_name)
        if threat:
            threat.update(get_threat_context(threat['threat_type']))
            risk_info = calculate_risk(threat)
            
            console.print(f"[bold]{threat['threat_type'].upper()}[/bold]")
            console.print(f"  Risk Score: {risk_info['risk_score']}/100")
            
            color = get_risk_color(risk_info['risk_level'])
            console.print(f"  Risk Level: [{color}]{risk_info['risk_level'].upper()}[/{color}]")
            console.print(f"  Financial Loss: ${risk_info['estimated_financial_loss']:,}")
            console.print(f"  POPIA Exposure: {'YES' if risk_info['popia_exposure'] else 'NO'}")
            console.print()


def demo_3_command_mode():
    """Demonstrate Command Mode display."""
    demo_header("DEMO 3: Command Mode Display")

    # Simulate a high-risk threat
    threat = {
        'threat_type': 'ransomware',
        'keywords_matched': 'ransomware',
        'severity': 9,
    }
    threat.update(get_threat_context(threat['threat_type']))
    risk_info = calculate_risk(threat)

    # Display Command Mode activation
    console.print(display_command_mode_activation(threat, risk_info))
    console.print()

    # Display suggested actions
    console.print(display_suggested_actions(risk_info['risk_level']))
    console.print()

    # Display risk table
    table = create_risk_table(risk_info)
    console.print(table)


def demo_4_rich_formatting():
    """Demonstrate Rich formatting capabilities."""
    demo_header("DEMO 4: Rich Formatting")

    # Risk levels demonstration
    risk_levels_demo = [
        ("low", 20, "$1,000"),
        ("medium", 55, "$5,000"),
        ("high", 95, "$50,000"),
    ]

    for level, score, loss in risk_levels_demo:
        color = get_risk_color(level)
        risk_table = Table(title=f"Risk Level: {level.upper()}", show_header=True, header_style="bold magenta")
        risk_table.add_column("Metric", style="cyan")
        risk_table.add_column("Value", style="green")
        
        risk_table.add_row("Risk Score", f"[{color}]{score}/100[/{color}]")
        risk_table.add_row("Risk Level", f"[{color}]{level.upper()}[/{color}]")
        risk_table.add_row("Financial Loss", loss)
        
        console.print(risk_table)
        console.print()


def demo_5_engine_integration():
    """Demonstrate engine integration."""
    demo_header("DEMO 5: Engine Integration (Logging)")

    initialize_logging()

    # Simulate threat detection through engine
    test_inputs = [
        "We detected a malware infection on 3 servers",
        "Possible data breach - unauthorized access detected",
    ]

    for user_input in test_inputs:
        console.print(f"[cyan]Processing:[/cyan] {user_input}\n")
        response = handle_input(user_input)
        # The response would be displayed as Rich-formatted text
        console.print("[green]Threat logged successfully[/green]\n")

    # Show logs
    logs = get_session_logs()
    console.print(f"[bold]Total threats logged:[/bold] {len(logs)}\n")

    if logs:
        logs_table = Table(show_header=True, header_style="bold magenta")
        logs_table.add_column("Threat Type", style="yellow")
        logs_table.add_column("Risk Score", style="red")
        logs_table.add_column("Risk Level", style="red")
        logs_table.add_column("POPIA", style="red")

        for log in logs[-5:]:
            logs_table.add_row(
                log['threat_type'],
                str(log['risk_score']),
                log['risk_level'],
                "[red]YES[/red]" if log['popia_exposure'] else "[green]NO[/green]"
            )

        console.print(logs_table)


def main():
    """Run all demonstrations."""
    console.print("\n")
    console.print("[bold green]" + "="*70 + "[/bold green]")
    console.print("[bold yellow]      WHITE CELL V1.1 - FEATURE DEMONSTRATION[/bold yellow]")
    console.print("[bold green]" + "="*70 + "[/bold green]")

    try:
        demo_1_threat_detection()
        demo_2_risk_scoring()
        demo_3_command_mode()
        demo_4_rich_formatting()
        demo_5_engine_integration()

        console.print("\n[bold green]" + "="*70 + "[/bold green]")
        console.print("[bold green]All V1.1 features demonstrated successfully![/bold green]")
        console.print("[bold green]" + "="*70 + "[/bold green]\n")

    except Exception as e:
        console.print(f"[red]Error during demonstration: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
