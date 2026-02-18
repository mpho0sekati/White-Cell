"""
White Cell Agent System Demo and Test

Demonstrates the autonomous agent system with real-time threat monitoring and prevention.
Shows: Agent deployment, threat detection, prevention, and AI-powered decision making.

Author: White Cell Project
"""

import time
import json
from whitecell.agent import agent_manager, Agent
from whitecell.config import load_config, set_config_value, get_config_value
from whitecell.security_checks import run_all_checks, get_check_by_name
from whitecell.groq_client import groq_client
from whitecell.detection import detect_threat


def print_section(title: str):
    """Print a formatted section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def demo_1_agent_deployment():
    """Demo 1: Deploy autonomous agents."""
    print_section("DEMO 1: AUTONOMOUS AGENT DEPLOYMENT")
    
    print("Step 1: Creating agent 'production-server'")
    agent1 = agent_manager.create_agent("production-server", check_interval=30)
    print(f"✓ Agent created: {agent1.agent_id}")
    
    print("\nStep 2: Registering threat detection callback")
    def on_threat(threat_data):
        print(f"  🚨 THREAT DETECTED: {threat_data.get('source')}")
        print(f"     Threat: {threat_data.get('threat')}")
        if threat_data.get('prevented'):
            print(f"     ✓ PREVENTED: {threat_data.get('prevented_by')}")
    
    agent1.register_threat_callback(on_threat)
    print("✓ Callback registered")
    
    print("\nStep 3: Starting agent in background")
    if agent1.start():
        print("✓ Agent started successfully")
        print(f"  Check interval: {agent1.check_interval} seconds")
    
    return agent1


def demo_2_security_checks():
    """Demo 2: Run security checks."""
    print_section("DEMO 2: LOCAL SECURITY CHECKS")
    
    print("Running all security checks on the system...")
    checks = run_all_checks()
    
    total_threats = 0
    for check in checks:
        status = "✓" if check.get("status") == "success" else "✗"
        threats = check.get("threats", [])
        threat_count = len(threats)
        total_threats += threat_count
        
        print(f"\n{status} {check.get('check')}")
        print(f"   Threats found: {threat_count}")
        
        if threats:
            for threat in threats[:3]:  # Show first 3
                print(f"   - {threat}")
            if len(threats) > 3:
                print(f"   ... and {len(threats) - 3} more")
    
    print(f"\nTotal threats detected: {total_threats}")
    return checks


def demo_3_threat_detection():
    """Demo 3: Threat detection from user input."""
    print_section("DEMO 3: USER INPUT THREAT DETECTION")
    
    test_inputs = [
        "We detected ransomware on the file server",
        "Possible DDoS attack detected - high packet volume",
        "Multiple failed login attempts from China",
        "Unknown process consuming 95% CPU found",
    ]
    
    print("Analyzing user inputs for threats...\n")
    
    for user_input in test_inputs:
        print(f"Input: {user_input}")
        threat = detect_threat(user_input)
        if threat:
            print(f"✓ Threat detected: {threat[0]}")
        else:
            print("✗ No threat detected")
        print()


def demo_4_agent_status():
    """Demo 4: Check agent status and statistics."""
    print_section("DEMO 4: AGENT STATUS & STATISTICS")
    
    print("Waiting for agent to perform checks...")
    time.sleep(3)
    
    # Get status
    status = agent_manager.get_agent_status("production-server")
    stats = agent_manager.get_global_statistics()
    
    print("Agent Status:")
    print(f"  Agent ID: {status['agent_id']}")
    print(f"  Running: {status['running']}")
    print(f"  Checks performed: {status['checks_performed']}")
    print(f"  Threats detected: {status['threats_detected']}")
    print(f"  Threats prevented: {status['prevented_count']}")
    
    print("\nGlobal Statistics:")
    print(f"  Total agents: {stats['total_agents']}")
    print(f"  Running agents: {stats['running_agents']}")
    print(f"  Total checks: {stats['total_checks_performed']}")
    print(f"  Total threats detected: {stats['total_threats_detected']}")
    print(f"  Total threats prevented: {stats['total_prevented']}")


def demo_5_simulated_threats():
    """Demo 5: Simulate threat detection in agent."""
    print_section("DEMO 5: SIMULATED THREAT DETECTION & PREVENTION")
    
    print("Simulating detected threats through agent...\n")
    
    simulated_threats = [
        ("Ransomware detected in system memory", "malware_scan"),
        ("Unauthorized port 4444 open on server", "port_monitoring"),
        ("Suspicious process cmd.exe running", "process_monitoring"),
    ]
    
    # Manually trigger threat handling
    for threat_text, source in simulated_threats:
        print(f"Threat from {source}:")
        print(f"  {threat_text}")
        
        threat_type = detect_threat(threat_text)
        if threat_type:
            print(f"  Type: {threat_type[0]}")
        print()


def demo_6_groq_integration():
    """Demo 6: GROQ API integration status."""
    print_section("DEMO 6: GROQ API INTEGRATION STATUS")
    
    is_configured = groq_client.is_configured()
    
    if is_configured:
        print("✓ GROQ API is configured and ready!")
        print("\nAI-powered features enabled:")
        print("  - Threat analysis and recommendations")
        print("  - Intelligent prevention decisions")
        print("  - Contextual threat explanations")
    else:
        print("✗ GROQ API is not configured")
        print("\nTo enable AI-powered threat prevention:")
        print("  1. Get your API key from: https://console.groq.com/keys")
        print("  2. Run: 'agent configure' in White Cell CLI")
        print("  3. Enter your API key when prompted")
        print("\nWithout Groq, agents will use built-in prevention logic")


def demo_7_agent_management():
    """Demo 7: Multiple agent management."""
    print_section("DEMO 7: MULTIPLE AGENT MANAGEMENT")
    
    print("Creating additional agents...\n")
    
    agent2 = agent_manager.create_agent("web-server", check_interval=45)
    agent3 = agent_manager.create_agent("database-server", check_interval=60)
    
    print("✓ Agent 'web-server' created")
    print("✓ Agent 'database-server' created")
    
    print("\nStarting all agents...")
    agent_manager.start_agent("web-server")
    agent_manager.start_agent("database-server")
    
    print("✓ All agents started")
    
    print("\nGlobal statistics:")
    stats = agent_manager.get_global_statistics()
    print(f"  Total agents: {stats['total_agents']}")
    print(f"  Running agents: {stats['running_agents']}")
    
    print("\nAll agent status:")
    all_status = agent_manager.get_all_status()
    for agent_id, status in all_status.items():
        running_text = "Running" if status['running'] else "Stopped"
        print(f"  {agent_id}: {running_text} (Checks: {status['checks_performed']})")


def demo_8_shutdown():
    """Demo 8: Graceful shutdown of all agents."""
    print_section("DEMO 8: AGENT SHUTDOWN & DATA EXPORT")
    
    print("Stopping all agents...\n")
    
    stopped = agent_manager.stop_all_agents()
    print(f"✓ Stopped {stopped} agents")
    
    print("\nAgent statistics before shutdown:")
    stats = agent_manager.get_global_statistics()
    print(f"  Total checks performed: {stats['total_checks_performed']}")
    print(f"  Total threats detected: {stats['total_threats_detected']}")
    print(f"  Total threats prevented: {stats['total_prevented']}")
    
    print("\nExporting agent data to JSON...")
    try:
        export_path = "logs/agent_export.json"
        if agent_manager.export_all_data(export_path):
            print(f"✓ Data exported to {export_path}")
        else:
            print("✗ Export failed")
    except Exception as e:
        print(f"Note: Export attempted (may require elevated privileges)")


def run_full_demo():
    """Run the complete agent system demonstration."""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  WHITE CELL - AUTONOMOUS AGENT SYSTEM DEMONSTRATION".center(68) + "║")
    print("║" + "  Real-time Security Monitoring & Prevention".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    print("\n[INFO] This demo showcases the complete agent-based security system")
    print("[INFO] Agents run autonomously to detect and prevent threats\n")
    
    # Run demos
    try:
        print("[1/8] Deploying autonomous agents...")
        agent1 = demo_1_agent_deployment()
        
        print("\n[2/8] Running security checks...")
        checks = demo_2_security_checks()
        
        print("\n[3/8] Testing threat detection...")
        demo_3_threat_detection()
        
        print("\n[4/8] Checking agent status...")
        demo_4_agent_status()
        
        print("\n[5/8] Simulating threat scenarios...")
        demo_5_simulated_threats()
        
        print("\n[6/8] Checking GROQ API integration...")
        demo_6_groq_integration()
        
        print("\n[7/8] Managing multiple agents...")
        demo_7_agent_management()
        
        print("\n[8/8] Shutting down gracefully...")
        demo_8_shutdown()
        
        print_section("DEMONSTRATION COMPLETE")
        print("""
✓ Agent System Features Demonstrated:
  • Autonomous background threat monitoring
  • Real-time security checks (process, port, file, logs, firewall)
  • Threat detection with keyword matching
  • Risk scoring and threat prevention
  • Multi-agent orchestration
  • GROQ API integration path
  • Data export and reporting

Next Steps:
  1. Run 'python main.py' to start the interactive CLI
  2. Use 'agent deploy <name>' to create custom agents
  3. Use 'agent configure' to add your GROQ API key
  4. Use 'agent status' to monitor running agents
  5. Use 'agent threats <name>' to view detected threats

Documentation:
  See AGENT_SYSTEM.md for detailed usage and architecture
        """)
        
    except Exception as e:
        print(f"\n✗ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_full_demo()
