"""
Task Assignment Examples for White Cell Agents

This file demonstrates how to assign tasks to agents using the White Cell system.
Tasks allow you to give agents specific work beyond periodic security checks.

Author: White Cell Project
"""

from whitecell.agent import agent_manager, Task
import time


def example_1_basic_task_assignment():
    """Example 1: Assign a basic security check task."""
    print("=" * 60)
    print("Example 1: Basic Task Assignment")
    print("=" * 60)
    
    # Create an agent
    agent = agent_manager.create_agent("security-monitor-1", check_interval=10)
    agent.start()
    print(f"Started agent: {agent.agent_id}\n")
    
    # Create a task to check for running suspicious processes
    task = agent_manager.create_task(
        task_type="check",
        description="Monitor running processes for threats",
        parameters={"check_name": "process"}
    )
    
    # Assign task to agent
    assigned = agent_manager.assign_task_to_agent(agent.agent_id, task)
    print(f"Task {task.task_id} assigned: {assigned}")
    print(f"Task Status: {task.status}\n")
    
    # Wait for execution
    time.sleep(2)
    
    # Check results
    results = agent_manager.get_agent_completed_tasks(agent.agent_id)
    print(f"Completed tasks: {len(results)}")
    
    if results:
        for result in results:
            print(f"  - Task ID: {result['task_id']}")
            print(f"    Status: {result['status']}")
            print(f"    Type: {result['task_type']}")
            if result['error']:
                print(f"    Error: {result['error']}")
    
    agent.stop()


def example_2_multiple_agents():
    """Example 2: Assign same task to multiple agents."""
    print("\n" + "=" * 60)
    print("Example 2: Broadcast Task to All Agents")
    print("=" * 60)
    
    # Create multiple agents
    agents = []
    for i in range(3):
        agent = agent_manager.create_agent(f"agent-{i}", check_interval=10)
        agent.start()
        agents.append(agent)
    
    print(f"Created {len(agents)} agents\n")
    
    # Create task
    task = agent_manager.create_task(
        task_type="scan",
        description="Perform comprehensive threat scan",
        parameters={"threat_data": "unauthorized_access_attempt"}
    )
    
    # Assign to all running agents
    count = agent_manager.assign_task_to_all_agents(task)
    print(f"Task assigned to {count} agents\n")
    
    # Wait for execution
    time.sleep(2)
    
    # Get all results
    all_results = agent_manager.get_all_completed_tasks()
    for agent_id, tasks in all_results.items():
        print(f"{agent_id}: {len(tasks)} completed tasks")
    
    # Cleanup
    for agent in agents:
        agent.stop()


def example_3_threat_analysis():
    """Example 3: Use AI-powered threat analysis task."""
    print("\n" + "=" * 60)
    print("Example 3: AI-Powered Threat Analysis")
    print("=" * 60)
    
    agent = agent_manager.create_agent("ai-analyzer", check_interval=10)
    agent.start()
    print(f"Started agent: {agent.agent_id}\n")
    
    # Create threat analysis task
    task = agent_manager.create_task(
        task_type="threat_analysis",
        description="Analyze suspicious network traffic",
        parameters={
            "threat_description": "Suspicious outbound connection on port 4444 to 192.168.1.100",
            "indicators": ["unusual_port", "external_ip", "anomalous_traffic"]
        }
    )
    
    # Assign task
    agent_manager.assign_task_to_agent(agent.agent_id, task)
    print(f"Assigned threat analysis task: {task.task_id}\n")
    
    # Wait for execution
    time.sleep(2)
    
    # Get results
    results = agent_manager.get_agent_completed_tasks(agent.agent_id)
    if results:
        result = results[-1]
        print(f"Analysis Results:")
        print(f"  Status: {result['status']}")
        print(f"  Description: {result['description']}")
        if result['result']:
            print(f"  Result: {result['result']}")
    
    agent.stop()


def example_4_remediation():
    """Example 4: Assign remediation task."""
    print("\n" + "=" * 60)
    print("Example 4: Threat Remediation")
    print("=" * 60)
    
    agent = agent_manager.create_agent("remediation-specialist", check_interval=10)
    agent.start()
    print(f"Started agent: {agent.agent_id}\n")
    
    # Create remediation task
    task = agent_manager.create_task(
        task_type="remediate",
        description="Remediate detected ransomware",
        parameters={"threat_type": "ransomware"}
    )
    
    # Assign task
    agent_manager.assign_task_to_agent(agent.agent_id, task)
    print(f"Assigned remediation task: {task.task_id}\n")
    
    # Wait for execution
    time.sleep(2)
    
    # Get results
    results = agent_manager.get_agent_completed_tasks(agent.agent_id)
    if results:
        result = results[-1]
        print(f"Remediation Status:")
        print(f"  Status: {result['status']}")
        if result['result']:
            for key, value in result['result'].items():
                print(f"  {key}: {value}")
    
    agent.stop()


def example_5_custom_task():
    """Example 5: Create and assign custom tasks."""
    print("\n" + "=" * 60)
    print("Example 5: Custom Tasks")
    print("=" * 60)
    
    agent = agent_manager.create_agent("custom-task-agent", check_interval=10)
    agent.start()
    print(f"Started agent: {agent.agent_id}\n")
    
    # Create custom task
    task = agent_manager.create_task(
        task_type="custom",
        description="Generate security report",
        parameters={
            "action": "generate_report",
            "format": "json",
            "include": ["threats", "statistics", "recommendations"]
        }
    )
    
    # Assign task
    agent_manager.assign_task_to_agent(agent.agent_id, task)
    print(f"Assigned custom task: {task.task_id}\n")
    
    # Wait for execution
    time.sleep(2)
    
    # Get results
    results = agent_manager.get_agent_completed_tasks(agent.agent_id)
    if results:
        result = results[-1]
        print(f"Custom Task Results:")
        print(f"  Status: {result['status']}")
        print(f"  Description: {result['description']}")
        print(f"  Parameters: {result['parameters']}")
    
    agent.stop()


def example_6_cli_usage():
    """
    Example 6: Using tasks from the CLI.
    
    Interactive commands:
    
    1. Start the CLI:
       python main.py
    
    2. Deploy an agent:
       agent deploy security-monitor
    
    3. Assign a task:
       task assign
       - Select agent
       - Select task type (check, scan, threat_analysis, remediate, custom)
       - Enter parameters
    
    4. View task status:
       task list
    
    5. View detailed results:
       task results security-monitor
    """
    print("\n" + "=" * 60)
    print("Example 6: CLI Usage Instructions")
    print("=" * 60)
    print(example_6_cli_usage.__doc__)


# Task Types Reference
"""
Available Task Types:

1. check
   - Run a specific security check
   - Parameters: {"check_name": "process|port|file|logs|firewall|malware"}
   - Returns: Threats detected, check results

2. scan
   - Comprehensive threat scan
   - Parameters: {"threat_data": "string to scan"}
   - Returns: Threat information, risk score, threat type

3. threat_analysis
   - Analyze threat with AI (if GROQ configured)
   - Parameters: {
       "threat_description": "...",
       "indicators": ["indicator1", "indicator2"]
     }
   - Returns: AI analysis, threat level, recommendations

4. remediate
   - Execute threat remediation
   - Parameters: {"threat_type": "ransomware|malware|..."}
   - Returns: Action taken, success status

5. custom
   - User-defined custom task
   - Parameters: Flexible, define as needed
   - Returns: Custom results based on action
"""


def run_all_examples():
    """Run all examples."""
    try:
        example_1_basic_task_assignment()
        example_2_multiple_agents()
        example_3_threat_analysis()
        example_4_remediation()
        example_5_custom_task()
        example_6_cli_usage()
        
        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        example_num = sys.argv[1]
        locals()[f"example_{example_num}"]()
    else:
        run_all_examples()
