"""
White Cell Agent

This module implements autonomous agents that run security checks and prevent threats.
Agents can be deployed on any machine for real-time security monitoring.

Author: White Cell Project
"""

import threading
import time
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from enum import Enum
from queue import Queue

from whitecell.detection import detect_threat
from whitecell.risk import calculate_risk, get_threat_mitigations
from whitecell.security_checks import run_all_checks, get_check_by_name
from whitecell.config import load_config, get_config_value
from whitecell.groq_client import groq_client
from whitecell.agent_learning import agent_learning


class TaskStatus(str, Enum):
    """Task status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Task:
    """
    Represents a task to be executed by an agent.
    """

    def __init__(
        self,
        task_id: str,
        task_type: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a task.

        Args:
            task_id: Unique task identifier
            task_type: Type of task (check, scan, threat_analysis, remediate, custom)
            description: Human-readable description
            parameters: Task-specific parameters
        """
        self.task_id = task_id
        self.task_type = task_type
        self.description = description
        self.parameters = parameters or {}
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.error = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary."""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "description": self.description,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error
        }


class Agent:
    """
    Autonomous security agent that monitors and prevents threats.
    """

    def __init__(self, agent_id: str = "default", check_interval: int = 60):
        """
        Initialize an agent.

        Args:
            agent_id: Unique identifier for the agent
            check_interval: Seconds between checks
        """
        self.agent_id = agent_id
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.threats_detected = []
        self.checks_performed = 0
        self.start_time = None
        self.on_threat_detected = None
        self.on_prevention_action = None
        
        # Task management
        self.task_queue = Queue()
        self.tasks_completed = []
        self.on_task_completed = None

    def start(self) -> bool:
        """
        Start the agent in a background thread.

        Returns:
            True if started successfully
        """
        if self.running:
            return False

        self.running = True
        self.start_time = datetime.now()
        self.threats_detected = []
        self.checks_performed = 0

        self.thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"WhiteCell-Agent-{self.agent_id}"
        )
        self.thread.start()
        return True

    def stop(self) -> bool:
        """
        Stop the agent.

        Returns:
            True if stopped successfully
        """
        if not self.running:
            return False

        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        return True

    def _run_loop(self):
        """Main agent execution loop."""
        while self.running:
            try:
                # Process any pending tasks first
                self._process_task_queue()
                
                # Then perform periodic security checks
                self._perform_checks()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"Agent {self.agent_id} error: {e}")

    def _process_task_queue(self):
        """Process pending tasks from the queue."""
        while not self.task_queue.empty():
            try:
                task = self.task_queue.get_nowait()
                self._execute_task(task)
            except Exception as e:
                print(f"Error processing task queue: {e}")

    def _execute_task(self, task: Task) -> None:
        """
        Execute a task.

        Args:
            task: Task to execute
        """
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()

        try:
            # Route to appropriate task handler
            if task.task_type == "check":
                result = self._task_run_check(task)
            elif task.task_type == "scan":
                result = self._task_scan(task)
            elif task.task_type == "threat_analysis":
                result = self._task_analyze_threat(task)
            elif task.task_type == "remediate":
                result = self._task_remediate(task)
            elif task.task_type == "custom":
                result = self._task_custom(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

            task.result = result
            task.status = TaskStatus.COMPLETED
        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED
            print(f"Task {task.task_id} failed: {e}")
        finally:
            task.completed_at = datetime.now()
            self.tasks_completed.append(task)

            # Call callback if registered
            if self.on_task_completed:
                self.on_task_completed(task)

            # Record interaction for learning system
            try:
                agent_learning.record_interaction(
                    agent_id=self.agent_id,
                    task_type=task.task_type,
                    task_description=task.description,
                    outcome=str(task.result or task.error or "No output"),
                    success=task.status == TaskStatus.COMPLETED,
                    threat_type=task.parameters.get("threat_type"),
                    metadata={"task_id": task.task_id, "parameters": task.parameters}
                )
            except Exception as e:
                pass  # Don't fail if learning capture fails

    def _task_run_check(self, task: Task) -> Dict[str, Any]:
        """Execute a specific security check."""
        check_name = task.parameters.get("check_name")
        if not check_name:
            raise ValueError("check_name parameter required")

        result = get_check_by_name(check_name)
        threats = result.get("threats", [])

        if threats:
            for threat in threats:
                self._handle_threat_detection(threat, f"task:{task.task_id}")

        return {
            "check_name": check_name,
            "threats_detected": len(threats),
            "threats": threats
        }

    def _task_scan(self, task: Task) -> Dict[str, Any]:
        """Execute a comprehensive security scan."""
        threat_data = task.parameters.get("threat_data", "")
        
        threat_info = detect_threat(threat_data)
        scan_results = {
            "threat_detected": threat_info is not None,
            "threat_type": threat_info.get("threat_type") if threat_info else None,
            "timestamp": datetime.now().isoformat()
        }

        if threat_info:
            risk_info = calculate_risk(threat_info)
            scan_results["risk_score"] = risk_info.get("risk_score")
            scan_results["risk_level"] = risk_info.get("risk_level")
            
            # Handle threat
            threat_record = {
                "timestamp": datetime.now().isoformat(),
                "threat": threat_data,
                "source": f"task:{task.task_id}",
                "agent_id": self.agent_id,
                "threat_type": threat_info.get("threat_type"),
                "risk_score": risk_info.get("risk_score"),
            }
            self.threats_detected.append(threat_record)

        return scan_results

    def _task_analyze_threat(self, task: Task) -> Dict[str, Any]:
        """Analyze a specific threat using GROQ if available."""
        threat_description = task.parameters.get("threat_description")
        indicators = task.parameters.get("indicators", [])

        if not threat_description:
            raise ValueError("threat_description parameter required")

        analysis = {
            "threat_description": threat_description,
            "indicators": indicators,
            "timestamp": datetime.now().isoformat()
        }

        if groq_client.is_configured():
            groq_analysis = groq_client.analyze_threat(threat_description, indicators)
            analysis["groq_analysis"] = groq_analysis
            analysis["ai_powered"] = True
        else:
            analysis["ai_powered"] = False
            analysis["message"] = "GROQ not configured - using built-in analysis"

        return analysis

    def _task_remediate(self, task: Task) -> Dict[str, Any]:
        """Execute remediation for a threat."""
        threat_type = task.parameters.get("threat_type")
        if not threat_type:
            raise ValueError("threat_type parameter required")

        action = self._execute_prevention_action(threat_type)
        return {
            "threat_type": threat_type,
            "action_taken": action,
            "timestamp": datetime.now().isoformat(),
            "success": True
        }

    def _task_custom(self, task: Task) -> Dict[str, Any]:
        """Execute a custom task."""
        # Custom tasks can be defined by the user
        action = task.parameters.get("action", "No action specified")
        return {
            "custom_action": action,
            "timestamp": datetime.now().isoformat(),
            "parameters": task.parameters
        }

    def assign_task(self, task: Task) -> bool:
        """
        Assign a task to this agent.

        Args:
            task: Task to assign

        Returns:
            True if task was queued
        """
        if not self.running:
            return False

        self.task_queue.put(task)
        return True

    def get_pending_tasks(self) -> List[Task]:
        """
        Get list of pending tasks.

        Returns:
            List of pending tasks
        """
        # Queue doesn't have an easy way to peek, so we return empty
        # In production, you might want to track this separately
        return []

    def get_completed_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recently completed tasks.

        Args:
            limit: Maximum number of tasks to return

        Returns:
            List of completed task records
        """
        return [task.to_dict() for task in self.tasks_completed[-limit:]]

    def register_task_callback(self, callback: Callable):
        """
        Register callback for task completion.

        Args:
            callback: Function to call when task completes
        """
        self.on_task_completed = callback

    def _perform_checks(self):
        """Perform security checks."""
        self.checks_performed += 1
        
        config = load_config()
        checks_to_run = config.get("security_checks", [])

        for check_name in checks_to_run:
            if not self.running:
                break

            try:
                result = get_check_by_name(check_name)
                threats = result.get("threats", [])

                if threats:
                    for threat in threats:
                        self._handle_threat_detection(threat, check_name)
            except Exception as e:
                pass  # Continue with next check

    def _handle_threat_detection(self, threat_text: str, source: str):
        """
        Handle a detected threat.

        Args:
            threat_text: Description of the threat
            source: Source of the threat detection
        """
        threat_data = {
            "timestamp": datetime.now().isoformat(),
            "threat": threat_text,
            "source": source,
            "agent_id": self.agent_id,
            "prevented": False,
            "prevented_by": None
        }

        # Try to detect threat type from text
        threat_info = detect_threat(threat_text)

        if threat_info:
            threat_type = threat_info.get("threat_type")
            threat_data["threat_type"] = threat_type
            
            # Calculate risk
            risk_info = calculate_risk(threat_info)
            threat_score = risk_info.get("risk_score", 0)
            threat_data["risk_score"] = threat_score

            # Check if we should prevent this threat
            should_prevent = threat_score > get_config_value("threat_threshold", 50)

            if should_prevent:
                threat_data["prevented"] = self._attempt_prevention(threat_type, threat_data)

        self.threats_detected.append(threat_data)

        # Call callback if registered
        if self.on_threat_detected:
            self.on_threat_detected(threat_data)

    def _attempt_prevention(self, threat_type: str, threat_data: dict) -> bool:
        """
        Attempt to prevent a threat.

        Args:
            threat_type: Type of threat
            threat_data: Threat information

        Returns:
            True if prevention was successful
        """
        try:
            # Check if Groq is configured for AI-powered prevention
            if groq_client.is_configured():
                analysis = groq_client.analyze_threat(
                    threat_data.get("threat", ""),
                    [threat_type]
                )

                if analysis.get("should_prevent"):
                    prevention_action = self._execute_prevention_action(threat_type)
                    threat_data["prevented_by"] = prevention_action
                    
                    if self.on_prevention_action:
                        self.on_prevention_action(self.agent_id, threat_type, prevention_action)
                    
                    return True
            else:
                # Use built-in prevention logic
                if threat_type in ["ransomware", "malware", "exploit", "denial_of_service"]:
                    prevention_action = self._execute_prevention_action(threat_type)
                    threat_data["prevented_by"] = prevention_action
                    
                    if self.on_prevention_action:
                        self.on_prevention_action(self.agent_id, threat_type, prevention_action)
                    
                    return True
        except Exception as e:
            pass

        return False

    def _execute_prevention_action(self, threat_type: str) -> str:
        """
        Execute a prevention action for a threat.

        Args:
            threat_type: Type of threat

        Returns:
            Description of action taken
        """
        actions = {
            "ransomware": "Isolated suspicious process, enabled file recovery",
            "malware": "Quarantined suspicious file, ran antivirus scan",
            "exploit": "Patched vulnerable service, disconnected from network",
            "denial_of_service": "Rate-limited connection, blocked attacker IP",
            "phishing": "Blocked malicious email domain, alerted user",
            "data_breach": "Isolated affected system, enabled data encryption",
            "lateral_movement": "Restricted network access, enabled MFA",
            "credential_theft": "Reset compromised credentials, enabled 2FA",
            "supply_chain": "Quarantined suspicious package, verified source"
        }

        return actions.get(threat_type, f"Took preventive action for {threat_type}")

    def get_status(self) -> Dict[str, Any]:
        """
        Get agent status.

        Returns:
            Dictionary with status information
        """
        uptime = None
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()

        return {
            "agent_id": self.agent_id,
            "running": self.running,
            "checks_performed": self.checks_performed,
            "threats_detected": len(self.threats_detected),
            "prevented_count": sum(1 for t in self.threats_detected if t.get("prevented")),
            "uptime_seconds": uptime,
            "check_interval": self.check_interval
        }

    def get_recent_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent detected threats.

        Args:
            limit: Maximum number of threats to return

        Returns:
            List of threat records
        """
        return self.threats_detected[-limit:]

    def clear_threat_history(self):
        """Clear threat history."""
        self.threats_detected = []

    def export_threats(self, filepath: str = None) -> str:
        """
        Export threat data to JSON.

        Args:
            filepath: File path to export to (optional)

        Returns:
            JSON string of threats
        """
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(self.threats_detected, f, indent=2)
            return f"Exported {len(self.threats_detected)} threats to {filepath}"

        return json.dumps(self.threats_detected, indent=2)

    def register_threat_callback(self, callback: Callable):
        """
        Register callback for threat detection.

        Args:
            callback: Function to call when threat is detected
        """
        self.on_threat_detected = callback

    def register_prevention_callback(self, callback: Callable):
        """
        Register callback for prevention actions.

        Args:
            callback: Function to call when prevention action is taken
        """
        self.on_prevention_action = callback


class AgentManager:
    """
    Manages multiple agents across the system.
    """

    def __init__(self):
        """Initialize the agent manager."""
        self.agents = {}
        self.global_log = []

    def create_agent(self, agent_id: str, check_interval: int = 60) -> Agent:
        """
        Create a new agent.

        Args:
            agent_id: Unique identifier for the agent
            check_interval: Seconds between checks

        Returns:
            The created agent
        """
        if agent_id in self.agents:
            return self.agents[agent_id]

        agent = Agent(agent_id, check_interval)
        agent.register_threat_callback(self._log_threat_globally)
        agent.register_prevention_callback(self._log_prevention_action)
        
        self.agents[agent_id] = agent
        return agent

    def start_agent(self, agent_id: str) -> bool:
        """
        Start an agent.

        Args:
            agent_id: Agent ID to start

        Returns:
            True if successful
        """
        if agent_id in self.agents:
            return self.agents[agent_id].start()
        return False

    def stop_agent(self, agent_id: str) -> bool:
        """
        Stop an agent.

        Args:
            agent_id: Agent ID to stop

        Returns:
            True if successful
        """
        if agent_id in self.agents:
            return self.agents[agent_id].stop()
        return False

    def remove_agent(self, agent_id: str) -> bool:
        """
        Stop and remove an agent from the manager.

        Returns True if removed, False otherwise.
        """
        if agent_id in self.agents:
            try:
                self.agents[agent_id].stop()
            except Exception:
                pass
            del self.agents[agent_id]
            return True
        return False

    def stop_all_agents(self) -> int:
        """
        Stop all agents.

        Returns:
            Number of agents stopped
        """
        count = 0
        for agent in self.agents.values():
            if agent.stop():
                count += 1
        return count

    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of an agent.

        Args:
            agent_id: Agent ID

        Returns:
            Status dictionary or None
        """
        if agent_id in self.agents:
            return self.agents[agent_id].get_status()
        return None

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all agents.

        Returns:
            Dictionary of all agent statuses
        """
        return {agent_id: agent.get_status() for agent_id, agent in self.agents.items()}

    def get_global_statistics(self) -> Dict[str, Any]:
        """
        Get global statistics across all agents.

        Returns:
            Statistics dictionary
        """
        total_checks = sum(a.checks_performed for a in self.agents.values())
        total_threats = sum(len(a.threats_detected) for a in self.agents.values())
        total_prevented = sum(
            sum(1 for t in a.threats_detected if t.get("prevented"))
            for a in self.agents.values()
        )

        return {
            "total_agents": len(self.agents),
            "running_agents": sum(1 for a in self.agents.values() if a.running),
            "total_checks_performed": total_checks,
            "total_threats_detected": total_threats,
            "total_prevented": total_prevented,
            "global_events": len(self.global_log)
        }

    def _log_threat_globally(self, threat_data: dict):
        """Log a threat globally."""
        self.global_log.append({
            "event": "threat_detected",
            "timestamp": datetime.now().isoformat(),
            "data": threat_data
        })

    def _log_prevention_action(self, *args):
        """Log a prevention action globally.

        Supports both call styles for compatibility:
        - (agent_id, threat_type, action)
        - (threat_type, action)
        """
        if len(args) == 3:
            agent_id, threat_type, action = args
        elif len(args) == 2:
            threat_type, action = args
            agent_id = None
        else:
            raise TypeError("_log_prevention_action expects 2 or 3 positional arguments")

        event = {
            "event": "prevention_action",
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "action": action
        }
        if agent_id:
            event["agent_id"] = agent_id

        self.global_log.append(event)

    def assign_task_to_agent(self, agent_id: str, task: Task) -> bool:
        """
        Assign a task to a specific agent.

        Args:
            agent_id: Agent ID to assign task to
            task: Task to assign

        Returns:
            True if task was assigned
        """
        if agent_id in self.agents:
            return self.agents[agent_id].assign_task(task)
        return False

    def assign_task_to_all_agents(self, task: Task) -> int:
        """
        Assign a task to all running agents.

        Args:
            task: Task to assign

        Returns:
            Number of agents task was assigned to
        """
        count = 0
        for agent in self.agents.values():
            if agent.running and agent.assign_task(task):
                count += 1
        return count

    def create_task(
        self,
        task_type: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Task:
        """
        Create a new task.

        Args:
            task_type: Type of task (check, scan, threat_analysis, remediate, custom)
            description: Human-readable description
            parameters: Task-specific parameters

        Returns:
            Created Task object
        """
        import uuid
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        return Task(task_id, task_type, description, parameters)

    def get_agent_completed_tasks(self, agent_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get completed tasks for an agent.

        Args:
            agent_id: Agent ID
            limit: Maximum number of tasks to return

        Returns:
            List of completed task records
        """
        if agent_id in self.agents:
            return self.agents[agent_id].get_completed_tasks(limit)
        return []

    def get_all_completed_tasks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get completed tasks for all agents.

        Returns:
            Dictionary of agent ID to completed tasks
        """
        return {
            agent_id: agent.get_completed_tasks(10)
            for agent_id, agent in self.agents.items()
        }

    def export_all_data(self, filepath: str) -> bool:
        """
        Export all agent data.

        Args:
            filepath: File to export to

        Returns:
            True if successful
        """
        try:
            data = {
                "statistics": self.get_global_statistics(),
                "agents": {
                    agent_id: {
                        "status": agent.get_status(),
                        "recent_threats": agent.get_recent_threats(20)
                    }
                    for agent_id, agent in self.agents.items()
                },
                "global_log": self.global_log[-100:]  # Last 100 events
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Export failed: {e}")
            return False

    def get_learned_techniques(self, threat_type: str) -> List[Dict[str, Any]]:
        """Get techniques the system has learned for a threat type.
        
        Args:
            threat_type: Type of threat
            
        Returns:
            List of effective techniques ranked by effectiveness
        """
        return agent_learning.get_techniques_for_threat(threat_type)

    def get_learned_rules(self) -> List[Dict[str, Any]]:
        """Extract and return learned decision rules.
        
        Returns:
            List of learned rules with confidence scores
        """
        return agent_learning.extract_learned_rules()

    def get_recommendation_for_threat(self, threat_type: str, task_type: str = "remediate") -> Optional[Dict[str, Any]]:
        """Get AI-powered recommendation based on what we've learned.
        
        Args:
            threat_type: Type of threat to handle
            task_type: Type of task to perform
            
        Returns:
            Recommendation with suggested techniques
        """
        return agent_learning.get_recommendation(threat_type, task_type)

    def get_learning_summary(self, agent_id: Optional[str] = None) -> str:
        """Get a summary of what the system has learned.
        
        Args:
            agent_id: Optional - filter by specific agent
            
        Returns:
            Formatted summary string
        """
        return agent_learning.get_conversation_summary(agent_id)


# Global agent manager instance
agent_manager = AgentManager()
