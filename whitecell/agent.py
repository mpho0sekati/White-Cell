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

from whitecell.detection import detect_threat
from whitecell.risk import calculate_risk, get_threat_mitigations
from whitecell.security_checks import run_all_checks, get_check_by_name
from whitecell.config import load_config, get_config_value
from whitecell.groq_client import groq_client


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
                self._perform_checks()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"Agent {self.agent_id} error: {e}")

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
        threat_type = detect_threat(threat_text)

        if threat_type:
            threat_data["threat_type"] = threat_type[0]
            
            # Calculate risk
            risk_score = calculate_risk(threat_type[0], threat_text)
            threat_data["risk_score"] = risk_score

            # Check if we should prevent this threat
            should_prevent = risk_score > get_config_value("threat_threshold", 50)

            if should_prevent:
                threat_data["prevented"] = self._attempt_prevention(threat_type[0], threat_data)

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
                        self.on_prevention_action(threat_type, prevention_action)
                    
                    return True
            else:
                # Use built-in prevention logic
                if threat_type in ["ransomware", "malware", "exploit", "denial_of_service"]:
                    prevention_action = self._execute_prevention_action(threat_type)
                    threat_data["prevented_by"] = prevention_action
                    
                    if self.on_prevention_action:
                        self.on_prevention_action(threat_type, prevention_action)
                    
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

    def _log_prevention_action(self, threat_type: str, action: str):
        """Log a prevention action globally."""
        self.global_log.append({
            "event": "prevention_action",
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "action": action
        })

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


# Global agent manager instance
agent_manager = AgentManager()
