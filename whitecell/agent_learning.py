"""
Agent Learning System

Captures and learns from agent interactions:
- Conversation history between main agent and helpers
- Techniques used by agents
- Task success/failure rates
- Patterns and recommendations
- Persistent knowledge base
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

try:
    from whitecell.groq_client import groq_client
except ImportError:
    groq_client = None


class AgentLearning:
    """Learn and remember agent techniques and conversation history."""

    def __init__(self, knowledge_file: Optional[str] = None):
        """Initialize learning system.
        
        Args:
            knowledge_file: Path to persistent knowledge base (default: ~/.whitecell/agent_knowledge.json)
        """
        if knowledge_file is None:
            home = Path.home()
            wc_dir = home / ".whitecell"
            wc_dir.mkdir(exist_ok=True)
            knowledge_file = str(wc_dir / "agent_knowledge.json")
        
        self.knowledge_file = knowledge_file
        self.interactions = []  # In-memory log of all interactions
        self.knowledge_base = {
            "techniques": defaultdict(list),  # technique_name -> [outcomes]
            "threat_patterns": defaultdict(list),  # threat_type -> [techniques_effective]
            "agent_conversations": [],  # Full conversation history
            "learned_rules": [],  # Extracted decision rules
            "metadata": {
                "created": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "total_interactions": 0
            }
        }
        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """Load persisted knowledge base from file."""
        try:
            if Path(self.knowledge_file).exists():
                with open(self.knowledge_file, 'r') as f:
                    data = json.load(f)
                    # Convert lists back to defaultdict
                    techniques = data.get("knowledge_base", {}).get("techniques", {})
                    self.knowledge_base["techniques"] = defaultdict(list, techniques)
                    self.knowledge_base["threat_patterns"] = defaultdict(
                        list, data.get("knowledge_base", {}).get("threat_patterns", {})
                    )
                    self.knowledge_base["agent_conversations"] = data.get("knowledge_base", {}).get("agent_conversations", [])
                    self.knowledge_base["learned_rules"] = data.get("knowledge_base", {}).get("learned_rules", [])
                    self.knowledge_base["metadata"] = data.get("knowledge_base", {}).get("metadata", {})
        except Exception as e:
            print(f"Warning: Could not load knowledge base: {e}")

    def save_knowledge(self) -> None:
        """Persist knowledge base to file."""
        try:
            data = {
                "knowledge_base": {
                    "techniques": dict(self.knowledge_base["techniques"]),
                    "threat_patterns": dict(self.knowledge_base["threat_patterns"]),
                    "agent_conversations": self.knowledge_base["agent_conversations"],
                    "learned_rules": self.knowledge_base["learned_rules"],
                    "metadata": {
                        **self.knowledge_base["metadata"],
                        "last_updated": datetime.now().isoformat(),
                        "total_interactions": len(self.interactions)
                    }
                }
            }
            Path(self.knowledge_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.knowledge_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save knowledge base: {e}")

    def record_interaction(
        self,
        agent_id: str,
        task_type: str,
        task_description: str,
        outcome: str,
        success: bool,
        techniques_used: Optional[List[str]] = None,
        threat_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Record an agent interaction/task.
        
        Args:
            agent_id: ID of the agent that performed the task
            task_type: Type of task (scan, analyze, remediate, etc.)
            task_description: Human-readable description
            outcome: Result or output from the task
            success: Whether the task succeeded
            techniques_used: List of techniques/methods used
            threat_type: Type of threat handled (if applicable)
            metadata: Additional metadata
            
        Returns:
            Interaction ID
        """
        interaction_id = hashlib.md5(
            f"{agent_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]

        interaction = {
            "id": interaction_id,
            "agent_id": agent_id,
            "task_type": task_type,
            "task_description": task_description,
            "outcome": outcome,
            "success": success,
            "techniques_used": techniques_used or [],
            "threat_type": threat_type,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }

        self.interactions.append(interaction)
        self.knowledge_base["agent_conversations"].append(interaction)

        # Record in techniques index
        if techniques_used:
            for technique in techniques_used:
                self.knowledge_base["techniques"][technique].append({
                    "agent_id": agent_id,
                    "success": success,
                    "threat_type": threat_type,
                    "task_type": task_type,
                    "timestamp": interaction["timestamp"]
                })

        # Record in threat patterns index
        if threat_type:
            if techniques_used:
                self.knowledge_base["threat_patterns"][threat_type].extend(techniques_used)
            self.knowledge_base["threat_patterns"][threat_type].append({
                "task": task_type,
                "success": success,
                "agent_id": agent_id
            })

        self.save_knowledge()
        return interaction_id

    def get_techniques_for_threat(self, threat_type: str) -> List[Dict[str, Any]]:
        """Get all known effective techniques for a threat type.
        
        Args:
            threat_type: Type of threat
            
        Returns:
            List of techniques with effectiveness metadata
        """
        if threat_type not in self.knowledge_base["threat_patterns"]:
            return []

        techniques_used = self.knowledge_base["threat_patterns"][threat_type]
        technique_stats = {}

        for item in techniques_used:
            if isinstance(item, dict):
                continue
            if item not in technique_stats:
                technique_stats[item] = {"count": 0, "successes": 0}
            technique_stats[item]["count"] += 1

        # Get success rates
        if threat_type in self.knowledge_base["techniques"]:
            for technique_name, outcomes in self.knowledge_base["techniques"].items():
                for outcome in outcomes:
                    if outcome.get("threat_type") == threat_type:
                        if technique_name in technique_stats:
                            if outcome.get("success"):
                                technique_stats[technique_name]["successes"] += 1

        # Format as list with effectiveness
        result = []
        for technique, stats in sorted(technique_stats.items(), key=lambda x: x[1]["successes"], reverse=True):
            effectiveness = 100 * stats["successes"] / stats["count"] if stats["count"] > 0 else 0
            result.append({
                "technique": technique,
                "effectiveness": effectiveness,
                "uses": stats["count"],
                "successes": stats["successes"]
            })

        return result

    def extract_learned_rules(self) -> List[Dict[str, Any]]:
        """Extract decision rules from learned patterns.
        
        Returns:
            List of learned rules with confidence scores
        """
        rules = []

        # Rule: Threats with high success rate techniques
        for threat_type, techniques_list in self.knowledge_base["threat_patterns"].items():
            if isinstance(threat_type, str) and threat_type not in ["task", "success", "agent_id"]:
                effective_techniques = self.get_techniques_for_threat(threat_type)
                if effective_techniques:
                    best_technique = effective_techniques[0]
                    if best_technique["effectiveness"] >= 70:
                        rules.append({
                            "type": "technique_recommendation",
                            "threat_type": threat_type,
                            "recommended_technique": best_technique["technique"],
                            "confidence": best_technique["effectiveness"],
                            "rule": f"For {threat_type}, use {best_technique['technique']} (success rate: {best_technique['effectiveness']:.0f}%)"
                        })

        # Rule: Task type effectiveness
        task_success_rates = defaultdict(lambda: {"total": 0, "success": 0})
        for interaction in self.interactions:
            task_type = interaction.get("task_type")
            if task_type:
                task_success_rates[task_type]["total"] += 1
                if interaction.get("success"):
                    task_success_rates[task_type]["success"] += 1

        for task_type, stats in task_success_rates.items():
            success_rate = 100 * stats["success"] / stats["total"] if stats["total"] > 0 else 0
            if success_rate >= 80:
                rules.append({
                    "type": "task_strategy",
                    "task_type": task_type,
                    "success_rate": success_rate,
                    "rule": f"{task_type} tasks have {success_rate:.0f}% success rate"
                })

        self.knowledge_base["learned_rules"] = rules
        self.save_knowledge()
        return rules

    def get_recommendation(self, threat_type: str, task_type: str) -> Optional[Dict[str, Any]]:
        """Get AI-powered recommendation based on learned patterns.
        
        Args:
            threat_type: Type of threat to handle
            task_type: Type of task to perform
            
        Returns:
            Recommendation with suggested approach
        """
        techniques = self.get_techniques_for_threat(threat_type)
        if not techniques:
            return None

        rec = {
            "threat_type": threat_type,
            "task_type": task_type,
            "recommended_techniques": techniques[:3],  # Top 3
            "confidence": techniques[0]["effectiveness"] if techniques else 0
        }

        # Use Groq to refine recommendation if available
        if groq_client and groq_client.is_configured():
            try:
                techniques_str = ", ".join([t["technique"] for t in techniques[:3]])
                prompt = f"""Based on learned patterns, recommend how to handle a '{threat_type}' threat using a '{task_type}' task.
                Previously effective techniques: {techniques_str}.
                Provide a brief actionable recommendation."""

                rec["ai_recommendation"] = groq_client.get_explanation(prompt)
            except Exception:
                pass

        return rec

    def get_conversation_summary(self, agent_id: Optional[str] = None, limit: int = 10) -> str:
        """Get a summary of learned conversations.
        
        Args:
            agent_id: Filter by agent ID (None = all agents)
            limit: Number of conversations to include
            
        Returns:
            Formatted summary string
        """
        convs = self.knowledge_base["agent_conversations"]
        if agent_id:
            convs = [c for c in convs if c.get("agent_id") == agent_id]

        summary = f"\n{'='*70}\nAgent Learning Summary (Agent: {agent_id or 'All'})\n{'='*70}\n"
        summary += f"Total Interactions: {len(self.interactions)}\n"
        summary += f"Conversations Recorded: {len(self.knowledge_base['agent_conversations'])}\n"
        summary += f"Knowledge Base Updated: {self.knowledge_base['metadata'].get('last_updated', 'Never')}\n\n"

        if convs:
            summary += f"Recent Interactions (last {min(limit, len(convs))}):\n"
            summary += f"{'-'*70}\n"
            for conv in convs[-limit:]:
                status = "[SUCCESS]" if conv.get("success") else "[FAILED]"
                summary += f"\n{status} {conv['task_type'].upper()}: {conv['task_description']}\n"
                summary += f"  Outcome: {conv['outcome'][:60]}...\n" if len(conv.get('outcome', '')) > 60 else f"  Outcome: {conv.get('outcome', 'N/A')}\n"
                if conv.get("techniques_used"):
                    summary += f"  Techniques: {', '.join(conv['techniques_used'])}\n"
                if conv.get("threat_type"):
                    summary += f"  Threat Type: {conv['threat_type']}\n"

        summary += f"\n{'='*70}\n"
        return summary


# Global learning instance
agent_learning = AgentLearning()
