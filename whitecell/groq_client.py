"""
White Cell Groq Client

This module handles communication with the Groq API for AI-powered reasoning.
It provides explanations and strategic advice for cybersecurity scenarios.

Author: White Cell Project
"""

import os
import logging
from typing import Optional

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

logger = logging.getLogger(__name__)


class GroqClient:
    """
    Client for interacting with Groq API.

    This class provides methods to query Groq for AI-powered cybersecurity reasoning.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Groq client.

        Args:
            api_key: Groq API key. If not provided, will attempt to load from
                     GROQ_API_KEY environment variable and persistent config.
        """
        # Try to load API key in order of priority:
        # 1. Provided argument
        # 2. Environment variable
        # 3. Persistent configuration
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        
        if not self.api_key:
            try:
                # Late import to avoid circular dependency
                from whitecell.config import get_groq_api_key
                self.api_key = get_groq_api_key()
            except (ImportError, Exception) as e:
                logger.debug(f"Could not load API key from config: {e}")
                self.api_key = None
        
        self.model = "mixtral-8x7b-32768"  # Default Groq model
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Groq client if API key is available."""
        if not GROQ_AVAILABLE:
            logger.debug("Groq library not installed. Install with: pip install groq")
            return
        
        if not self.api_key:
            logger.debug("No Groq API key configured. AI-powered threat analysis disabled.")
            return
        
        try:
            self.client = Groq(api_key=self.api_key)
            logger.info("Groq API client initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize Groq client: {e}")
            self.client = None

    def is_configured(self) -> bool:
        """
        Check if the Groq client is properly configured with an API key.

        Returns:
            True if API key is available and Groq library is installed, False otherwise
        """
        return self.api_key is not None and GROQ_AVAILABLE and self.client is not None

    def reload_from_config(self) -> bool:
        """
        Reload the API key from persistent config and reinitialize client.

        Returns:
            True if successfully configured, False otherwise
        """
        try:
            from whitecell.config import get_groq_api_key
            self.api_key = get_groq_api_key()
            self._initialize_client()
            return self.is_configured()
        except Exception as e:
            logger.warning(f"Failed to reload Groq config: {e}")
            return False

    def set_api_key(self, api_key: str) -> bool:
        """
        Set a new API key and reinitialize the client.

        Args:
            api_key: The new API key

        Returns:
            True if successful
        """
        self.api_key = api_key
        self._initialize_client()
        return self.is_configured()

    def get_explanation(self, query: str, context: str = "") -> str:
        """
        Get an explanation for a cybersecurity scenario.

        Args:
            query: The user's question or scenario
            context: Additional context about the threat

        Returns:
            AI-generated explanation
        """
        if not self.is_configured():
            return "Groq API not configured. Please provide a valid API key."

        try:
            system_prompt = """You are a cybersecurity expert assistant for White Cell, 
            a security threat detection and prevention system. Provide clear, actionable 
            security insights. Keep responses concise and technical."""

            user_message = f"{query}\n\nContext: {context}" if context else query

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3,
                max_tokens=500,
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"Error querying Groq API: {str(e)}"

    def get_strategy(self, threat_type: str, threat_details: dict = None) -> str:
        """
        Get strategic recommendations for handling a specific threat type.

        Args:
            threat_type: The type of threat (e.g., 'ransomware')
            threat_details: Dictionary with threat information (risk_score, impact, etc.)

        Returns:
            AI-generated strategy recommendations
        """
        if not self.is_configured():
            return "Groq API not configured. Please provide a valid API key."

        try:
            details_text = ""
            if threat_details:
                details_text = f"\nThreat Details:\n"
                for key, value in threat_details.items():
                    details_text += f"- {key}: {value}\n"

            system_prompt = """You are a cybersecurity expert for White Cell. 
            Provide concrete, step-by-step mitigation strategies for the given threat. 
            Focus on immediate actions and long-term prevention."""

            user_message = f"""Provide a comprehensive response strategy for addressing a {threat_type} threat.
            Include:
            1. Immediate response actions
            2. Containment measures
            3. Investigation steps
            4. Recovery procedures
            5. Prevention recommendations
            
            {details_text}"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3,
                max_tokens=1000,
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"Error querying Groq API: {str(e)}"

    def analyze_threat(self, threat_description: str, indicators: list = None) -> dict:
        """
        Analyze a threat using Groq AI and provide prevention recommendations.

        Args:
            threat_description: Description of the threat
            indicators: List of indicators or keywords detected

        Returns:
            Dictionary with analysis and recommendations
        """
        if not self.is_configured():
            return {
                "status": "unconfigured",
                "message": "Groq API not configured. Please provide a valid API key.",
                "should_prevent": False
            }

        try:
            indicators_text = "\n".join([f"- {ind}" for ind in indicators]) if indicators else "No specific indicators"

            system_prompt = """You are a security AI system. Analyze threats and provide 
            JSON-formatted responses with prevention recommendations. Be decisive about 
            whether to take prevention action."""

            user_message = f"""Analyze this security threat and provide recommendations:

Threat Description: {threat_description}

Detected Indicators:
{indicators_text}

Provide a JSON response with:
{{
    "threat_level": "low/medium/high/critical",
    "confidence": 0-100,
    "should_prevent": true/false,
    "recommended_actions": ["action1", "action2", ...],
    "reasoning": "brief explanation"
}}"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.2,
                max_tokens=500,
            )

            response_text = response.choices[0].message.content
            
            # Try to parse JSON response
            import json
            try:
                # Find JSON in response
                start = response_text.find('{')
                end = response_text.rfind('}') + 1
                if start != -1 and end > start:
                    json_str = response_text[start:end]
                    return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # Fallback if JSON parsing fails
            return {
                "status": "success",
                "analysis": response_text,
                "should_prevent": "high" in response_text.lower() or "critical" in response_text.lower()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "should_prevent": False
            }

    def blue_team_exercise(self, scenario: str = "") -> str:
        """
        Conduct a Blue Team (defensive) security exercise.

        Args:
            scenario: Specific scenario or prompt for the blue team exercise

        Returns:
            Blue team defense strategy and recommendations
        """
        if not self.is_configured():
            return "Groq API not configured. Please configure to enable blue team exercises."

        try:
            system_prompt = """You are a cybersecurity Blue Team expert conducting defensive security exercises. 
            Provide comprehensive defensive strategies, mitigation techniques, and security hardening recommendations.
            Focus on detection, prevention, and rapid response to security threats.
            Format your response with clear sections and actionable steps."""

            user_message = f"""Conduct a Blue Team (defensive) security exercise.

Scenario/Focus: {scenario if scenario else 'General defensive security hardening'}

Provide:
1. Current defensive posture assessment
2. Key vulnerabilities and gaps to address
3. Detection strategy and monitoring setup
4. Incident response procedures
5. Hardening recommendations
6. Testing plan to validate defenses
7. Security awareness training focus areas

Be specific and technical in your recommendations."""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.4,
                max_tokens=1500,
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"Error conducting blue team exercise: {str(e)}"

    def red_team_exercise(self, scenario: str = "") -> str:
        """
        Conduct a Red Team (offensive) security exercise.

        Args:
            scenario: Specific scenario or prompt for the red team exercise

        Returns:
            Red team attack strategy and recommendations
        """
        if not self.is_configured():
            return "Groq API not configured. Please configure to enable red team exercises."

        try:
            system_prompt = """You are a cybersecurity Red Team expert conducting authorized offensive security exercises. 
            Provide comprehensive attack simulation strategies, exploitation techniques, and penetration testing methodologies.
            Focus on reconnaissance, vulnerability assessment, and exploitation paths.
            Format your response with clear sections and logical attack sequences.
            Note: This is for authorized security testing only."""

            user_message = f"""Conduct a Red Team (offensive) security exercise for authorized testing.

Scenario/Focus: {scenario if scenario else 'General network and application penetration testing'}

Provide:
1. Reconnaissance methodology and targets to probe
2. Initial access vectors and techniques
3. Lateral movement strategies
4. Privilege escalation paths
5. Data exfiltration techniques
6. Persistence mechanisms (for testing)
7. Evasion tactics to avoid detection
8. Impact assessment criteria

Be specific about methodologies and tools that would be used in authorized penetration testing.
Include MITRE ATT&CK framework mapping where applicable."""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.4,
                max_tokens=1500,
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"Error conducting red team exercise: {str(e)}"

    def team_battle_scenario(self, threat_scenario: str = "") -> dict:
        """
        Run a Blue Team vs Red Team battle scenario.

        Args:
            threat_scenario: The security scenario to evaluate

        Returns:
            Dictionary with both blue and red team strategies
        """
        if not self.is_configured():
            return {
                "status": "unconfigured",
                "message": "Groq API not configured. Please configure to enable team battle scenarios."
            }

        try:
            # Get blue team defense
            blue_response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Blue Team expert. Design defensive measures for the given scenario."
                    },
                    {
                        "role": "user",
                        "content": f"""Scenario: {threat_scenario if threat_scenario else 'Ransomware attack on enterprise infrastructure'}

For this scenario, provide:
1. Detection mechanisms
2. Prevention measures
3. Containment strategy
4. Recovery plan
5. Monitoring approach

Be concise and tactical."""
                    }
                ],
                temperature=0.3,
                max_tokens=800,
            )

            # Get red team offense
            red_response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Red Team expert. Design attack vectors for the given scenario. This is for authorized testing."
                    },
                    {
                        "role": "user",
                        "content": f"""Scenario: {threat_scenario if threat_scenario else 'Ransomware attack on enterprise infrastructure'}

For this scenario, provide:
1. Initial access methods
2. Propagation techniques
3. Persistence mechanisms
4. Evasion tactics
5. Impact objectives

Be concise and tactical."""
                    }
                ],
                temperature=0.3,
                max_tokens=800,
            )

            return {
                "status": "success",
                "scenario": threat_scenario or "General security scenario",
                "blue_team": {
                    "role": "Defense",
                    "strategy": blue_response.choices[0].message.content
                },
                "red_team": {
                    "role": "Offense",
                    "strategy": red_response.choices[0].message.content
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


# Global Groq client instance
groq_client = GroqClient()
