"""
White Cell Groq Client

This module handles communication with the Groq API for AI-powered reasoning.
It provides explanations and strategic advice for cybersecurity scenarios.

Author: White Cell Project
"""

import os
from typing import Optional

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


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
                     GROQ_API_KEY environment variable and config.
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = "mixtral-8x7b-32768"  # Default Groq model
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Groq client if API key is available."""
        if self.api_key and GROQ_AVAILABLE:
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                print(f"Failed to initialize Groq client: {e}")
                self.client = None

    def is_configured(self) -> bool:
        """
        Check if the Groq client is properly configured with an API key.

        Returns:
            True if API key is available and Groq library is installed, False otherwise
        """
        return self.api_key is not None and GROQ_AVAILABLE and self.client is not None

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


# Global Groq client instance
groq_client = GroqClient()
