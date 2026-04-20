"""
Attribution module for White Cell.

This module captures network packets, identifies suspicious activity,
queries threat intelligence APIs, and generates threat actor profiles.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import requests

# Try to import scapy, but allow graceful degradation if not available
try:
    from scapy.all import sniff, TCP, UDP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy is not installed. Network attribution features will be limited.")

from concurrent.futures import ThreadPoolExecutor, as_completed

from whitecell.groq_client import groq_client
from whitecell.detection import detect_threat
from whitecell.config import load_config

logger = logging.getLogger(__name__)

# Patterns to identify potentially malicious traffic
MALICIOUS_PATTERNS = [
    r'nmap',  # Nmap scans
    r'havij',  # SQL injection tools
    r'sqlmap',  # SQL injection automation
    r'nikto',  # Web vulnerability scanner
    r'nessus',  # Vulnerability scanner
    r'hydra',  # Password brute-forcing
    r'metasploit',  # Exploitation framework
    r'arachni',  # Web application scanner
    r'w3af',  # Web application attack framework
]

# Ports commonly associated with scanning
SCANNING_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 11211, 27017
]

class PacketAnalyzer:
    """
    Analyzes network packets to identify suspicious activity.
    """
    
    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Network packet analysis is not available.")
        self.suspicious_ips = set()
        self.packet_count = 0
        self.last_analysis_time = datetime.now()
    
    def is_suspicious_packet(self, packet) -> bool:
        """
        Determine if a packet is suspicious based on various criteria.
        """
        if not packet.haslayer(IP):
            return False
            
        # Extract IP layer info
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        # Check if it's a port scan attempt (many connections to different ports from same IP)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dst_port = None
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                
            if dst_port and dst_port in SCANNING_PORTS:
                # Check for multiple connections to different ports from same IP
                # This is simplified - in reality you'd track connections over time
                return True
        
        # Check payload for malicious patterns
        if packet.haslayer('Raw'):
            payload = str(packet['Raw'].load)
            for pattern in MALICIOUS_PATTERNS:
                if re.search(pattern, payload, re.IGNORECASE):
                    return True
        
        return False
    
    def extract_source_ip(self, packet):
        """
        Extract the source IP from a packet.
        """
        if packet.haslayer(IP):
            return packet[IP].src
        return None


class AttributionEngine:
    """
    Main attribution engine that captures packets and creates threat profiles.
    """
    
    def __init__(self):
        self.analyzer = None
        if SCAPY_AVAILABLE:
            try:
                self.analyzer = PacketAnalyzer()
            except RuntimeError:
                logger.warning("Packet analyzer not available due to missing scapy")
        self.threat_profiles = {}
        self.ip_cache = {}  # Cache for IP lookups
        self.config = load_config()
        
    def capture_packets(self, interface=None, timeout=60, count=1000):
        """
        Capture packets on the specified interface for a given timeout period.
        
        Args:
            interface: Network interface to capture on (None for default)
            timeout: Time in seconds to capture packets
            count: Maximum number of packets to capture
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Cannot capture packets.")
            return []
        
        if self.analyzer is None:
            logger.error("Packet analyzer not initialized.")
            return []
        
        logger.info(f"Starting packet capture on interface: {interface or 'default'}")
        
        try:
            packets = sniff(
                iface=interface,
                timeout=timeout,
                count=count,
                filter="ip",  # Only capture IP packets
                prn=lambda x: self._process_packet(x)
            )
            logger.info(f"Captured {len(packets)} packets")
            return packets
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            return []
    
    def _process_packet(self, packet):
        """
        Process a captured packet to check for suspicious activity.
        """
        if not SCAPY_AVAILABLE or self.analyzer is None:
            return
        
        self.analyzer.packet_count += 1
        
        if self.analyzer.is_suspicious_packet(packet):
            src_ip = self.analyzer.extract_source_ip(packet)
            if src_ip:
                logger.info(f"Suspicious activity detected from IP: {src_ip}")
                self.analyzer.suspicious_ips.add(src_ip)
                
                # Generate threat profile for this IP
                profile = self.generate_threat_profile(src_ip)
                if profile:
                    self.threat_profiles[src_ip] = profile
    
    def query_ip_intel(self, ip_address: str) -> Optional[Dict]:
        """
        Query IP intelligence service to get geolocation and ISP info.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary with IP intelligence data or None if failed
        """
        # First check cache to avoid repeated API calls
        if ip_address in self.ip_cache:
            logger.debug(f"Retrieved {ip_address} from cache")
            return self.ip_cache[ip_address]
        
        # Query ip-api.com for geolocation data
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    # Cache the result
                    self.ip_cache[ip_address] = data
                    return data
                else:
                    logger.warning(f"IP API returned error for {ip_address}: {data.get('message')}")
                    return None
            else:
                logger.error(f"IP API request failed with status {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error querying IP intelligence for {ip_address}: {e}")
            return None
    
    def generate_threat_profile(self, ip_address: str) -> Optional[str]:
        """
        Generate a threat actor profile based on IP intelligence.
        
        Args:
            ip_address: The suspicious IP address
            
        Returns:
            A human-readable threat actor profile or None if failed
        """
        logger.info(f"Generating threat profile for {ip_address}")
        
        # Get IP intelligence data
        intel_data = self.query_ip_intel(ip_address)
        if not intel_data:
            logger.warning(f"Could not get intelligence for {ip_address}")
            return None
        
        # Prepare context for LLM
        context_parts = [
            f"Source IP: {ip_address}",
            f"Country: {intel_data.get('country', 'Unknown')}",
            f"Region: {intel_data.get('regionName', 'Unknown')}",
            f"City: {intel_data.get('city', 'Unknown')}",
            f"ISP: {intel_data.get('isp', 'Unknown')}",
            f"Organization: {intel_data.get('org', 'Unknown')}",
            f"AS Info: {intel_data.get('as', 'Unknown')}",
            f"Proxy/VPN: {'Yes' if intel_data.get('proxy', False) else 'No'}",
            f"Hosting Provider: {'Yes' if intel_data.get('hosting', False) else 'No'}",
        ]
        
        context = "\n".join(context_parts)
        
        # Create a prompt for the LLM
        prompt = f"""
Based on the following IP intelligence data, generate a brief threat actor profile that describes the likely characteristics of the attacker/source:

{context}

Provide a concise profile that includes:
1. Likely identity (e.g., script kiddie, professional hacker, state actor)
2. Motivation (e.g., financial gain, political activism, curiosity)
3. Sophistication level (low, medium, high)
4. Potential affiliation (if applicable)

Format the response as: "Likely a [identity] motivated by [motivation], with [level] sophistication, potentially affiliated with [affiliation]."
        """
        
        try:
            # Use the Groq client to generate the threat profile
            response = groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="mixtral-8x7b-32768",  # Using Mixtral for good balance of speed and quality
                max_tokens=200,
                temperature=0.5,
            )
            
            profile = response.choices[0].message.content.strip()
            logger.info(f"Generated profile for {ip_address}: {profile}")
            return profile
            
        except Exception as e:
            logger.error(f"Error generating threat profile for {ip_address}: {e}")
            # Return a basic profile in case of failure
            return f"Could not generate detailed profile for {ip_address}. Basic info: IP located in {intel_data.get('country', 'Unknown')} with ISP {intel_data.get('isp', 'Unknown')}."
    
    def get_suspicious_activity_report(self) -> str:
        """
        Generate a report of all suspicious activity detected.
        
        Returns:
            Formatted string report
        """
        if not SCAPY_AVAILABLE or self.analyzer is None:
            return "Network attribution not available. Install scapy to enable packet capture."
        
        if not self.analyzer.suspicious_ips:
            return "No suspicious activity detected."
        
        report_parts = ["SUSPICIOUS ACTIVITY REPORT", "="*50]
        
        for ip in self.analyzer.suspicious_ips:
            report_parts.append(f"\nIP Address: {ip}")
            
            # Get cached intelligence if available
            if ip in self.ip_cache:
                intel = self.ip_cache[ip]
                report_parts.append(f"  Location: {intel.get('city', 'Unknown')}, {intel.get('regionName', 'Unknown')}, {intel.get('country', 'Unknown')}")
                report_parts.append(f"  ISP: {intel.get('isp', 'Unknown')}")
                report_parts.append(f"  Proxy/VPN: {'Yes' if intel.get('proxy', False) else 'No'}")
            
            if ip in self.threat_profiles:
                report_parts.append(f"  Threat Profile: {self.threat_profiles[ip]}")
        
        return "\n".join(report_parts)
    
    def run_attribution_scan(self, interface=None, timeout=60) -> str:
        """
        Run a complete attribution scan cycle.
        
        Args:
            interface: Network interface to capture on
            timeout: How long to capture packets
            
        Returns:
            Report of suspicious activity
        """
        if not SCAPY_AVAILABLE:
            return "Network attribution not available. Install scapy to enable packet capture:\n\npip install scapy"
        
        if self.analyzer is None:
            return "Packet analyzer not initialized. Install scapy to enable packet capture."
        
        logger.info("Starting attribution scan...")
        
        # Clear previous results
        self.analyzer.suspicious_ips.clear()
        self.threat_profiles.clear()
        
        # Capture packets
        self.capture_packets(interface=interface, timeout=timeout)
        
        # Generate and return report
        report = self.get_suspicious_activity_report()
        logger.info("Attribution scan completed")
        return report


# Global instance for easy access
attribution_engine = AttributionEngine()


def run_attribution_scan(interface=None, timeout=60) -> str:
    """
    Convenience function to run attribution scan.
    
    Args:
        interface: Network interface to capture on (None for default)
        timeout: Time in seconds to capture packets
        
    Returns:
        Report of suspicious activity
    """
    return attribution_engine.run_attribution_scan(interface, timeout)


def get_suspicious_activity_report() -> str:
    """
    Get the latest suspicious activity report.
    
    Returns:
        Formatted report string
    """
    return attribution_engine.get_suspicious_activity_report()


if __name__ == "__main__":
    # Example usage
    print("Running attribution scan for 30 seconds...")
    report = run_attribution_scan(timeout=30)
    print(report)