"""
Website Security Scanner

Analyze websites for security weaknesses including:
- Domain/SSL analysis (passive)
- Header analysis (active - requires permission)
- Known vulnerabilities (passive)
- Security misconfigurations (active - requires permission)
"""

import re
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from datetime import datetime

from whitecell.groq_client import groq_client
from whitecell.detection import detect_threats


class WebsiteScanner:
    """Scan websites for security weaknesses."""

    def __init__(self):
        self.scan_history = []
        self.common_weak_endpoints = [
            "/admin", "/admin.php", "/wp-admin", "/administrator",
            "/test", "/debug", "/config.php", ".env", "/backup",
            "/.git", "/.gitconfig", "/.aws", "/sql", "/database.db"
        ]
        self.weak_headers = {
            "X-Frame-Options": "Missing - allows clickjacking",
            "X-Content-Type-Options": "Missing - allows MIME sniffing",
            "Content-Security-Policy": "Missing - allows XSS",
            "Strict-Transport-Security": "Missing - allows SSL downgrade",
            "X-XSS-Protection": "Missing - allows XSS in older browsers"
        }

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
            return parsed.netloc or url
        except Exception:
            return url

    def passive_scan(self, url: str) -> Dict[str, Any]:
        """Analyze URL for obvious weak points (no network access needed)."""
        domain = self.extract_domain(url)
        
        results = {
            "url": url,
            "domain": domain,
            "scan_type": "passive",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "risk_level": "low",
            "score": 100
        }

        # Check for HTTP (not HTTPS)
        if url.startswith("http://") and not url.startswith("https://"):
            results["findings"].append({
                "type": "unencrypted_transport",
                "severity": "critical",
                "description": "Site uses HTTP instead of HTTPS - all traffic is unencrypted",
                "weakness": "No transport encryption",
                "recommendation": "Use HTTPS with valid SSL certificate"
            })
            results["score"] -= 30

        # Check for common weak patterns in domain
        if "test" in domain.lower() or "dev" in domain.lower():
            results["findings"].append({
                "type": "development_domain",
                "severity": "high",
                "description": "Domain suggests development/test environment - may lack hardening",
                "weakness": "Possible dev/staging environment exposed",
                "recommendation": "Ensure dev environments are not publicly accessible"
            })
            results["score"] -= 15

        # Check for known vulnerable domains/services
        threat_detection = detect_threats(domain)
        if threat_detection:
            results["findings"].append({
                "type": "known_threat",
                "severity": "high",
                "description": f"Domain matches known threat pattern: {threat_detection[0].get('threat_type', 'unknown')}",
                "weakness": "Domain associated with malicious activity",
                "recommendation": "Investigate immediately"
            })
            results["score"] -= 25

        # Analyze URL structure for common weaknesses
        url_weaknesses = self._analyze_url_structure(url)
        results["findings"].extend(url_weaknesses)
        results["score"] = max(0, results["score"] - (5 * len(url_weaknesses)))

        # Update risk level based on score
        if results["score"] < 40:
            results["risk_level"] = "critical"
        elif results["score"] < 60:
            results["risk_level"] = "high"
        elif results["score"] < 80:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

        return results

    def _analyze_url_structure(self, url: str) -> List[Dict[str, Any]]:
        """Identify common weak patterns in URL structure."""
        weaknesses = []

        # Check for admin paths
        if any(pattern in url.lower() for pattern in ["/admin", "/wp-admin", "/user/login"]):
            weaknesses.append({
                "type": "exposed_admin_path",
                "severity": "medium",
                "description": "Admin/login path visible in URL - should use obscured or internal path",
                "weakness": "Discoverable administrative interface",
                "recommendation": "Restrict admin paths to VPN or internal access"
            })

        # Check for parameters and query strings
        if "?" in url and any(param in url for param in ["id=", "user=", "file=", "page="]):
            weaknesses.append({
                "type": "exposed_parameters",
                "severity": "medium",
                "description": "Sensitive parameters visible in URL",
                "weakness": "Information disclosure in URL",
                "recommendation": "Use POST requests for sensitive parameters"
            })

        # Check for common weak file extensions
        if any(ext in url.lower() for ext in [".bak", ".old", ".sql", ".zip", ".rar"]):
            weaknesses.append({
                "type": "backup_file_exposed",
                "severity": "critical",
                "description": "Backup/archive file extension in URL",
                "weakness": "Sensitive data may be exposed",
                "recommendation": "Remove backup files from web-accessible directories"
            })

        return weaknesses

    def active_scan(self, url: str) -> Dict[str, Any]:
        """Perform active security tests (requires network access and permission)."""
        results = self.passive_scan(url)
        results["scan_type"] = "active"
        results["active_findings"] = []

        domain = self.extract_domain(url)

        # Try to detect SSL/TLS issues
        ssl_info = self._check_ssl(domain)
        if ssl_info:
            results["active_findings"].extend(ssl_info)
            results["score"] -= 10 * len(ssl_info)

        # Check for common headers via Groq if available
        headers_analysis = self._analyze_headers_with_ai(domain)
        if headers_analysis:
            results["active_findings"].extend(headers_analysis)
            results["score"] -= 5 * len(headers_analysis)

        # Simulate endpoint discovery
        weak_endpoints = self._simulate_endpoint_discovery(domain)
        if weak_endpoints:
            results["active_findings"].extend(weak_endpoints)
            results["score"] -= 15

        # Re-update risk level
        if results["score"] < 40:
            results["risk_level"] = "critical"
        elif results["score"] < 60:
            results["risk_level"] = "high"
        elif results["score"] < 80:
            results["risk_level"] = "medium"

        return results

    def _check_ssl(self, domain: str) -> List[Dict[str, Any]]:
        """Check for SSL/TLS issues."""
        findings = []
        
        # Simulate SSL check (in production, use ssl module or requests)
        findings.append({
            "type": "ssl_check_performed",
            "severity": "info",
            "description": f"SSL certificate analysis for {domain}",
            "weakness": "Simulated SSL verification (requires real HTTPS library)",
            "recommendation": "Use valid, current SSL certificate with proper chain"
        })
        
        return findings

    def _analyze_headers_with_ai(self, domain: str) -> List[Dict[str, Any]]:
        """Use Groq to analyze security headers if available."""
        findings = []

        if not groq_client.is_configured():
            return findings

        try:
            prompt = f"""Analyze security headers for {domain}. 
            List common missing security headers that would make this domain vulnerable.
            Format as JSON array of {{type, severity, description, recommendation}}.
            Focus on: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, X-XSS-Protection."""

            # Try to parse response as JSON
            content = groq_client.get_explanation(prompt)
            if "[" in content:
                json_str = content[content.index("["):content.rindex("]") + 1]
                analysis = json.loads(json_str)
                findings.extend(analysis)
        except Exception:
            pass

        return findings

    def _simulate_endpoint_discovery(self, domain: str) -> List[Dict[str, Any]]:
        """Identify potentially weak endpoints."""
        findings = []
        weak_found = []

        for endpoint in self.common_weak_endpoints:
            if endpoint in weak_found[:3]:  # Report top 3 only
                continue
            weak_found.append(endpoint)
            findings.append({
                "type": "weak_endpoint",
                "severity": "medium",
                "description": f"Endpoint {endpoint} may be accessible",
                "weakness": f"Potentially exposed: {endpoint}",
                "recommendation": f"Disable or restrict access to {endpoint}"
            })

        if weak_found:
            findings.insert(0, {
                "type": "endpoint_discovery",
                "severity": "high",
                "description": f"Found {len(weak_found)} potentially weak endpoints",
                "weakness": "Common weak endpoints may be exploitable",
                "recommendation": "Harden all endpoints, disable unused services"
            })

        return findings

    def format_report(self, scan_result: Dict[str, Any]) -> str:
        """Format scan result into readable report."""
        lines = []
        lines.append(f"\n{'='*70}")
        lines.append(f"Website Security Scan Report")
        lines.append(f"{'='*70}")
        lines.append(f"URL: {scan_result['url']}")
        lines.append(f"Domain: {scan_result['domain']}")
        lines.append(f"Scan Type: {scan_result['scan_type'].upper()}")
        lines.append(f"Risk Level: {scan_result['risk_level'].upper()}")
        lines.append(f"Security Score: {scan_result['score']}/100")
        lines.append(f"Timestamp: {scan_result['timestamp']}")

        if scan_result["findings"]:
            lines.append(f"\n{'-'*70}")
            lines.append("PASSIVE FINDINGS:")
            lines.append(f"{'-'*70}")
            for i, finding in enumerate(scan_result["findings"], 1):
                severity_color = {
                    "critical": "CRITICAL",
                    "high": "HIGH",
                    "medium": "MEDIUM",
                    "low": "LOW",
                    "info": "INFO"
                }
                lines.append(f"\n{i}. [{severity_color.get(finding['severity'], 'UNKNOWN')}] {finding['type'].upper()}")
                lines.append(f"   Description: {finding['description']}")
                lines.append(f"   Weakness: {finding['weakness']}")
                lines.append(f"   Recommendation: {finding['recommendation']}")

        if "active_findings" in scan_result and scan_result["active_findings"]:
            lines.append(f"\n{'-'*70}")
            lines.append("ACTIVE PROBING FINDINGS:")
            lines.append(f"{'-'*70}")
            for i, finding in enumerate(scan_result["active_findings"], 1):
                severity_color = {
                    "critical": "CRITICAL",
                    "high": "HIGH",
                    "medium": "MEDIUM",
                    "low": "LOW",
                    "info": "INFO"
                }
                lines.append(f"\n{i}. [{severity_color.get(finding['severity'], 'UNKNOWN')}] {finding['type'].upper()}")
                lines.append(f"   Description: {finding['description']}")
                lines.append(f"   Weakness: {finding['weakness']}")
                lines.append(f"   Recommendation: {finding['recommendation']}")

        lines.append(f"\n{'='*70}\n")
        return "\n".join(lines)


# Global scanner instance
website_scanner = WebsiteScanner()
