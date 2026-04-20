"""
Website Security Scanner

Analyze websites for security weaknesses including:
- Domain analysis (passive)
- SSL/TLS and header checks (active - requires permission)
- Known vulnerabilities (passive)
- Security misconfigurations based on real responses (active - requires permission)
"""

import socket
import ssl
from typing import Dict, Any, List
from urllib.parse import urlparse
from urllib import request, error
from datetime import datetime

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
            return (parsed.netloc or url).split(":")[0]
        except Exception:
            return url

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has scheme."""
        if url.startswith(("http://", "https://")):
            return url
        return f"https://{url}"

    def _request_url(self, url: str, timeout: int = 5) -> tuple[int, dict]:
        """Request URL and return (status, headers)."""
        req = request.Request(url, method="GET", headers={"User-Agent": "WhiteCellScanner/1.0"})
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers.items())

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
        normalized_url = self._normalize_url(url)

        # Try to detect SSL/TLS issues
        ssl_info = self._check_ssl(domain)
        if ssl_info:
            results["active_findings"].extend(ssl_info)
            results["score"] -= 10 * len(ssl_info)

        # Check actual response headers
        headers_analysis = self._analyze_security_headers(normalized_url)
        if headers_analysis:
            results["active_findings"].extend(headers_analysis)
            results["score"] -= 5 * len(headers_analysis)

        # Probe weak endpoints and report only reachable ones
        weak_endpoints = self._probe_common_endpoints(normalized_url)
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
        """Check SSL/TLS connectivity and version."""
        findings = []

        context = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    protocol = tls_sock.version() or "unknown"
                    cert = tls_sock.getpeercert()
                    not_after = cert.get("notAfter") if cert else None

            if protocol in {"TLSv1", "TLSv1.1"}:
                findings.append({
                    "type": "weak_tls_version",
                    "severity": "high",
                    "description": f"Server negotiated legacy TLS version: {protocol}",
                    "weakness": "Outdated transport security protocol",
                    "recommendation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+"
                })
            else:
                findings.append({
                    "type": "ssl_tls_ok",
                    "severity": "info",
                    "description": f"TLS connectivity verified ({protocol})",
                    "weakness": "None observed",
                    "recommendation": "Continue certificate lifecycle monitoring"
                })

            if not not_after:
                findings.append({
                    "type": "cert_metadata_unavailable",
                    "severity": "low",
                    "description": "Certificate expiry metadata was not available",
                    "weakness": "Unable to validate certificate expiry date",
                    "recommendation": "Validate certificate details with your certificate authority"
                })
        except Exception as e:
            findings.append({
                "type": "ssl_connection_error",
                "severity": "high",
                "description": f"TLS check failed for {domain}: {e}",
                "weakness": "TLS handshake/connectivity problem",
                "recommendation": "Verify TLS certificate chain, host configuration, and network path"
            })

        return findings

    def _analyze_security_headers(self, url: str) -> List[Dict[str, Any]]:
        """Analyze actual HTTP response headers for security controls."""
        findings = []

        try:
            _, headers = self._request_url(url, timeout=6)
        except Exception as e:
            return [{
                "type": "http_request_failed",
                "severity": "medium",
                "description": f"Could not retrieve headers from {url}: {e}",
                "weakness": "Unable to validate response headers",
                "recommendation": "Verify host availability and retry scan"
            }]

        normalized = {k.lower(): v for k, v in headers.items()}
        expected = {
            "content-security-policy": "Add a restrictive Content-Security-Policy",
            "x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN",
            "x-content-type-options": "Set X-Content-Type-Options to nosniff",
            "strict-transport-security": "Enable HSTS with a suitable max-age",
        }
        for header, recommendation in expected.items():
            if header not in normalized:
                findings.append({
                    "type": "missing_security_header",
                    "severity": "medium",
                    "description": f"Missing header: {header}",
                    "weakness": "Browser-side protection is reduced",
                    "recommendation": recommendation
                })

        return findings

    def _probe_common_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Probe common weak endpoints and report only reachable responses."""
        findings = []
        base = base_url.rstrip("/")
        reachable = []

        for endpoint in self.common_weak_endpoints[:10]:
            target = f"{base}{endpoint}"
            try:
                status, _ = self._request_url(target, timeout=3)
                # Consider 2xx/3xx/401/403 as endpoint exposure signals.
                if status < 400 or status in {401, 403}:
                    reachable.append((endpoint, status))
            except error.HTTPError as e:
                if e.code in {401, 403}:
                    reachable.append((endpoint, e.code))
            except Exception:
                continue

        for endpoint, status in reachable[:5]:
            findings.append({
                "type": "reachable_sensitive_endpoint",
                "severity": "medium",
                "description": f"Endpoint {endpoint} is reachable (HTTP {status})",
                "weakness": f"Potentially exposed endpoint: {endpoint}",
                "recommendation": f"Restrict or harden {endpoint}"
            })

        if reachable:
            findings.insert(0, {
                "type": "endpoint_discovery",
                "severity": "high",
                "description": f"Found {len(reachable)} reachable sensitive endpoints",
                "weakness": "Sensitive endpoints are externally reachable",
                "recommendation": "Review exposure and enforce authentication/network restrictions"
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
