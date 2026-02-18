"""
White Cell Security Checks

This module implements local security scanning functionality.
Checks for common security issues on the system.

Author: White Cell Project
"""

import os
import sys
import subprocess
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


class SecurityCheck:
    """Base class for security checks."""

    def __init__(self, name: str, description: str):
        """
        Initialize a security check.

        Args:
            name: Check name
            description: Check description
        """
        self.name = name
        self.description = description
        self.timestamp = datetime.now()

    def run(self) -> Dict[str, Any]:
        """
        Run the security check.

        Returns:
            Dictionary with check results
        """
        raise NotImplementedError


class ProcessMonitoringCheck(SecurityCheck):
    """Monitor running processes for suspicious activity."""

    def __init__(self):
        super().__init__(
            "Process Monitoring",
            "Monitors running processes for suspicious activity"
        )

    def run(self) -> Dict[str, Any]:
        """Run process monitoring check."""
        try:
            if sys.platform == "win32":
                return self._check_windows()
            else:
                return self._check_unix()
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    def _check_windows(self) -> Dict[str, Any]:
        """Check Windows processes."""
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True,
                timeout=10
            )

            suspicious_processes = [
                "cmd.exe",
                "powershell.exe",
                "wscript.exe",
                "cscript.exe"
            ]

            threats = []
            for proc in suspicious_processes:
                if proc in result.stdout:
                    threats.append(f"Suspicious process detected: {proc}")

            return {
                "check": self.name,
                "status": "success",
                "threats": threats,
                "process_count": result.stdout.count("\n")
            }
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    def _check_unix(self) -> Dict[str, Any]:
        """Check Unix processes."""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10
            )

            suspicious_patterns = ["nc ", "bash -i", "/dev/tcp"]

            threats = []
            for line in result.stdout.split("\n"):
                for pattern in suspicious_patterns:
                    if pattern in line:
                        threats.append(f"Suspicious process pattern: {pattern}")

            return {
                "check": self.name,
                "status": "success",
                "threats": threats,
                "process_count": result.stdout.count("\n")
            }
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }


class PortMonitoringCheck(SecurityCheck):
    """Monitor open network ports."""

    def __init__(self):
        super().__init__(
            "Port Monitoring",
            "Monitors open network ports for suspicious services"
        )

    def run(self) -> Dict[str, Any]:
        """Run port monitoring check."""
        try:
            if sys.platform == "win32":
                return self._check_windows()
            else:
                return self._check_unix()
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    def _check_windows(self) -> Dict[str, Any]:
        """Check Windows open ports."""
        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=10
            )

            suspicious_ports = ["4444", "5555", "6666", "7777", "8888"]
            threats = []

            for port in suspicious_ports:
                if port in result.stdout:
                    threats.append(f"Suspicious port open: {port}")

            return {
                "check": self.name,
                "status": "success",
                "threats": threats,
                "open_ports_count": result.stdout.count("ESTABLISHED")
            }
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    def _check_unix(self) -> Dict[str, Any]:
        """Check Unix open ports."""
        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=10
            )

            suspicious_ports = ["4444", "5555", "6666", "7777"]
            threats = []

            for port in suspicious_ports:
                if port in result.stdout:
                    threats.append(f"Suspicious port open: {port}")

            return {
                "check": self.name,
                "status": "success",
                "threats": threats,
                "open_ports_count": result.stdout.count("ESTABLISHED")
            }
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }


class FilePermissionCheck(SecurityCheck):
    """Check critical file permissions."""

    def __init__(self):
        super().__init__(
            "File Permissions",
            "Checks critical file permissions for security issues"
        )

    def run(self) -> Dict[str, Any]:
        """Run file permission check."""
        try:
            threats = []
            critical_paths = self._get_critical_paths()

            for path in critical_paths:
                if os.path.exists(path):
                    stat_info = os.stat(path)
                    # Check if world-writable
                    if stat_info.st_mode & 0o002:
                        threats.append(f"World-writable critical file: {path}")
                    # Check if group-writable
                    if stat_info.st_mode & 0o020:
                        threats.append(f"Group-writable critical file: {path}")

            return {
                "check": self.name,
                "status": "success",
                "threats": threats,
                "files_checked": len(critical_paths)
            }
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    @staticmethod
    def _get_critical_paths() -> List[str]:
        """Get list of critical paths to check."""
        if sys.platform == "win32":
            return [
                "C:\\Windows\\System32",
                os.path.expanduser("~\\AppData\\Local\\Temp"),
            ]
        else:
            return [
                "/etc",
                "/root",
                "/home"
            ]


class SystemLogsCheck(SecurityCheck):
    """Check system logs for suspicious activity."""

    def __init__(self):
        super().__init__(
            "System Logs",
            "Analyzes system logs for suspicious activity"
        )

    def run(self) -> Dict[str, Any]:
        """Run system logs check."""
        try:
            threats = []
            suspicious_keywords = [
                "unauthorized",
                "failed login",
                "malware",
                "exploit",
                "attack"
            ]

            if sys.platform == "win32":
                return self._check_windows_logs(suspicious_keywords)
            else:
                return self._check_unix_logs(suspicious_keywords)
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    @staticmethod
    def _check_windows_logs(keywords: List[str]) -> Dict[str, Any]:
        """Check Windows event logs."""
        # Simplified check - in production would query Event Viewer
        return {
            "check": "System Logs",
            "status": "success",
            "threats": [],
            "note": "Windows event log monitoring requires elevated privileges"
        }

    @staticmethod
    def _check_unix_logs(keywords: List[str]) -> Dict[str, Any]:
        """Check Unix system logs."""
        threats = []
        log_files = ["/var/log/auth.log", "/var/log/syslog"]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", errors="ignore") as f:
                        for line in f.readlines()[-100:]:  # Last 100 lines
                            for keyword in keywords:
                                if keyword.lower() in line.lower():
                                    threats.append(f"Found '{keyword}' in logs")
                except PermissionError:
                    threats.append(f"Permission denied reading {log_file}")

        return {
            "check": "System Logs",
            "status": "success",
            "threats": threats,
            "files_checked": len(log_files)
        }


class FirewallCheck(SecurityCheck):
    """Check firewall status."""

    def __init__(self):
        super().__init__(
            "Firewall Check",
            "Checks firewall status and rules"
        )

    def run(self) -> Dict[str, Any]:
        """Run firewall check."""
        try:
            if sys.platform == "win32":
                return self._check_windows_firewall()
            else:
                return self._check_unix_firewall()
        except Exception as e:
            return {
                "check": self.name,
                "status": "error",
                "message": str(e),
                "threats": []
            }

    @staticmethod
    def _check_windows_firewall() -> Dict[str, Any]:
        """Check Windows Firewall status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-NetFirewallProfile"],
                capture_output=True,
                text=True,
                timeout=10
            )

            threats = []
            if "Enabled : False" in result.stdout:
                threats.append("Windows Firewall is disabled")

            return {
                "check": "Firewall Check",
                "status": "success",
                "threats": threats,
                "note": "Status check completed"
            }
        except Exception as e:
            return {
                "check": "Firewall Check",
                "status": "warning",
                "message": str(e),
                "threats": []
            }

    @staticmethod
    def _check_unix_firewall() -> Dict[str, Any]:
        """Check Unix firewall status."""
        threats = []
        try:
            result = subprocess.run(
                ["sudo", "ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "inactive" in result.stdout.lower():
                threats.append("UFW firewall is inactive")
        except Exception:
            pass

        return {
            "check": "Firewall Check",
            "status": "success",
            "threats": threats,
            "note": "Status check completed"
        }


class MalwareScanCheck(SecurityCheck):
    """Simulate malware scanning."""

    def __init__(self):
        super().__init__(
            "Malware Scan",
            "Simulates malware scanning (checks for common signatures)"
        )

    def run(self) -> Dict[str, Any]:
        """Run malware scan check."""
        threats = []

        # Check for common malware directories/files
        suspicious_locations = [
            Path.home() / ".ssh" / "known_hosts",
            Path.home() / ".bash_history",
            Path.home() / ".config"
        ]

        for location in suspicious_locations:
            if location.exists():
                try:
                    # Simulate scan by checking file size
                    size = location.stat().st_size
                    if size > 10000000:  # > 10MB
                        threats.append(f"Unusually large file: {location}")
                except Exception:
                    pass

        return {
            "check": self.name,
            "status": "success",
            "threats": threats,
            "locations_scanned": len(suspicious_locations)
        }


def run_all_checks() -> List[Dict[str, Any]]:
    """
    Run all security checks.

    Returns:
        List of check results
    """
    checks = [
        ProcessMonitoringCheck(),
        PortMonitoringCheck(),
        FilePermissionCheck(),
        SystemLogsCheck(),
        FirewallCheck(),
        MalwareScanCheck(),
    ]

    results = []
    for check in checks:
        results.append(check.run())

    return results


def get_check_by_name(name: str) -> Dict[str, Any]:
    """
    Run a specific check by name.

    Args:
        name: Check name

    Returns:
        Check result
    """
    check_map = {
        "process_monitoring": ProcessMonitoringCheck(),
        "port_monitoring": PortMonitoringCheck(),
        "file_permission": FilePermissionCheck(),
        "system_logs": SystemLogsCheck(),
        "firewall": FirewallCheck(),
        "malware_scan": MalwareScanCheck(),
    }

    if name in check_map:
        return check_map[name].run()

    return {
        "status": "error",
        "message": f"Unknown check: {name}",
        "threats": []
    }
