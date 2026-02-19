"""System guard utilities for host-level defensive telemetry."""

from __future__ import annotations

import platform
import socket
import subprocess
from datetime import datetime

SUSPICIOUS_PROCESS_KEYWORDS = (
    "mimikatz",
    "meterpreter",
    "cobalt",
    "empire",
    "beacon",
    "njrat",
)


def _run_command(command: list[str]) -> str:
    """Run a system command and return stdout safely."""

    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        return result.stdout or ""
    except OSError:
        return ""


def _collect_process_names() -> list[str]:
    """Collect process names in a cross-platform way."""

    if platform.system().lower().startswith("win"):
        output = _run_command(["tasklist"])
    else:
        output = _run_command(["ps", "-eo", "comm"])

    names: list[str] = []
    for line in output.splitlines():
        normalized = line.strip().lower()
        if normalized and not normalized.startswith(("image name", "command")):
            names.append(normalized)
    return names


def _count_established_connections() -> int:
    """Count active TCP established connections from netstat output."""

    output = _run_command(["netstat", "-an"])
    count = 0
    for line in output.splitlines():
        if "ESTABLISHED" in line.upper():
            count += 1
    return count


def scan_system() -> dict:
    """Run a lightweight host scan and return structured guard findings."""

    processes = _collect_process_names()
    established_connections = _count_established_connections()

    suspicious = sorted(
        {
            name
            for name in processes
            for keyword in SUSPICIOUS_PROCESS_KEYWORDS
            if keyword in name
        }
    )

    findings: list[dict] = []
    if suspicious:
        findings.append(
            {
                "signal": "suspicious_processes",
                "severity": "high",
                "details": f"Potentially malicious tools running: {', '.join(suspicious)}",
            }
        )

    if established_connections > 400:
        findings.append(
            {
                "signal": "high_connection_volume",
                "severity": "medium",
                "details": f"Host has {established_connections} established TCP connections.",
            }
        )

    risk_level = "high" if any(item["severity"] == "high" for item in findings) else "medium" if findings else "low"

    recommendation = (
        "Isolate endpoint and run incident response triage."
        if risk_level == "high"
        else "Review telemetry and harden exposed services."
        if risk_level == "medium"
        else "System appears healthy; continue monitoring."
    )

    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "established_connections": established_connections,
        "risk_level": risk_level,
        "findings": findings,
        "recommendation": recommendation,
    }
