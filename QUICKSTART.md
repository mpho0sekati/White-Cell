# White Cell V1.1 - Quick Start Guide

## Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup Steps

1. **Navigate to project directory:**
   ```bash
   cd /path/to/White-Cell
   ```

2. **Create/activate virtual environment (if not already done):**
   ```bash
   # Create a new virtual environment
   python -m venv .venv

   # Activate on macOS/Linux
   source .venv/bin/activate

   # Activate on Windows (PowerShell)
   .venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running White Cell

### Basic Usage
```bash
python main.py
```

### Demo All V1.1 Features
```bash
python demo_v1_1.py
```

## Interactive Commands

Once inside the CLI:

### Help
```
WhiteCell> help
```
Displays all available commands and usage information.

### Check Status
```
WhiteCell> status
```
Shows current system state, command mode status, and session logs count.

### View Threat Logs
```
WhiteCell> logs
```
Displays the last 10 detected threats with risk assessments from JSONL logs.

### Optional Groq Explain
```
WhiteCell> explain suspicious login from unknown ASN
```
Uses optional Groq wiring if enabled and configured (currently placeholder responses).

### Optional Groq Strategy
```
WhiteCell> strategy ransomware
```
Uses optional Groq strategy wiring for a threat type (currently placeholder responses).

### Clear Crisis Mode
```
WhiteCell> clear
```
Deactivates Command Mode if it's currently active.

### Exit Application
```
WhiteCell> exit
```
Safely exit the application.

## Example Scenarios

### Scenario 1: Ransomware Detected
```
WhiteCell> We have a ransomware attack on our main server!

━━━━━━━━━━━━━━━ THREAT DETECTED ━━━━━━━━━━━━━━━
Threat Type: RANSOMWARE
Trigger: "ransomware"
Risk Level: HIGH (100/100)
━━━━━━━━━ COMMAND MODE ACTIVE ━━━━━━━━━━

Suggested Actions:
• IMMEDIATELY isolate affected systems from the network
• Activate incident response team
• Contact cybersecurity experts
• Begin forensic data collection
• Notify management and legal if data breach suspected
• Preserve evidence for investigation
```

### Scenario 2: Phishing Email
```
WhiteCell> Got a suspicious phishing email asking to verify credentials

━━━━━━━━━━━━━━━ THREAT DETECTED ━━━━━━━━━━━━━━━
Threat Type: PHISHING
Trigger: "phishing"
Risk Level: MEDIUM (48/100)
━━━━━━━━━ COMMAND MODE ACTIVE ━━━━━━━━━━

Suggested Actions:
• Enable enhanced logging and monitoring
• Prepare incident response procedures
• Alert security team
• Isolate potentially affected systems if necessary
```

### Scenario 3: Safe Query
```
WhiteCell> How can I improve my password security?

[cyan]You said:[/cyan] How can I improve my password security?
```

## Log File Location

Threat logs are automatically saved to:
```
<project_root>/logs/threats.jsonl
```

The application computes this path at runtime from the repository root (`whitecell/engine.py`) and writes append-only JSON Lines (JSONL).

Logging lifecycle behavior:
- Structured records include a `schema_version` field for compatibility.
- Files rotate automatically when size thresholds are reached.
- Retention keeps only the most recent rotated files.

Each log entry contains:
- Timestamp (ISO format)
- Threat type
- Triggered keyword
- Original user input
- Risk score (0-100)
- Risk level (low/medium/high)
- Estimated financial loss
- POPIA exposure status

## Risk Score Interpretation

| Range | Level | Color | Action |
|-------|-------|-------|--------|
| 0-33 | Low | Green | Monitor and document |
| 34-66 | Medium | Yellow | Increase logging, prepare procedures |
| 67-100 | High | Red | Immediate action required |

## Supported Threat Types

1. **Ransomware** - File encryption/system lockdown attacks
2. **Malware** - Malicious software including viruses, trojans, worms
3. **Data Breach** - Unauthorized data access or exfiltration
4. **Phishing** - Social engineering attacks via email/links
5. **Exploit** - Zero-day or known vulnerability exploitation
6. **Lateral Movement** - Privilege escalation and network traversal
7. **Denial of Service** - DDoS and resource exhaustion attacks

## Environment Variables

To use optional Groq commands (`explain`, `strategy`), set one of the following:
```bash
# macOS/Linux
export GROQ_API_KEY=your_api_key_here

# Windows (PowerShell)
$env:GROQ_API_KEY="your_api_key_here"
```

Feature flag (enabled by default):
```bash
# Disable Groq commands
export WHITECELL_ENABLE_GROQ=0
```

## Troubleshooting

### Import Errors
Ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Logging Directory Not Created
The `logs/` directory is created automatically. If it fails, create manually:
```bash
mkdir logs
```

### Unicode Display Issues
Update Python and ensure terminal supports UTF-8:
```bash
# Check Python version
python --version

# On Windows, set code page to UTF-8
chcp 65001
```

## Features Overview

### ✅ Implemented (V1.1)
- Deterministic threat detection
- Risk scoring (0-100 scale)
- Financial loss estimation
- POPIA exposure detection
- Command Mode with suggested actions
- Rich terminal formatting
- Structured threat logging to JSONL with schema versioning
- Log rotation and retention policy
- Interactive CLI with help system
- Session state management

### 🔄 Planned (V1.2+)
- Production Groq API integration for real AI reasoning (current commands are placeholders)
- Machine learning-based detection
- Custom threat signatures
- Web dashboard
- Webhook notifications
- SIEM integration
- Automated response playbooks
- Multi-user sessions
- Compliance reporting

## Performance Notes

- Threat detection: < 1ms per query
- Risk scoring: < 5ms per threat
- Log writing: < 50ms (depends on disk I/O)
- CLI startup: < 500ms

## Support & Documentation

- See `V1_1_IMPLEMENTATION.md` for full feature documentation
- See `README.md` for project overview
- See `demo_v1_1.py` for code examples

## License & Attribution

White Cell Project - Cybersecurity Assistant
Built for educational and enterprise security purposes.
