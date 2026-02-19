# White Cell V1.1 - Quick Start Guide

## Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup Steps

1. **Navigate to project directory:**
   ```bash
   # From your shell, change to the project root (where README.md lives)
   cd /path/to/whitecell_project
   ```

2. **Create/activate virtual environment (if not already done):**
   ```bash
   # On Windows
   venv\Scripts\activate
   
   # Or create new venv
   python -m venv venv
   venv\Scripts\activate
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

### Quick Reference with Aliases
```
h/? - help              st - status           l - logs              t - threats
a - analyze             e - export            s - search            c - clear
q - exit
```

### Core Commands
```
WhiteCell> help                 # Show all commands
WhiteCell> exit                 # Exit application
WhiteCell> status               # Show system status
WhiteCell> clear                # Clear Command Mode
```

### Threat Management
```
WhiteCell> threats              # View all threat types with descriptions
WhiteCell> logs                 # Display last 10 threat logs
WhiteCell> logs 20              # Display last 20 threat logs
WhiteCell> search ransomware    # Find all ransomware threats
WhiteCell> search phishing      # Find all phishing threats
WhiteCell> analyze ransomware   # Get detailed analysis of ransomware
WhiteCell> analyze phishing     # Get detailed analysis of phishing
WhiteCell> export csv           # Export logs as CSV file
WhiteCell> export json          # Export logs as JSON file
```

### Using Aliases (Faster!)
```
WhiteCell> h                    # Same as 'help'
WhiteCell> st                   # Same as 'status'
WhiteCell> l 15                 # Show last 15 logs
WhiteCell> t                    # Show threat types
WhiteCell> a malware            # Analyze malware threats
WhiteCell> s data_breach        # Search for data breach incidents
WhiteCell> e csv                # Export as CSV
WhiteCell> c                    # Clear command mode
WhiteCell> q                    # Quit application
```

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

Threat logs are automatically saved to the `logs/` directory in the project root (for example `logs/threats.json`).
The application will create the `logs/` folder if it does not already exist.

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

To use Groq AI features (future), set:
```bash
set GROQ_API_KEY=your_api_key_here
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
- Threat logging to JSON
- Interactive CLI with help system
- Session state management

### 🔄 Planned (V1.2+)
- Groq API integration for AI reasoning
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
