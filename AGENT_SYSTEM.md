# White Cell Agent System Documentation

## Overview

The White Cell Agent System enables autonomous, distributed security monitoring and threat prevention across multiple machines. Agents run in the background, continuously performing security checks, detecting threats, and taking preventive action using optional AI-powered decision making via the GROQ API.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    White Cell Agents                    │
├─────────────────────────────────────────────────────────┤
│  Agent Manager          │ Individual Agents             │
│  ├─ create_agent()      │ ├─ _run_loop()               │
│  ├─ start_agent()       │ ├─ _perform_checks()         │
│  ├─ stop_agent()        │ ├─ _handle_threat_detection()│
│  ├─ get_status()        │ └─ _attempt_prevention()     │
│  └─ export_all_data()   │                              │
├─────────────────────────────────────────────────────────┤
│  Security Checks          │ Integration Modules         │
│  ├─ ProcessMonitoring     │ ├─ Detection Engine        │
│  ├─ PortMonitoring        │ ├─ Risk Calculator         │
│  ├─ FilePermission        │ ├─ GROQ AI Client          │
│  ├─ SystemLogs            │ ├─ Config Manager          │
│  ├─ FirewallCheck         │ └─ Logging System          │
│  └─ MalwareScan           │                             │
└─────────────────────────────────────────────────────────┘
```

## Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure GROQ API (Optional but Recommended)

The agent system works without GROQ, but AI-powered threat prevention requires a GROQ API key:

```bash
python main.py
# In the CLI, run: agent configure
```

Or set environment variable:
```bash
set GROQ_API_KEY=your_api_key_here
```

Get your key from: https://console.groq.com/keys

## Quick Start

### Using the CLI

```bash
python main.py
```

Then use these commands:

```
agent deploy <name> [interval]    # Start a new agent
agent stop <name>                 # Stop an agent
agent status                       # View all agent status
agent threats <name> [limit]      # View threats from an agent
agent configure                   # Set GROQ API key
```

### Example Usage

```
> agent deploy production-server 60
✓ Agent 'production-server' deployed and running!
✓ Check interval: 60 seconds

> agent status
[Agent Status Table showing running agents and statistics]

> agent threats production-server
[Showing recent threats detected by the agent]
```

### Programmatic Usage

```python
from whitecell.agent import agent_manager

# Create an agent
agent = agent_manager.create_agent("my-server", check_interval=60)

# Register callbacks
def on_threat(threat_data):
    print(f"Threat detected: {threat_data}")

agent.register_threat_callback(on_threat)

# Start monitoring
agent_manager.start_agent("my-server")

# Check status
status = agent_manager.get_agent_status("my-server")
print(f"Running: {status['running']}")
print(f"Threats detected: {status['threats_detected']}")

# View recent threats
threats = agent.get_recent_threats(10)

# Stop when done
agent_manager.stop_agent("my-server")
```

## Security Checks

The agent system performs these security checks:

### 1. Process Monitoring
- Detects suspicious processes (cmd.exe, powershell.exe, wscript.exe, etc.)
- Monitors process creation and termination
- Flags unusual process activity

### 2. Port Monitoring
- Scans for open network ports
- Identifies suspicious listening services
- Detects backdoor ports (4444, 5555, 6666, etc.)

### 3. File Permission Checks
- Verifies critical file permissions
- Detects world-writable critical files
- Identifies permission escalation attempts

### 4. System Log Analysis
- Scans system logs for suspicious patterns
- Detects failed login attempts
- Identifies malware indicators

### 5. Firewall Status
- Verifies firewall is enabled
- Checks firewall rules
- Alerts if firewall is disabled

### 6. Malware Detection (Simulated)
- Simulates malware scanning
- Checks for suspicious file locations
- Detects unusual file sizes

## Configuration

Configuration is stored in `~/.whitecell/config.json`:

```json
{
  "groq_api_key": "your_api_key_or_null",
  "agent_enabled": true,
  "agent_auto_start": false,
  "security_checks": [
    "malware_scan",
    "port_monitoring",
    "process_monitoring",
    "firewall_check",
    "system_logs"
  ],
  "check_interval": 60,
  "max_threats": 10,
  "threat_threshold": 50
}
```

### Configuration Keys

| Key | Type | Description |
|-----|------|-------------|
| `groq_api_key` | string | GROQ API key for AI-powered decisions |
| `agent_enabled` | bool | Enable/disable agent system |
| `agent_auto_start` | bool | Auto-start agents on login |
| `security_checks` | list | Which checks to perform |
| `check_interval` | int | Seconds between checks |
| `max_threats` | int | Max stored threat records |
| `threat_threshold` | int | Risk score threshold for prevention (0-100) |

## Threat Prevention

### Built-in Prevention Actions

When a threat is detected with a risk score above the threshold:

| Threat Type | Prevention Action |
|-------------|------------------|
| Ransomware | Isolate process, enable file recovery |
| Malware | Quarantine file, run antivirus |
| Exploit | Patch service, disconnect network |
| DDoS | Rate-limit connection, block IP |
| Phishing | Block email domain, alert user |
| Data Breach | Isolate system, enable encryption |
| Lateral Movement | Restrict network, enable MFA |
| Credential Theft | Reset credentials, enable 2FA |
| Supply Chain | Quarantine package, verify source |

### AI-Powered Prevention (with GROQ)

When GROQ is configured, agents:

1. **Analyze threats** - GROQ provides context and risk assessment
2. **Recommend actions** - AI suggests specific prevention steps
3. **Make decisions** - Agents execute prevention based on AI confidence
4. **Learn threats** - System adapts to new threat patterns

### Risk Scoring

Threats are scored 0-100:

- **0-30**: Low Risk - Monitor only
- **30-70**: Medium Risk - Report and log
- **70-100**: High Risk - Attempt prevention

## Agent Monitoring

### View Agent Status

```
agent status
```

Shows:
- Total agents running
- Total security checks performed
- Total threats detected
- Total threats prevented/blocked

### View Agent Threats

```
agent threats <agent-id> [limit]
```

Shows recent threats for a specific agent:
- Timestamp
- Threat type
- Risk score
- Prevention status
- Threat details

### Export Data

```python
# Export all data
agent_manager.export_all_data("security_report.json")

# Export specific agent data
agent = agent_manager.agents["my-agent"]
json_data = agent.export_threats()
```

## Multi-Machine Deployment

### Local Machine

```python
# Create local agent for this machine
from whitecell.agent import agent_manager

agent = agent_manager.create_agent("local-monitor")
agent_manager.start_agent("local-monitor")
```

### Remote/Multiple Machines

1. Deploy White Cell on each machine
2. Configure GROQ API key on each
3. Run agent on each machine:

```bash
python -c "
from whitecell.agent import agent_manager
agent = agent_manager.create_agent('$(hostname)')
agent_manager.start_agent('$(hostname)')
import time
while True: time.sleep(60)
"
```

### Monitor All Machines Centrally

Collect logs from all agents:

```bash
# On central server
python multi_agent_monitor.py  # Collects from all machines
```

## GROQ API Integration

### Enabling AI-Powered Threat Prevention

1. Get free API key: https://console.groq.com/keys
2. Configure in White Cell:
   ```
   agent configure
   ```
3. Enter your API key

### AI Features Enabled

Once configured:
- **Threat Analysis** - GROQ analyzes detected threats
- **Risk Assessment** - AI provides risk confidence
- **Prevention Decisions** - AI recommends prevention actions
- **Explanations** - Get AI-powered threat explanations

### Example with GROQ

```python
from whitecell.groq_client import groq_client

# Analyze a threat
analysis = groq_client.analyze_threat(
    "Ransomware detected in SMB traffic",
    indicators=["file_encryption", "ransom_note", "payment_demand"]
)

# Get prevention recommendation
if analysis.get("should_prevent"):
    print("AI recommends prevention action")
    print(analysis.get("recommended_actions"))
```

## Troubleshooting

### Agent Not Detecting Threats

1. Check if checks are enabled in config:
   ```python
   from whitecell.config import get_config_value
   checks = get_config_value("security_checks")
   print(checks)
   ```

2. Check agent status:
   ```
   agent status
   ```

3. Verify check interval isn't too long

### GROQ API Not Working

1. Verify API key:
   ```python
   from whitecell.groq_client import groq_client
   print(groq_client.is_configured())
   ```

2. Check API key format
3. Verify internet connection
4. Check GROQ API status: https://status.groq.com

### High CPU/Memory Usage

1. Increase check interval:
   ```python
   from whitecell.config import set_config_value
   set_config_value("check_interval", 300)  # 5 minutes
   ```

2. Disable unnecessary checks:
   ```python
   from whitecell.config import set_config_value
   checks = ["malware_scan", "port_monitoring"]
   set_config_value("security_checks", checks)
   ```

## Performance Considerations

### Recommended Settings

| Environment | Check Interval | Checks | Notes |
|-------------|----------------|--------|-------|
| Development | 60s | All | Full monitoring |
| Production | 300s | Critical only | Minimal overhead |
| Edge Device | 600s | Lightweight | Battery-friendly |

### Resource Usage

- **Memory**: ~20-50MB per agent
- **CPU**: <1% average
- **Disk**: ~1MB per 100 threat logs
- **Network**: ~1KB per check

## Security Best Practices

1. **Rotate API Keys** - Update GROQ keys regularly
2. **Restrict Config Access** - Config file is 0600 permissions
3. **Monitor Logs** - Review threat logs regularly
4. **Update Checks** - Keep threat signatures current
5. **Test Prevention** - Verify prevention actions in safe environment
6. **Audit Agents** - Review agent activity logs
7. **Isolate Critical Systems** - Don't run untrusted agents
8. **Network Segmentation** - Isolate agent networks

## Advanced Usage

### Custom Security Checks

```python
from whitecell.security_checks import SecurityCheck

class CustomCheck(SecurityCheck):
    def run(self):
        # Your custom security logic
        return {
            "check": self.name,
            "status": "success",
            "threats": []
        }
```

### Custom Prevention Actions

```python
# In agent system
def custom_prevention(threat_type):
    # Your prevention logic
    pass
```

### Callbacks and Events

```python
def on_threat_detected(threat_data):
    # Handle threat
    pass

def on_prevention(threat_type, action):
    # Handle prevention
    pass

agent.register_threat_callback(on_threat_detected)
agent.register_prevention_callback(on_prevention)
```

## FAQ

**Q: Do agents require internet?**
A: No, but GROQ AI features do. Agents work offline with built-in logic.

**Q: Can agents communicate with each other?**
A: Not directly. Use central monitoring server for coordination.

**Q: How many agents can run simultaneously?**
A: Depends on system resources, typically 5-10 per machine.

**Q: What happens if an agent crashes?**
A: It stops monitoring. Use system service/cron to auto-restart.

**Q: Can I run agents in containers?**
A: Yes, they work in Docker, Kubernetes, etc.

## Support & Documentation

- **Repository**: https://github.com/mpho0sekati/White-Cell
- **Issues**: Github Issues
- **Documentation**: See README.md and code comments

## License

White Cell Agent System is part of the White Cell cybersecurity project.
