# White Cell

White Cell is a SOC-first cybersecurity CLI for detection, investigation, and governed response workflows.

## What It Solves

- Fast alert triage from the terminal
- Consistent analyst workflow: triage -> investigate -> respond
- Guardrails for risky actions through role-based access and approvals
- Optional AI assistance (Groq and CrewAI) without requiring cloud-only usage

## Core Capabilities

| Area | Capability |
|---|---|
| SOC Workflow | `triage`, `investigate`, `respond`, `soc run` |
| Governance | RBAC, approval queue, audit logging |
| Scanning | Passive website analysis, allowlisted active probing |
| Agent Ops | Background agents, live status, threat logs |
| UX | Rich CLI, dashboard, peek window, command aliases |

## Architecture At A Glance

```text
CLI (whitecell/cli_enhanced.py)
  -> Engine (whitecell/engine.py)
  -> Detection + Risk (whitecell/detection.py, whitecell/risk.py)
  -> Governance (whitecell/governance.py)
  -> Agent System (whitecell/agent.py)
  -> Website Scanner (whitecell/website_scanner.py)
  -> AI Providers (whitecell/groq_client.py, whitecell/crew.py)
  -> Config (whitecell/config.py)
```

## Installation

```bash
git clone https://github.com/mpho0sekati/White-Cell.git
cd White-Cell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## SOC-First Commands

```text
triage <alert_text>
investigate <threat_type|log_index>
respond recommend <incident>
respond execute <action> <target>
soc run <alert_text> [--execute <action> <target>]
```

Example:

```text
soc run suspicious powershell and credential dumping --execute block_ip 10.0.0.8
```

## Governance Commands

```text
governance status
governance role <admin|analyst|viewer>
governance policy <add|remove> <action>
governance approvals list
governance approvals approve <id>
governance approvals reject <id>
```

## Website Scanning Safety Model

- Passive scans are always available to authorized roles.
- Active probing requires:
  - Target allowlisted in config (`scan allowlist add <domain>`)
  - Approval when policy requires it (`scan.website.active`)

## AI Configuration

Groq key can be configured once and reused:

```text
agent configure
```

CrewAI mission command:

```text
agent crewai <objective>
```

## Documentation

- `QUICKSTART.md` - fast setup and day-1 usage
- `README_AGENT_SYSTEM.md` - operations and governance detail
- `docs/updates.md` - dated project updates

## Test Status

Run all tests:

```bash
venv\Scripts\python -m pytest -q tests
```
