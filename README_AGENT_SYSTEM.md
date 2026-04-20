# White Cell Agent and Operations Guide

## Scope

This document covers production usage of White Cell agent operations, SOC workflows, governance controls, and safe scanning behavior.

## Operating Model

White Cell is designed around three layers:

1. Detection and risk scoring
2. SOC workflow execution (`triage`, `investigate`, `respond`)
3. Governance guardrails (RBAC, approvals, audit)

## Start the Platform

```bash
python main.py
```

## Command Reference

### SOC Workflow

```text
triage <alert_text>
investigate <threat_type|log_index>
respond recommend <incident>
respond execute <action> <target>
soc run <alert_text> [--execute <action> <target>]
```

### Agent Operations

```text
agent deploy <name> [interval]
agent status
agent threats <name> [limit]
agent stop <name>
agent configure
agent ask <prompt>
agent blue <scenario>
agent red <scenario>
agent battle <scenario>
agent crewai <objective>
```

### Governance

```text
governance status
governance role <admin|analyst|viewer>
governance policy <add|remove> <action>
governance approvals list
governance approvals approve <id>
governance approvals reject <id>
```

### Scanning

```text
scan allowlist show
scan allowlist add <domain>
scan allowlist remove <domain>
scan website <url> [--active]
```

## Governance Details

### Roles

| Role | Typical Access |
|---|---|
| `viewer` | visibility and investigation only |
| `analyst` | SOC workflow and passive operations |
| `admin` | full control including governance updates |

### Approval-Controlled Actions

Policy is configurable in config and at runtime. Common examples:

- `scan.website.active`
- `respond.block_ip`
- `respond.disable_user`
- `agent.evolve.apply`

### Audit Logging

All key controlled actions are written to `logs/audit.jsonl` with:

- timestamp
- actor
- action
- outcome
- details

Approval requests are stored in `logs/approvals.json`.

## Safe Scanning Policy

Active probing is never executed blindly.

Execution path:
1. User confirms authorization
2. Domain is checked against allowlist
3. Governance approval is required when policy marks action as controlled
4. Action is audited

## Configuration

Config file location:

```text
~/.whitecell/config.json
```

Key sections:

```json
{
  "groq_api_key": null,
  "scan_allowlist": [],
  "governance": {
    "role": "admin",
    "approval_required_actions": [
      "scan.website.active",
      "respond.block_ip",
      "respond.disable_user",
      "agent.evolve.apply"
    ]
  }
}
```

## SOC Runbook Example

```text
soc run suspicious powershell and credential dumping
```

Expected flow:
1. Triage classifies threat and risk
2. Investigation pivots through matching logs
3. Response recommendations are generated

Optional governed execution:

```text
soc run suspicious powershell and credential dumping --execute block_ip 10.0.0.8
```

If policy requires approval, White Cell creates an approval request and waits for admin decision.

## UX Surfaces

- Main CLI prompt: `WHITE CELL >`
- `peek`: live operational window
- `dashboard`: high-level system snapshot
- Rich tables/panels for consistent readability

## Validation

Run tests:

```bash
venv\Scripts\python -m pytest -q tests
```

## Production Notes

- Keep role assignment explicit per operator context.
- Review approval rules periodically.
- Rotate API keys and monitor audit log growth.
- Keep allowlist tight and domain-specific.
