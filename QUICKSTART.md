# White Cell Quickstart

## 1. Setup

```bash
cd /path/to/whitecell_project
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Run

```bash
python main.py
```

## 3. First Commands

```text
help
status
peek
dashboard
```

## 4. SOC Workflow (Primary)

### Step A: Triage

```text
triage suspicious powershell downloading payload
```

### Step B: Investigate

```text
investigate malware
investigate 0
```

### Step C: Respond

```text
respond recommend possible credential theft on finance host
respond execute block_ip 10.0.0.8
```

### One-command chain

```text
soc run suspicious powershell downloading payload
soc run suspicious powershell downloading payload --execute block_ip 10.0.0.8
```

## 5. Governance and Access Control

### Check status

```text
governance status
```

### Set role

```text
governance role admin
governance role analyst
governance role viewer
```

### Manage approval policy

```text
governance policy add respond.block_ip
governance policy remove respond.block_ip
```

### Process approvals

```text
governance approvals list
governance approvals approve <id>
governance approvals reject <id>
```

## 6. Website Analysis (Ethical and Controlled)

```text
scan allowlist add example.com
scan website https://example.com
scan website https://example.com --active
```

Notes:
- Active probing is blocked unless allowlisted.
- Governance policy may require approval for active probing.

## 7. AI Enablement

```text
agent configure
agent ask summarize this incident pattern
agent blue defend against ransomware in small enterprise
agent red authorized simulation of phishing campaign controls
agent crewai produce incident response playbook draft
```

## 8. Logs and Export

```text
logs 20
export csv
export json
```

Log files:
- `logs/threats.json`
- `logs/audit.jsonl`
- `logs/approvals.json`

## 9. Troubleshooting

### Dependencies

```bash
pip install -r requirements.txt
```

### Run tests

```bash
venv\Scripts\python -m pytest -q tests
```
