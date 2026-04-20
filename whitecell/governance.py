"""
White Cell Governance: RBAC, approvals, and audit logging.
"""

import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from typing import Any

from whitecell.config import (
    get_governance_role,
    get_approval_required_actions,
)


LOGS_DIR = Path(__file__).parent.parent / "logs"
AUDIT_LOG_FILE = LOGS_DIR / "audit.jsonl"
APPROVALS_FILE = LOGS_DIR / "approvals.json"

ROLE_PERMISSIONS = {
    "viewer": {
        "view.status",
        "view.logs",
        "view.dashboard",
        "view.help",
        "soc.triage",
        "soc.investigate",
    },
    "analyst": {
        "view.status",
        "view.logs",
        "view.dashboard",
        "view.help",
        "agent.use",
        "scan.website.passive",
        "soc.triage",
        "soc.investigate",
        "soc.respond",
    },
    "admin": {"*"},
}


def _ensure_logs_dir() -> None:
    LOGS_DIR.mkdir(exist_ok=True)


def _load_json(path: Path, fallback: Any) -> Any:
    try:
        if not path.exists():
            return fallback
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return fallback


def _save_json(path: Path, payload: Any) -> bool:
    try:
        _ensure_logs_dir()
        path.write_text(json.dumps(payload, indent=2))
        return True
    except OSError:
        return False


def get_current_role() -> str:
    return get_governance_role()


def has_permission(capability: str, role: str | None = None) -> bool:
    current_role = (role or get_current_role()).lower().strip()
    allowed = ROLE_PERMISSIONS.get(current_role, ROLE_PERMISSIONS["viewer"])
    return "*" in allowed or capability in allowed


def is_approval_required(action: str) -> bool:
    required = set(get_approval_required_actions())
    return action in required


def audit_event(
    event_type: str,
    action: str,
    actor: str,
    outcome: str,
    details: dict | None = None,
) -> None:
    _ensure_logs_dir()
    entry = {
        "id": str(uuid4()),
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "action": action,
        "actor": actor,
        "outcome": outcome,
        "details": details or {},
    }
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def request_approval(
    action: str,
    target: str,
    reason: str,
    requested_by: str,
    metadata: dict | None = None,
) -> dict:
    requests = _load_json(APPROVALS_FILE, [])
    if not isinstance(requests, list):
        requests = []

    item = {
        "id": str(uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "target": target,
        "reason": reason,
        "requested_by": requested_by,
        "status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "review_note": "",
        "metadata": metadata or {},
    }
    requests.append(item)
    _save_json(APPROVALS_FILE, requests)
    audit_event("approval", action, requested_by, "requested", {"request_id": item["id"], "target": target})
    return item


def list_approvals(status: str | None = None) -> list[dict]:
    requests = _load_json(APPROVALS_FILE, [])
    if not isinstance(requests, list):
        return []
    if not status:
        return requests
    return [r for r in requests if r.get("status") == status]


def review_approval(request_id: str, decision: str, reviewer: str, note: str = "") -> bool:
    requests = _load_json(APPROVALS_FILE, [])
    if not isinstance(requests, list):
        return False

    for req in requests:
        if req.get("id") != request_id:
            continue
        if req.get("status") != "pending":
            return False
        req["status"] = "approved" if decision == "approve" else "rejected"
        req["reviewed_by"] = reviewer
        req["reviewed_at"] = datetime.now().isoformat()
        req["review_note"] = note
        ok = _save_json(APPROVALS_FILE, requests)
        if ok:
            audit_event(
                "approval",
                req.get("action", "unknown"),
                reviewer,
                req["status"],
                {"request_id": request_id, "target": req.get("target", "")},
            )
        return ok

    return False


def get_approval(request_id: str) -> dict | None:
    for req in list_approvals():
        if req.get("id") == request_id:
            return req
    return None
