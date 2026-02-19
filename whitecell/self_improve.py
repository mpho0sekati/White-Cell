"""
Guarded autonomous self-improvement engine.

This module allows White Cell to propose and apply limited self-modifications.
All modifications require explicit user permission via approval token.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class AutonomousSelfImprover:
    """Generate and apply bounded self-improvement proposals with approval gates."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path(__file__).parent.parent
        self.logs_dir = self.workspace_root / "logs"
        self.state_file = self.logs_dir / "self_improvement_proposals.json"
        self.allowed_roots = ("whitecell", "tests", "docs")
        self.dangerous_patterns = (
            "os.system(",
            "subprocess.",
            "eval(",
            "exec(",
            "__import__(",
        )

        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._interval_seconds = 120

        self._state = {
            "running": False,
            "interval_seconds": self._interval_seconds,
            "last_cycle": None,
            "proposals": [],
        }
        self._load_state()

    def _load_state(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        if not self.state_file.exists():
            self._save_state()
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._state.update(data)
        except (json.JSONDecodeError, OSError):
            self._save_state()

    def _save_state(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def _now(self) -> str:
        return datetime.now().isoformat()

    def start(self, interval_seconds: int = 120) -> None:
        with self._lock:
            if self._running:
                return
            self._interval_seconds = max(30, int(interval_seconds))
            self._state["interval_seconds"] = self._interval_seconds
            self._running = True
            self._state["running"] = True
            self._save_state()

            self._thread = threading.Thread(target=self._loop, daemon=True, name="WhiteCell-SelfImprove")
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._state["running"] = False
            self._save_state()
        if self._thread:
            self._thread.join(timeout=2)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            proposals = self._state.get("proposals", [])
            pending = sum(1 for p in proposals if p.get("status") == "pending")
            approved = sum(1 for p in proposals if p.get("status") == "approved")
            applied = sum(1 for p in proposals if p.get("status") == "applied")
            return {
                "running": self._running,
                "interval_seconds": self._interval_seconds,
                "last_cycle": self._state.get("last_cycle"),
                "total_proposals": len(proposals),
                "pending": pending,
                "approved": approved,
                "applied": applied,
            }

    def _loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    return
            self.generate_proposal()
            with self._lock:
                self._state["last_cycle"] = self._now()
                self._save_state()
                interval = self._interval_seconds
            time.sleep(interval)

    def list_proposals(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            proposals = list(self._state.get("proposals", []))
        return proposals[-max(1, limit):]

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for proposal in self._state.get("proposals", []):
                if proposal.get("id") == proposal_id:
                    return proposal.copy()
        return None

    def _append_proposal(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._state["proposals"].append(proposal)
            self._save_state()
        return proposal

    def _proposal_exists_for_title(self, title: str) -> bool:
        for p in self._state.get("proposals", []):
            if p.get("title") == title and p.get("status") in {"pending", "approved", "applied"}:
                return True
        return False

    def generate_proposal(self) -> Optional[Dict[str, Any]]:
        """
        Autonomously generate a bounded hardening proposal.

        Returns:
            Proposal dict if a new proposal was generated, otherwise None.
        """
        config_path = self.workspace_root / "whitecell" / "config.py"
        if not config_path.exists():
            return None

        text = config_path.read_text(encoding="utf-8")

        with self._lock:
            if '"prevention_rate_limit": 3' in text and not self._proposal_exists_for_title("Tighten guardian prevention rate limit"):
                proposal = self._build_proposal(
                    title="Tighten guardian prevention rate limit",
                    rationale="Reduce burst prevention actions to lower abuse and false-positive amplification risk.",
                    risk="low",
                    edits=[{
                        "path": "whitecell/config.py",
                        "find": '"prevention_rate_limit": 3',
                        "replace": '"prevention_rate_limit": 2',
                    }],
                )
                return self._append_proposal(proposal)

            if '"model_confidence_threshold": 80' in text and not self._proposal_exists_for_title("Raise model confidence threshold"):
                proposal = self._build_proposal(
                    title="Raise model confidence threshold",
                    rationale="Require stronger model confidence before automated guardian pauses.",
                    risk="low",
                    edits=[{
                        "path": "whitecell/config.py",
                        "find": '"model_confidence_threshold": 80',
                        "replace": '"model_confidence_threshold": 85',
                    }],
                )
                return self._append_proposal(proposal)

        return None

    def _build_proposal(self, title: str, rationale: str, risk: str, edits: List[Dict[str, str]]) -> Dict[str, Any]:
        return {
            "id": f"prop-{uuid.uuid4().hex[:8]}",
            "created_at": self._now(),
            "title": title,
            "rationale": rationale,
            "risk": risk,
            "status": "pending",
            "approval_token": None,
            "approved_at": None,
            "applied_at": None,
            "edits": edits,
        }

    def approve_proposal(self, proposal_id: str) -> Optional[str]:
        with self._lock:
            for proposal in self._state.get("proposals", []):
                if proposal.get("id") != proposal_id:
                    continue
                if proposal.get("status") not in {"pending", "approved"}:
                    return None
                token = f"appr-{uuid.uuid4().hex[:10]}"
                proposal["status"] = "approved"
                proposal["approval_token"] = token
                proposal["approved_at"] = self._now()
                self._save_state()
                return token
        return None

    def reject_proposal(self, proposal_id: str) -> bool:
        with self._lock:
            for proposal in self._state.get("proposals", []):
                if proposal.get("id") == proposal_id and proposal.get("status") in {"pending", "approved"}:
                    proposal["status"] = "rejected"
                    self._save_state()
                    return True
        return False

    def apply_proposal(self, proposal_id: str, approval_token: str) -> bool:
        with self._lock:
            proposal = None
            for p in self._state.get("proposals", []):
                if p.get("id") == proposal_id:
                    proposal = p
                    break

            if not proposal:
                return False
            if proposal.get("status") != "approved":
                return False
            if proposal.get("approval_token") != approval_token:
                return False

            edits = proposal.get("edits", [])

        for edit in edits:
            if not self._apply_single_edit(edit):
                return False

        with self._lock:
            proposal["status"] = "applied"
            proposal["applied_at"] = self._now()
            self._save_state()
        return True

    def _is_safe_path(self, rel_path: str) -> bool:
        path = Path(rel_path)
        if path.is_absolute():
            return False
        normalized = str(path).replace("\\", "/")
        if ".." in normalized:
            return False
        return normalized.startswith(self.allowed_roots)

    def _content_safe(self, content: str) -> bool:
        lowered = content.lower()
        return not any(pattern.lower() in lowered for pattern in self.dangerous_patterns)

    def _apply_single_edit(self, edit: Dict[str, str]) -> bool:
        rel_path = edit.get("path", "")
        needle = edit.get("find", "")
        replacement = edit.get("replace", "")

        if not rel_path or not needle:
            return False
        if not self._is_safe_path(rel_path):
            return False

        target = self.workspace_root / rel_path
        if not target.exists() or not target.is_file():
            return False

        try:
            current = target.read_text(encoding="utf-8")
        except OSError:
            return False

        if current.count(needle) != 1:
            return False

        updated = current.replace(needle, replacement, 1)
        if not self._content_safe(updated):
            return False

        try:
            target.write_text(updated, encoding="utf-8")
            return True
        except OSError:
            return False


self_improver = AutonomousSelfImprover()
