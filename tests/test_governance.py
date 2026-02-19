from pathlib import Path

import whitecell.governance as gov


def test_has_permission_by_role():
    assert gov.has_permission("view.help", "viewer") is True
    assert gov.has_permission("soc.respond", "viewer") is False
    assert gov.has_permission("soc.respond", "analyst") is True
    assert gov.has_permission("governance.manage", "admin") is True


def test_approval_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(gov, "LOGS_DIR", tmp_path)
    monkeypatch.setattr(gov, "AUDIT_LOG_FILE", tmp_path / "audit.jsonl")
    monkeypatch.setattr(gov, "APPROVALS_FILE", tmp_path / "approvals.json")

    req = gov.request_approval(
        action="scan.website.active",
        target="example.com",
        reason="Need active testing",
        requested_by="analyst",
    )
    assert req["status"] == "pending"

    pending = gov.list_approvals(status="pending")
    assert any(item["id"] == req["id"] for item in pending)

    approved = gov.review_approval(req["id"], "approve", "admin")
    assert approved is True

    item = gov.get_approval(req["id"])
    assert item is not None
    assert item["status"] == "approved"

    assert Path(tmp_path / "audit.jsonl").exists()


def test_is_approval_required(monkeypatch):
    monkeypatch.setattr(gov, "get_approval_required_actions", lambda: ["respond.block_ip"])
    assert gov.is_approval_required("respond.block_ip") is True
    assert gov.is_approval_required("respond.collect_forensics") is False
