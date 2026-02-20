import builtins

import whitecell.cli_enhanced as cli_mod


def test_agent_configure_persists_key_and_reloads(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    saved = {"key": None}
    api_key = "gsk-configure-abcdefghijklmnopqrstuvwxyz1234"

    monkeypatch.setattr(cli_mod, "get_groq_api_key", lambda: None)
    monkeypatch.setattr(cli_mod.Prompt, "ask", lambda *args, **kwargs: api_key)
    monkeypatch.setattr(cli_mod, "validate_groq_api_key", lambda value: value == api_key)

    def fake_set_key(value: str) -> bool:
        saved["key"] = value
        return True

    monkeypatch.setattr(cli_mod, "set_groq_api_key", fake_set_key)
    monkeypatch.setattr(cli_mod.groq_client, "reload_from_config", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda *args, **kwargs: "")

    cli.configure_groq_api()
    assert saved["key"] == api_key


def test_agent_ask_command_dispatches_to_prompt_runner(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    called = {"mode": None, "prompt": None}

    def fake_run(mode: str, prompt_text: str) -> None:
        called["mode"] = mode
        called["prompt"] = prompt_text

    monkeypatch.setattr(cli, "run_agent_ai_prompt", fake_run)

    cli.handle_agent_command(["ask", "summarize", "threat", "intel"])
    assert called["mode"] == "ask"
    assert called["prompt"] == "summarize threat intel"


def test_governance_approval_flow_for_response_execution(tmp_path, monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    cli.role = "admin"

    monkeypatch.setattr(cli_mod.governance, "LOGS_DIR", tmp_path)
    monkeypatch.setattr(cli_mod.governance, "AUDIT_LOG_FILE", tmp_path / "audit.jsonl")
    monkeypatch.setattr(cli_mod.governance, "APPROVALS_FILE", tmp_path / "approvals.json")
    monkeypatch.setattr(cli, "_check_permission", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        cli_mod.governance,
        "is_approval_required",
        lambda action: action == "respond.block_ip",
    )

    cli.handle_respond_command(["execute", "block_ip", "10.0.0.8"])
    pending = cli_mod.governance.list_approvals(status="pending")
    assert len(pending) == 1

    req_id = pending[0]["id"]
    cli.handle_governance_command(["approvals", "approve", req_id])

    approved = cli_mod.governance.list_approvals(status="approved")
    assert len(approved) == 1
    assert approved[0]["id"] == req_id

    cli.handle_respond_command(["execute", "block_ip", "10.0.0.8"])
    all_requests = cli_mod.governance.list_approvals()
    assert len(all_requests) == 1


def test_scan_website_active_requests_approval_when_allowlisted(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    requested = {"action": None, "target": None}

    monkeypatch.setattr(cli_mod.Confirm, "ask", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli_mod, "get_scan_allowlist", lambda: ["example.com"])
    monkeypatch.setattr(cli_mod.governance, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli_mod.governance, "is_approval_required", lambda action: True)

    def fake_request(action, target, reason, requested_by, metadata=None):
        requested["action"] = action
        requested["target"] = target
        return {"id": "REQ12345"}

    monkeypatch.setattr(cli_mod.governance, "request_approval", fake_request)
    monkeypatch.setattr(cli_mod.website_scanner, "passive_scan", lambda url: {"risk_level": "low"})
    monkeypatch.setattr(cli_mod.website_scanner, "format_report", lambda result: "report")

    cli.scan_website(["https://example.com", "--active"])
    assert requested["action"] == "scan.website.active"
    assert requested["target"] == "example.com"


def test_soc_run_golden_path_chains_workflow(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    calls = []

    monkeypatch.setattr(
        "whitecell.detection.detect_threat",
        lambda alert: {"threat_type": "ransomware"},
    )
    monkeypatch.setattr(
        cli, "handle_triage_command", lambda args: calls.append(("triage", list(args)))
    )
    monkeypatch.setattr(
        cli, "handle_investigate_command", lambda args: calls.append(("investigate", list(args)))
    )
    monkeypatch.setattr(
        cli, "handle_respond_command", lambda args: calls.append(("respond", list(args)))
    )

    cli.handle_soc_command(["run", "suspicious", "powershell", "--execute", "block_ip", "10.0.0.8"])

    assert calls == [
        ("triage", ["suspicious powershell"]),
        ("investigate", ["ransomware"]),
        ("respond", ["recommend", "suspicious powershell"]),
        ("respond", ["execute", "block_ip", "10.0.0.8"]),
    ]
