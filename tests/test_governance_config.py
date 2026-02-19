import whitecell.config as cfg


def test_governance_role_validation(monkeypatch):
    store = {}

    def fake_load():
        return {"governance": {"role": "admin", "approval_required_actions": []}}

    def fake_save(payload):
        store["payload"] = payload
        return True

    monkeypatch.setattr(cfg, "load_config", fake_load)
    monkeypatch.setattr(cfg, "save_config", fake_save)

    assert cfg.set_governance_role("analyst") is True
    assert store["payload"]["governance"]["role"] == "analyst"
    assert cfg.set_governance_role("invalid") is False


def test_approval_required_actions_normalization(monkeypatch):
    store = {}

    def fake_load():
        return {"governance": {"role": "admin", "approval_required_actions": []}}

    def fake_save(payload):
        store["payload"] = payload
        return True

    monkeypatch.setattr(cfg, "load_config", fake_load)
    monkeypatch.setattr(cfg, "save_config", fake_save)

    ok = cfg.set_approval_required_actions(["respond.block_ip", "respond.block_ip", " scan.website.active "])
    assert ok is True
    assert store["payload"]["governance"]["approval_required_actions"] == [
        "respond.block_ip",
        "scan.website.active",
    ]
