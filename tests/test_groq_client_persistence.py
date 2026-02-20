import os

import whitecell.config as cfg
import whitecell.groq_client as gc_mod


def test_groq_client_syncs_key_from_config(monkeypatch):
    monkeypatch.setattr(gc_mod, "GROQ_AVAILABLE", False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    current = {"key": "gsk-first-abcdefghijklmnopqrstuvwxyz123456"}
    monkeypatch.setattr(cfg, "get_groq_api_key", lambda: current["key"])

    client = gc_mod.GroqClient()
    assert client.api_key == current["key"]

    current["key"] = "gsk-second-abcdefghijklmnopqrstuvwxyz12345"
    client.is_configured()  # triggers key sync even when Groq SDK unavailable
    assert client.api_key == current["key"]


def test_set_api_key_persists_and_updates_env(monkeypatch):
    monkeypatch.setattr(gc_mod, "GROQ_AVAILABLE", False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(cfg, "get_groq_api_key", lambda: None)

    persisted = {"value": None}

    def fake_set_key(v: str) -> bool:
        persisted["value"] = v
        return True

    monkeypatch.setattr(cfg, "set_groq_api_key", fake_set_key)

    client = gc_mod.GroqClient()
    api_key = "gsk-persist-abcdefghijklmnopqrstuvwxyz123456"
    assert client.set_api_key(api_key, persist=True) is False  # SDK unavailable, but key handling should still work
    assert persisted["value"] == api_key
    assert os.getenv("GROQ_API_KEY") == api_key
    assert client.api_key == api_key


def test_invalid_config_key_falls_back_to_env(monkeypatch):
    monkeypatch.setattr(gc_mod, "GROQ_AVAILABLE", False)
    monkeypatch.setattr(cfg, "get_groq_api_key", lambda: "fernet://gAAAAABlegacy")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-env-abcdefghijklmnopqrstuvwxyz123456")

    client = gc_mod.GroqClient()
    assert client.api_key == "gsk-env-abcdefghijklmnopqrstuvwxyz123456"
