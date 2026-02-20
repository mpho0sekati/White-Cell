import json

import whitecell.config as cfg


def _write_config(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_migrate_legacy_key_uses_valid_fallback(tmp_path, monkeypatch, caplog):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfg, "CONFIG_FILE", config_file)

    _write_config(
        config_file,
        {
            "groq_api_key": "fernet://gAAAAABlegacyblob",
            "groq_api_key_hash": "oldhash",
            "groq_api_configured": True,
        },
    )

    fallback = "gsk-migrated-abcdefghijklmnopqrstuvwxyz1234"
    with caplog.at_level("WARNING"):
        migrated = cfg.migrate_legacy_groq_api_key(fallback)

    assert migrated == fallback
    stored = cfg.load_config()
    assert stored["groq_api_key"] == fallback
    assert stored["groq_api_configured"] is True
    assert "Legacy encrypted Groq API key detected" in caplog.text


def test_migrate_legacy_key_without_fallback_clears_key(tmp_path, monkeypatch, caplog):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfg, "CONFIG_FILE", config_file)

    _write_config(
        config_file,
        {
            "groq_api_key": "fernet://gAAAAABlegacyblob",
            "groq_api_key_hash": "oldhash",
            "groq_api_configured": True,
        },
    )

    with caplog.at_level("WARNING"):
        migrated = cfg.migrate_legacy_groq_api_key(None)

    assert migrated is None
    stored = cfg.load_config()
    assert stored["groq_api_key"] is None
    assert stored["groq_api_key_hash"] is None
    assert stored["groq_api_configured"] is False
    assert "cannot be decrypted" in caplog.text
