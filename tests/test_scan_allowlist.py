import whitecell.cli_enhanced as cli_mod


def test_normalize_domain_from_url():
    cli = cli_mod.EnhancedWhiteCellCLI()
    assert cli._normalize_domain("https://www.Example.com:443/path?q=1") == "example.com"


def test_allowlist_exact_and_subdomain(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    monkeypatch.setattr(cli_mod, "get_scan_allowlist", lambda: ["example.com"])

    assert cli._is_domain_allowlisted("example.com") is True
    assert cli._is_domain_allowlisted("api.example.com") is True
    assert cli._is_domain_allowlisted("evil-example.com") is False


def test_allowlist_add_and_remove(monkeypatch):
    cli = cli_mod.EnhancedWhiteCellCLI()
    stored = {"domains": ["example.com"]}

    monkeypatch.setattr(cli_mod, "get_scan_allowlist", lambda: list(stored["domains"]))

    def fake_set(domains):
        stored["domains"] = list(domains)
        return True

    monkeypatch.setattr(cli_mod, "set_scan_allowlist", fake_set)

    cli.handle_scan_allowlist_command(["add", "test.example.com"])
    assert "test.example.com" in stored["domains"]

    cli.handle_scan_allowlist_command(["remove", "test.example.com"])
    assert "test.example.com" not in stored["domains"]
