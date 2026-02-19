from whitecell.website_scanner import WebsiteScanner


def test_active_scan_reports_real_checks_not_simulated(monkeypatch):
    scanner = WebsiteScanner()

    monkeypatch.setattr(scanner, "_check_ssl", lambda domain: [{
        "type": "ssl_tls_ok",
        "severity": "info",
        "description": "TLS connectivity verified (TLSv1.3)",
        "weakness": "None observed",
        "recommendation": "Continue certificate lifecycle monitoring",
    }])
    monkeypatch.setattr(scanner, "_analyze_security_headers", lambda url: [])
    monkeypatch.setattr(scanner, "_probe_common_endpoints", lambda url: [])

    result = scanner.active_scan("https://example.com")
    joined = " ".join(f.get("description", "") for f in result.get("active_findings", []))
    assert "simulated" not in joined.lower()


def test_probe_common_endpoints_reports_only_reachable(monkeypatch):
    scanner = WebsiteScanner()

    def fake_request(url, timeout=5):
        if url.endswith("/admin"):
            return 200, {}
        raise Exception("not reachable")

    monkeypatch.setattr(scanner, "_request_url", fake_request)

    findings = scanner._probe_common_endpoints("https://example.com")
    endpoint_findings = [f for f in findings if f.get("type") == "reachable_sensitive_endpoint"]
    assert len(endpoint_findings) == 1
    assert endpoint_findings[0]["description"].startswith("Endpoint /admin is reachable")
