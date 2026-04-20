from whitecell.risk import calculate_risk


def test_calculate_risk_basic():
    info = {"threat_type": "ransomware", "severity": 9}
    res = calculate_risk(info)
    assert "risk_score" in res
    assert 0 <= res["risk_score"] <= 100
    assert "estimated_financial_loss" in res
    assert isinstance(res["popia_exposure"], bool)


def test_calculate_risk_unknown_type():
    info = {"threat_type": "unknown_type", "severity": 5}
    res = calculate_risk(info)
    assert res["risk_score"] >= 0
