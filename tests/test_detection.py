from whitecell.detection import detect_threat, detect_threats


def test_detect_threat_basic():
    res = detect_threat("Ransomware encrypted files, pay in bitcoin")
    assert res is not None
    assert res["threat_type"] == "ransomware"
    assert res["severity"] >= 1


def test_detect_threats_multiple():
    res = detect_threats("Possible data breach, credentials stolen from server")
    assert isinstance(res, list)
    types = [r["threat_type"] for r in res]
    assert "data_breach" in types or "credential_theft" in types
