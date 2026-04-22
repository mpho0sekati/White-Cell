from whitecell.immune import BCellSignatureMemory, ImmuneSystem
from whitecell.state import SessionState


def test_b_cell_memory_counts_repeat_sightings():
    memory = BCellSignatureMemory()
    threat_info = {
        "threat_type": "ransomware",
        "confidence": 0.9,
        "keywords_matched": ["ransomware", "encrypt"],
        "regex_matched": [],
    }
    risk_info = {"risk_score": 90}

    first = memory.remember_incident(threat_info, risk_info)
    second = memory.remember_incident(threat_info, risk_info)

    assert first.threat_type == "ransomware"
    assert second.sightings == 2


def test_immune_system_detects_and_activates_command_mode():
    system = ImmuneSystem()
    session = SessionState()

    outcome = system.handle_input("ransomware encrypt locked files", session)

    assert outcome.detected is True
    assert session.command_mode is True
    assert outcome.log_entry is not None
    assert outcome.signal is not None
    assert outcome.memory_record is not None
