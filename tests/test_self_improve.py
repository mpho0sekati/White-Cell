from pathlib import Path

from whitecell.self_improve import AutonomousSelfImprover


def _write_test_config(workspace: Path, prevention_limit: int = 3, model_threshold: int = 80) -> None:
    wc_dir = workspace / "whitecell"
    wc_dir.mkdir(parents=True, exist_ok=True)
    (wc_dir / "config.py").write_text(
        f"""
DEFAULT_CONFIG = {{
    "guardian": {{
        "prevention_rate_limit": {prevention_limit},
        "model_confidence_threshold": {model_threshold}
    }}
}}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def test_self_improver_requires_approval_token(tmp_path):
    _write_test_config(tmp_path, prevention_limit=3, model_threshold=80)
    improver = AutonomousSelfImprover(workspace_root=tmp_path)

    proposal = improver.generate_proposal()
    assert proposal is not None
    assert proposal["status"] == "pending"

    # Cannot apply before approval
    assert improver.apply_proposal(proposal["id"], "wrong-token") is False

    token = improver.approve_proposal(proposal["id"])
    assert token is not None

    # Wrong token still fails
    assert improver.apply_proposal(proposal["id"], "wrong-token") is False
    # Correct token succeeds
    assert improver.apply_proposal(proposal["id"], token) is True

    updated = (tmp_path / "whitecell" / "config.py").read_text(encoding="utf-8")
    assert '"prevention_rate_limit": 2' in updated


def test_self_improver_can_generate_second_hardening_proposal(tmp_path):
    _write_test_config(tmp_path, prevention_limit=2, model_threshold=80)
    improver = AutonomousSelfImprover(workspace_root=tmp_path)

    proposal = improver.generate_proposal()
    assert proposal is not None
    assert proposal["title"] == "Raise model confidence threshold"
