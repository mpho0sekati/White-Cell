import pytest
from pathlib import Path

import whitecell.engine as engine
from whitecell import state


@pytest.fixture(autouse=True)
def isolate_logs(tmp_path, monkeypatch):
    """Redirect engine log path to temporary test directory and reset global state."""
    test_logs_dir = tmp_path / "logs"
    test_logs_dir.mkdir()
    test_logs_file = test_logs_dir / "threats.json"

    monkeypatch.setattr(engine, "LOGS_DIR", test_logs_dir)
    monkeypatch.setattr(engine, "LOGS_FILE", test_logs_file)

    # Ensure any previous global_state is reset
    state.global_state = state.SessionState()

    yield

    # cleanup if needed
    if test_logs_file.exists():
        test_logs_file.unlink()
