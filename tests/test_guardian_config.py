import time

import whitecell.config as cfg
from whitecell.agent import agent_manager
from whitecell.guardian import create_and_start_guardian


def test_guardian_uses_config_overrides(monkeypatch):
    # monkeypatch load_config to return a guardian policy with low rate limit
    def fake_load():
        base = cfg.DEFAULT_CONFIG.copy()
        base["guardian"] = {"check_interval": 0.1, "prevention_rate_limit": 1, "window_seconds": 2, "per_agent": {}}
        return base

    monkeypatch.setattr(cfg, "load_config", fake_load)

    # create and start agent
    a = agent_manager.create_agent("cfg-test", check_interval=1)
    a.start()

    # create guardian that reads config (use_config True)
    g = create_and_start_guardian(use_config=True)

    # simulate prevention events
    for _ in range(3):
        agent_manager._log_prevention_action("malware", "quarantined")
        if agent_manager.global_log:
            agent_manager.global_log[-1]["agent_id"] = a.agent_id
        time.sleep(0.2)

    time.sleep(0.2)
    status = agent_manager.get_agent_status(a.agent_id)
    assert status is not None
    assert status["running"] is False

    g.stop()
