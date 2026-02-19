import time

from whitecell.agent import agent_manager
from whitecell.guardian import create_and_start_guardian


def test_guardian_pauses_agent_on_rate_limit():
    # create and start an agent
    a = agent_manager.create_agent("g-test", check_interval=1)
    a.start()

    # start guardian with low rate limit/window for quick test
    g = create_and_start_guardian(check_interval=0.2, prevention_rate_limit=2, window_seconds=2)

    # simulate prevention_action events in the global log for this agent
    for _ in range(4):
        agent_manager._log_prevention_action("ransomware", "isolated process")
        # add agent_id to last log entry to help guardian infer agent
        if agent_manager.global_log:
            agent_manager.global_log[-1]["agent_id"] = a.agent_id
        time.sleep(0.3)

    # give guardian a moment to process
    time.sleep(0.5)

    # agent should be stopped by guardian
    status = agent_manager.get_agent_status(a.agent_id)
    assert status is not None
    assert status["running"] is False

    # cleanup
    g.stop()
