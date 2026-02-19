"""
Crew manager: spawn temporary helper agents to execute testing tasks and report.

Helpers are short-lived agents created to perform a task (e.g., simulate an
attack or run checks). After completion they are removed and a report is
generated. The crew manager uses `agent_manager` to register agents and
aggregates events from the global log for reporting.
"""
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List

from whitecell.agent import agent_manager, Agent, Task


class CrewManager:
    def __init__(self):
        self.helpers: Dict[str, Agent] = {}
        self.reports: Dict[str, Dict[str, Any]] = {}

    def _make_helper_id(self) -> str:
        return f"helper-{uuid.uuid4().hex[:8]}"

    def spawn_helper(self, description: str, duration: int = 10, task_type: str = "custom", parameters: dict | None = None) -> str:
        """Spawn a short-lived helper agent that executes one task and exits.

        Returns a helper id that can be used to fetch the report.
        """
        helper_id = self._make_helper_id()
        a = agent_manager.create_agent(helper_id, check_interval=1)

        # create a task that simulates activity for `duration` seconds
        params = parameters or {}
        params.update({"duration": duration, "description": description})
        task = agent_manager.create_task(task_type, description, params)

        # register callbacks to capture completion
        def on_task_completed(t: Task):
            # generate report on task completion and schedule removal
            report = self._generate_report_for_helper(helper_id, t)
            self.reports[helper_id] = report
            # remove agent after small delay to allow guardian/audit to capture events
            threading.Timer(1.0, lambda: agent_manager.remove_agent(helper_id)).start()

        a.register_task_callback(on_task_completed)

        # start helper and assign task
        a.start()
        a.assign_task(task)

        # track helper
        self.helpers[helper_id] = a

        return helper_id

    def _generate_report_for_helper(self, helper_id: str, task: Task) -> Dict[str, Any]:
        # Aggregate events from agent_manager.global_log that reference the helper
        events = [ev for ev in agent_manager.global_log if ev.get("data", {}).get("agent_id") == helper_id or ev.get("agent_id") == helper_id]
        report = {
            "helper_id": helper_id,
            "task_id": task.task_id,
            "task_type": task.task_type,
            "description": task.description,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "status": task.status.value,
            "events": events,
        }
        return report

    def get_report(self, helper_id: str) -> Dict[str, Any] | None:
        return self.reports.get(helper_id)

    def list_helpers(self) -> List[str]:
        return list(self.helpers.keys())


    def watch_helpers(self, helper_ids: list[str] | None = None, callback=None, poll_interval: float = 0.5, stop_event: threading.Event | None = None):
        """Stream events related to helpers from the global agent log.

        - `helper_ids`: list of helper IDs to filter, or None for all helpers
        - `callback`: function called for each matching event: callback(event)
        - `poll_interval`: seconds between polls
        - `stop_event`: optional threading.Event used to stop the watcher

        This method blocks until `stop_event` is set (or forever if None).
        It is safe to call from a background thread.
        """
        last_idx = 0
        stop_event = stop_event or threading.Event()

        while not stop_event.is_set():
            # snapshot to avoid long locks
            log = list(agent_manager.global_log)
            if len(log) > last_idx:
                new = log[last_idx:]
                last_idx = len(log)
                for ev in new:
                    # determine agent id in event
                    ev_agent = None
                    data = ev.get("data") or {}
                    ev_agent = data.get("agent_id") or ev.get("agent_id")

                    if helper_ids is None or (ev_agent in helper_ids):
                        if callback:
                            try:
                                callback(ev)
                            except Exception:
                                pass
            stop_event.wait(poll_interval)


# Global crew manager
crew_manager = CrewManager()
