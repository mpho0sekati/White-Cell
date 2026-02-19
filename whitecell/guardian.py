"""
Guardian agent: monitors other agents' actions and enforces safety policies.

This lightweight guardian polls the `agent_manager.global_log` for events and
applies simple policy checks (rate limits on prevention actions, suspicious
behavior) and can pause agents or emit alerts when rules are violated.

This is a minimal, safe implementation intended as a starting point.
"""
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any

from whitecell.agent import agent_manager
from whitecell.config import get_guardian_config
from whitecell.groq_client import groq_client

# Module-level guardian instance
guardian_instance: GuardianAgent | None = None


class GuardianAgent:
    """Monitor agents and enforce simple safety policies."""

    def __init__(self, check_interval: float = 2.0, prevention_rate_limit: int = 3, window_seconds: int = 60):
        """
        Args:
            check_interval: seconds between polls of the global log
            prevention_rate_limit: maximum prevention actions allowed per agent within window
            window_seconds: size of sliding window (seconds) for rate limiting
        """
        self.check_interval = check_interval
        self.prevention_rate_limit = prevention_rate_limit
        self.window_seconds = window_seconds
        self._running = False
        self._thread = None

        # tracking: agent_id -> deque[timestamp of prevention action]
        self._prevention_history: Dict[str, deque[datetime]] = defaultdict(deque)

        # index of last processed global_log event
        self._processed_index = 0

        # guardian audit log
        self.audit_log: list[Dict[str, Any]] = []

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="GuardianAgent")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while self._running:
            try:
                self._process_new_events()
            except Exception as e:
                # keep guardian resilient
                self._audit({'level': 'error', 'message': f'guardian error: {e}', 'time': datetime.now().isoformat()})
            time.sleep(self.check_interval)

    def _process_new_events(self) -> None:
        log = agent_manager.global_log
        # Process events we haven't seen yet
        new_events = log[self._processed_index:]
        for ev in new_events:
            self._handle_event(ev)
            self._processed_index += 1

    def _handle_event(self, ev: Dict[str, Any]) -> None:
        event_type = ev.get('event')
        if event_type == 'prevention_action':
            agent_id = ev.get('data', {}).get('agent_id') or ev.get('agent_id') or ev.get('data', {}).get('agent')
            # best-effort: the event includes a threat_type and action
            threat_type = ev.get('threat_type') or ev.get('data', {}).get('threat_type')
            action = ev.get('action') or ev.get('data', {}).get('action')
            # If agent_id missing, try to infer from recent events
            if not agent_id:
                agent_id = ev.get('data', {}).get('agent_id')

            now = datetime.now()
            if agent_id:
                # load per-agent override from config if present
                guardian_cfg = get_guardian_config()
                per_agent = guardian_cfg.get('per_agent', {}) or {}
                agent_policy = per_agent.get(agent_id, {})

                rate_limit = agent_policy.get('prevention_rate_limit', self.prevention_rate_limit)
                window_seconds = agent_policy.get('window_seconds', self.window_seconds)

                dq = self._prevention_history[agent_id]
                dq.append(now)
                # prune old entries
                cutoff = now - timedelta(seconds=window_seconds)
                while dq and dq[0] < cutoff:
                    dq.popleft()

                # Optional model-based scoring
                model_pause = False
                try:
                    cfg = get_guardian_config() or {}
                    use_model = bool(cfg.get("use_model_scoring", False))
                    model_threshold = int(cfg.get("model_confidence_threshold", 80))
                except Exception:
                    use_model = False
                    model_threshold = 80

                if use_model and groq_client.is_configured():
                    try:
                        text = f"Agent {agent_id} action: {action} on threat {threat_type}"
                        analysis = groq_client.analyze_threat(text, indicators=[threat_type] if threat_type else None)
                        if isinstance(analysis, dict):
                            conf = int(analysis.get("confidence", 0))
                            should = bool(analysis.get("should_prevent", False))
                            model_pause = should and conf >= model_threshold
                    except Exception:
                        model_pause = False

                # If rate exceeded or model suggests pause, take action
                if len(dq) > rate_limit or model_pause:
                    # pause the offending agent and audit
                    paused = False
                    if agent_id in agent_manager.agents:
                        paused = agent_manager.stop_agent(agent_id)
                    self._audit({
                        'level': 'warning',
                        'message': 'Prevention rate limit exceeded or model flagged agent',
                        'agent_id': agent_id,
                        'count': len(dq),
                        'paused': paused,
                        'time': now.isoformat(),
                        'threat_type': threat_type,
                        'action': action,
                        'used_rate_limit': rate_limit,
                        'model_pause': model_pause,
                    })

        # Other event checks can be added here (e.g., unexpected remediation, repeated failures)

    def _audit(self, record: Dict[str, Any]) -> None:
        self.audit_log.append(record)


def create_and_start_guardian(check_interval: float | None = None, prevention_rate_limit: int | None = None, window_seconds: int | None = None, use_config: bool = True) -> GuardianAgent:
    """Create and start a GuardianAgent.

    When `use_config` is True, values missing (None) will be populated from
    `whitecell.config.get_guardian_config()` allowing centralized policy control.
    """
    if use_config:
        cfg = get_guardian_config() or {}
        if check_interval is None:
            check_interval = float(cfg.get("check_interval", 2.0))
        if prevention_rate_limit is None:
            prevention_rate_limit = int(cfg.get("prevention_rate_limit", 3))
        if window_seconds is None:
            window_seconds = int(cfg.get("window_seconds", 60))

    # Fallback to defaults if still None
    check_interval = float(check_interval or 2.0)
    prevention_rate_limit = int(prevention_rate_limit or 3)
    window_seconds = int(window_seconds or 60)

    g = GuardianAgent(check_interval=check_interval, prevention_rate_limit=prevention_rate_limit, window_seconds=window_seconds)
    g.start()
    return g


def start_guardian_from_config() -> GuardianAgent:
    """Start the global guardian instance from config and return it."""
    global guardian_instance
    if guardian_instance and guardian_instance._running:
        return guardian_instance
    cfg = get_guardian_config() or {}
    guardian_instance = create_and_start_guardian(
        check_interval=cfg.get("check_interval"),
        prevention_rate_limit=cfg.get("prevention_rate_limit"),
        window_seconds=cfg.get("window_seconds"),
        use_config=False,
    )
    return guardian_instance


def stop_guardian() -> bool:
    """Stop the global guardian instance if running."""
    global guardian_instance
    if not guardian_instance:
        return False
    guardian_instance.stop()
    guardian_instance = None
    return True


def get_guardian_status() -> dict:
    """Return status information about the global guardian instance."""
    if not guardian_instance:
        return {"running": False}
    return {
        "running": guardian_instance._running,
        "audit_log_count": len(guardian_instance.audit_log),
        "prevention_history_agents": list(guardian_instance._prevention_history.keys()),
    }
