import threading
import time


class StateStore:
    def __init__(self):
        self._states = {}
        self._lock = threading.Lock()

    def get_all(self):
        with self._lock:
            return {k: dict(v) for k, v in self._states.items()}

    def get(self, monitor_id):
        with self._lock:
            return dict(self._states.get(monitor_id, {}))

    def _default_state(self, monitor_id):
        return {
            "monitor_id": monitor_id,
            "last_count": None,
            "previous_count": None,
            "last_rule_reasons": [],
            "last_check": None,
            "last_alert": 0,
            "alert_count": 0,
            "status": "unknown",
            "errors": 0,
            "count_samples": [],
            "connection_ok": None,
            "last_error": None,
            "consecutive_failures": 0,
            "error_escalation_sms_sent": False,
            "error_escalation_call_sent": False,
            "error_escalation_bale_sent": False,
        }

    def update(self, monitor_id, **kwargs):
        with self._lock:
            state = self._states.setdefault(monitor_id, self._default_state(monitor_id))
            state.update(kwargs)
            if kwargs:
                state["last_check"] = time.time()

    def append_count_sample(self, monitor_id, count, retention_seconds):
        if retention_seconds <= 0:
            return
        now = time.time()
        cutoff = now - retention_seconds
        with self._lock:
            state = self._states.setdefault(monitor_id, self._default_state(monitor_id))
            samples = list(state.get("count_samples") or [])
            samples.append([now, int(count)])
            samples = [s for s in samples if s[0] >= cutoff]
            samples.sort(key=lambda x: x[0])
            state["count_samples"] = samples

    def volatility_baseline(self, monitor_id):
        with self._lock:
            state = self._states.get(monitor_id) or {}
            samples = state.get("count_samples") or []
            if not samples:
                return None
            return int(samples[0][1])
