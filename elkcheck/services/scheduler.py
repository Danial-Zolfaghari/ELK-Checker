import os
import threading
import time

from elkcheck.services.check_executor import run_monitor_check


class MonitorScheduler:

    def __init__(self, config_store, state_store, use_celery=True):
        self.config_store = config_store
        self.state_store = state_store
        self.use_celery = use_celery
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _enqueue_celery(self, monitor):
        if not self.use_celery:
            return False
        try:
            from elkcheck.tasks.monitor_tasks import monitor_check_task

            if monitor_check_task is None:
                return False
            monitor_check_task.delay(monitor)
            return True
        except Exception:
            return False

    def _loop(self):
        tick_seconds = max(3, int(os.environ.get("SCHEDULER_TICK_SECONDS", "5")))
        while not self._stop.is_set():
            try:
                data = self.config_store.load()
                monitors = [m for m in data.get("monitors", []) if m.get("enabled", True)]
                default_iv = int(data.get("global_settings", {}).get("default_check_interval", 60))
                now = time.time()
                for monitor in monitors:
                    interval = int(monitor.get("check_interval") or default_iv)
                    interval = max(5, interval)
                    st = self.state_store.get(monitor["id"])
                    last = st.get("last_check")
                    if last is not None and (now - float(last)) < interval:
                        continue
                    try:
                        if not self._enqueue_celery(monitor):
                            run_monitor_check(monitor, self.state_store)
                    except Exception:
                        run_monitor_check(monitor, self.state_store)
            except Exception:
                pass
            self._stop.wait(tick_seconds)
