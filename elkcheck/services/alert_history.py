import os
import threading
from collections import deque
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
from elkcheck.persistence.secure_json import load_json, save_json

_TZ_TEHRAN = ZoneInfo("Asia/Tehran")


def format_tehran(dt_utc):
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    local = dt_utc.astimezone(_TZ_TEHRAN)
    return local.strftime("%Y-%m-%d %H:%M:%S") + " (Tehran)"


class AlertHistory:

    def __init__(self, path="alert_history.json", max_entries=400):
        self.path = path
        self.max_entries = max_entries
        self._entries = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._load_from_disk()

    def _ensure_time_local(self, row):
        row = dict(row)
        if row.get("time_local"):
            return row
        ts = row.get("ts")
        try:
            if isinstance(ts, (int, float)):
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                row["time_local"] = format_tehran(dt)
                return row
        except (OSError, OverflowError, ValueError):
            pass
        row["time_local"] = row.get("time_utc") or "—"
        return row

    def _load_from_disk(self):
        if not os.path.exists(self.path):
            return
        try:
            data = load_json(self.path, {"entries": []})
            items = data.get("entries") or []
            for row in items[-self.max_entries :]:
                self._entries.append(row)
        except Exception:
            pass

    def _save(self):
        try:
            save_json(self.path, {"entries": list(self._entries)})
        except Exception:
            pass

    def add(
        self,
        *,
        monitor_id,
        monitor_name,
        kind,
        channel,
        status,
        detail="",
        reasons=None,
    ):
        now = datetime.now(timezone.utc)
        row = {
            "ts": now.timestamp(),
            "time_local": format_tehran(now),
            "monitor_id": monitor_id,
            "monitor_name": monitor_name or "Monitor",
            "kind": kind,
            "channel": channel,
            "status": status,
            "detail": (detail or "")[:900],
            "reasons": reasons if isinstance(reasons, list) else None,
        }
        with self._lock:
            self._entries.append(row)
            self._save()
        return row

    def recent(self, limit=80):
        limit = max(1, min(int(limit or 80), self.max_entries))
        with self._lock:
            items = list(self._entries)
        items.reverse()
        return [self._ensure_time_local(r) for r in items[:limit]]

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._save()


_store = None


def configure(path="alert_history.json"):
    global _store
    _store = AlertHistory(path=path)


def get_store():
    global _store
    if _store is None:
        configure()
    return _store
