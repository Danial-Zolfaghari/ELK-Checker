import os
from copy import deepcopy
from elkcheck.persistence.secure_json import load_json, save_json

DEFAULT_APP_SETTINGS = {
    "bale": {
        "bot_url": "http://localhost:8080",
    },
    "security": {
        "session_timeout_minutes": 15,
        "brute_force_threshold": 5,
    },
}


class AppSettingsStore:

    def __init__(self, path="app_settings.json"):
        self.path = path
        self._data = deepcopy(DEFAULT_APP_SETTINGS)

    def load(self):
        if not os.path.exists(self.path):
            self._data = deepcopy(DEFAULT_APP_SETTINGS)
            self.save()
            return self._data
        try:
            raw = load_json(self.path, {})
            merged = deepcopy(DEFAULT_APP_SETTINGS)
            for key, value in (raw or {}).items():
                if key == "bale" and isinstance(value, dict):
                    merged["bale"] = {**merged.get("bale", {}), **value}
                elif key == "security" and isinstance(value, dict):
                    merged["security"] = {**merged.get("security", {}), **value}
                else:
                    merged[key] = value
            self._data = merged
        except Exception:
            self._data = deepcopy(DEFAULT_APP_SETTINGS)
        return self._data

    def save(self):
        save_json(self.path, self._data)

    def get(self):
        return deepcopy(self._data)

    def update_bale_bot_url(self, bot_url):
        bot_url = (bot_url or "").strip()
        self._data.setdefault("bale", {})
        self._data["bale"]["bot_url"] = bot_url
        self.save()
        return self.get()

    def update_session_timeout_minutes(self, minutes):
        try:
            m = int(minutes)
        except (TypeError, ValueError):
            m = 15
        m = max(5, min(m, 24 * 60))
        self._data.setdefault("security", {})
        self._data["security"]["session_timeout_minutes"] = m
        self.save()
        return self.get()

    def get_session_timeout_minutes(self):
        self.load()
        sec = self._data.get("security") or {}
        raw = sec.get("session_timeout_minutes")
        if raw is None:
            return 15
        try:
            return max(5, min(int(raw), 24 * 60))
        except (TypeError, ValueError):
            return 15

    def update_brute_force_threshold(self, threshold):
        try:
            v = int(threshold)
        except (TypeError, ValueError):
            v = 5
        v = max(3, min(v, 20))
        self._data.setdefault("security", {})
        self._data["security"]["brute_force_threshold"] = v
        self.save()
        return self.get()

    def get_brute_force_threshold(self):
        self.load()
        sec = self._data.get("security") or {}
        raw = sec.get("brute_force_threshold")
        if raw is None:
            return 5
        try:
            return max(3, min(int(raw), 20))
        except (TypeError, ValueError):
            return 5
