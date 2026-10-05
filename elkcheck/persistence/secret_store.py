import json
import os
import secrets

from elkcheck.persistence.data_paths import data_file


class SecretStore:


    def __init__(self, path=None):
        self.path = path or data_file("secrets.json")
        self._data = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self._data = {}
            self.save()
            return self._data
        try:
            with open(self.path, "r", encoding="utf-8") as fp:
                raw = json.load(fp)
            self._data = raw if isinstance(raw, dict) else {}
        except Exception:
            self._data = {}
        return self._data

    def save(self):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fp:
            json.dump(self._data, fp, indent=2, ensure_ascii=False)

    def get_or_create(self, key):
        value = (self._data.get(key) or "").strip()
        if value:
            return value
        value = secrets.token_urlsafe(64)
        self._data[key] = value
        self.save()
        return value

