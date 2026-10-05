import os
import uuid
from copy import deepcopy

from elkcheck.persistence.monitor_crypto import decrypt_if_needed, encrypt_if_possible
from elkcheck.persistence.secure_json import load_json, save_json


class ServerStore:
    def __init__(self, path):
        self.path = path
        self.data = {"servers": []}

    def load(self):
        if not os.path.exists(self.path):
            self.save({"servers": []})
            self.data = {"servers": []}
            return self.data
        raw = load_json(self.path, {"servers": []})
        servers = raw.get("servers", []) if isinstance(raw, dict) else []
        self.data = {"servers": [self._decrypt_server(s) for s in servers if isinstance(s, dict)]}
        self.save(self.data)
        return self.data

    def save(self, data):
        self.data = {"servers": list(data.get("servers", []))}
        to_disk = {"servers": [self._encrypt_server(s) for s in self.data.get("servers", [])]}
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        save_json(self.path, to_disk)

    def list_public(self):
        out = []
        for s in self.data.get("servers", []):
            out.append(
                {
                    "id": s.get("id", ""),
                    "name": s.get("name", "") or s.get("hostname", ""),
                    "hostname": s.get("hostname", ""),
                    "username": s.get("username", ""),
                }
            )
        return out

    def get_by_id(self, server_id):
        sid = (server_id or "").strip()
        if not sid:
            return None
        for s in self.data.get("servers", []):
            if s.get("id") == sid:
                return deepcopy(s)
        return None

    def upsert(self, payload):
        name = (payload.get("name") or "").strip()
        hostname = (payload.get("hostname") or "").strip()
        username = (payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        sid = (payload.get("id") or "").strip()
        servers = self.data.setdefault("servers", [])
        existing = None
        if sid:
            for s in servers:
                if s.get("id") == sid:
                    existing = s
                    break
            if existing is None:
                raise ValueError("Server not found.")
        if not name:
            name = hostname
        if not name:
            raise ValueError("Server name is required.")
        if not hostname:
            raise ValueError("Hostname is required.")
        if not username:
            raise ValueError("Username is required.")
        if not password and existing is None:
            raise ValueError("Password is required.")
        if not sid:
            sid = f"srv_{uuid.uuid4().hex[:12]}"
        if not password and existing is not None:
            password = str(existing.get("password") or "")
        item = {"id": sid, "name": name, "hostname": hostname, "username": username, "password": password}
        for i, s in enumerate(servers):
            if s.get("id") == sid:
                servers[i] = item
                self.save(self.data)
                return item
        servers.append(item)
        self.save(self.data)
        return item

    def delete(self, server_id):
        sid = (server_id or "").strip()
        if not sid:
            raise ValueError("Server id is required.")
        before = len(self.data.get("servers", []))
        self.data["servers"] = [s for s in self.data.get("servers", []) if s.get("id") != sid]
        if len(self.data["servers"]) == before:
            raise ValueError("Server not found.")
        self.save(self.data)

    @staticmethod
    def _encrypt_server(server):
        out = deepcopy(server)
        out["hostname"] = encrypt_if_possible(out.get("hostname", ""))
        out["username"] = encrypt_if_possible(out.get("username", ""))
        out["password"] = encrypt_if_possible(out.get("password", ""))
        return out

    @staticmethod
    def _decrypt_server(server):
        out = deepcopy(server)
        out["hostname"] = decrypt_if_needed(out.get("hostname", ""))
        out["username"] = decrypt_if_needed(out.get("username", ""))
        out["password"] = decrypt_if_needed(out.get("password", ""))
        return out
