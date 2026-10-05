import os

from elkcheck.persistence.data_paths import data_file
from elkcheck.persistence.server_store import ServerStore


def resolve_monitor_connection(monitor, server_store=None):
    out = dict(monitor or {})
    sid = (out.get("server_id") or "").strip()
    if not sid:
        return out
    store = server_store
    if store is None:
        store = ServerStore(path=os.getenv("SERVERS_FILE", data_file("servers.json")))
        store.load()
    server = store.get_by_id(sid)
    if not server:
        raise ValueError(f"Server '{sid}' not found.")
    out["host"] = (server.get("hostname") or "").strip()
    out["username"] = (server.get("username") or "").strip()
    out["password"] = str(server.get("password") or "")
    return out
