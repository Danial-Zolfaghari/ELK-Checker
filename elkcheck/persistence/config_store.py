import json
import os
from copy import deepcopy

from elkcheck.persistence.monitor_crypto import decrypt_if_needed, encrypt_if_possible
from elkcheck.persistence.secure_json import load_json, save_json

DEFAULT_CONFIG = {
    "global_settings": {
        "default_check_interval": 60,
        "default_window_seconds": 60,
        "contacts": [],
    },
    "monitors": [],
}


def _default_rules():
    return {
        "no_hit": {"enabled": True, "notify_on_recovery": False},
        "reverse_hit": {"enabled": False, "notify_on_recovery": False},
        "count_threshold": {"enabled": False, "operator": "gt", "value": 0},
        "volatility": {"enabled": False, "percent": 0, "window_minutes": 5},
        "error_escalation": {
            "enabled": False,
            "sms_after_failures": 0,
            "call_after_failures": 0,
            "bale_after_failures": 0,
        },
    }


def _normalize_monitor(raw):
    notif_in = raw.get("notifications") or {}
    sms_src = notif_in.get("sms") or raw.get("sms") or {}
    call_src = notif_in.get("call") or raw.get("call") or {}
    kavenegar_api_key = notif_in.get("kavenegar_api_key") or raw.get("kavenegar_api_key", "")
    sms_sender = notif_in.get("sms_sender") or raw.get("sms_sender", "")

    notifications = {
        "kavenegar_api_key": kavenegar_api_key,
        "sms_sender": sms_sender,
        "sms": {
            "enabled": sms_src.get("enabled", True),
            "message": str(sms_src.get("message", "")).strip(),
            "recipients": list(sms_src.get("recipients") or []),
        },
        "call": {
            "enabled": call_src.get("enabled", False),
            "message": str(call_src.get("message", "")).strip(),
            "recipients": list(call_src.get("recipients") or []),
        },
        "recovery": {
            "sms": {
                "enabled": False,
                "message": "",
            },
            "call": {
                "enabled": False,
                "message": "",
            },
            "bale": {
                "enabled": False,
                "message": "",
            },
        },
    }
    bale_src = notif_in.get("bale") or {}
    rid = bale_src.get("requester_id")
    requester_id = None
    if rid is not None and rid != "":
        try:
            requester_id = int(rid)
        except (TypeError, ValueError):
            requester_id = None
    notifications["bale"] = {
        "enabled": bool(bale_src.get("enabled", False)),
        "token": str(bale_src.get("token", "")).strip(),
        "script_name": str(bale_src.get("script_name", "")).strip(),
        "message": str(bale_src.get("message", "")).strip(),
        "requester_id": requester_id,
    }
    recovery_src = notif_in.get("recovery") or {}
    notifications["recovery"]["sms"]["enabled"] = bool((recovery_src.get("sms") or {}).get("enabled", False))
    notifications["recovery"]["sms"]["message"] = str((recovery_src.get("sms") or {}).get("message", "")).strip()
    notifications["recovery"]["call"]["enabled"] = bool((recovery_src.get("call") or {}).get("enabled", False))
    notifications["recovery"]["call"]["message"] = str((recovery_src.get("call") or {}).get("message", "")).strip()
    notifications["recovery"]["bale"]["enabled"] = bool((recovery_src.get("bale") or {}).get("enabled", False))
    notifications["recovery"]["bale"]["message"] = str((recovery_src.get("bale") or {}).get("message", "")).strip()

    legacy_contacts = list(raw.get("contacts") or [])
    if legacy_contacts:
        if not notifications["sms"]["recipients"]:
            notifications["sms"]["recipients"] = list(legacy_contacts)
        if notifications["call"]["enabled"] and not notifications["call"]["recipients"]:
            notifications["call"]["recipients"] = list(legacy_contacts)

    merged = notifications["sms"]["recipients"] + notifications["call"]["recipients"]
    contacts = list(dict.fromkeys(merged))

    monitor = {
        "id": raw.get("id") or f"mon_{abs(hash(raw.get('name', 'monitor')))}",
        "name": raw.get("name", "Unnamed Monitor"),
        "enabled": raw.get("enabled", True),
        "server_id": str(raw.get("server_id", "")).strip(),
        "host": raw.get("host") or raw.get("elasticsearch", {}).get("host", ""),
        "index": raw.get("index") or raw.get("elasticsearch", {}).get("index", ""),
        "username": raw.get("user") or raw.get("username") or raw.get("elasticsearch", {}).get("user", ""),
        "password": raw.get("pass") or raw.get("password") or raw.get("elasticsearch", {}).get("pass", ""),
        "query_mode": raw.get("query_mode", "json"),
        "query_json": raw.get("query_json") or raw.get("query") or '{"query":{"match_all":{}}}',
        "query_kql": raw.get("query_kql", ""),
        "timestamp_field": raw.get("timestamp_field", "@timestamp"),
        "window_seconds": int(raw.get("window_seconds", 60)),
        "check_interval": int(raw.get("check_interval", 60)),
        "alert_cooldown": int(raw.get("alert_cooldown", 300)),
        "contacts": contacts,
        "notifications": notifications,
        "rules": deepcopy(_default_rules()),
    }
    user_rules = raw.get("rules", {})
    for key, value in user_rules.items():
        if key in monitor["rules"] and isinstance(value, dict):
            monitor["rules"][key].update(value)
    monitor["rules"]["no_hit"].setdefault("notify_on_recovery", False)
    monitor["rules"]["reverse_hit"].setdefault("notify_on_recovery", False)
    monitor["rules"]["volatility"].setdefault("window_minutes", 5)
    esc = monitor["rules"].setdefault("error_escalation", {})
    esc.setdefault("enabled", False)
    esc.setdefault("sms_after_failures", 0)
    esc.setdefault("call_after_failures", 0)
    esc.setdefault("bale_after_failures", 0)
    return monitor


def _encrypt_monitor_sensitive(m):
    out = deepcopy(m)
    out["host"] = encrypt_if_possible(out.get("host", ""))
    out["index"] = encrypt_if_possible(out.get("index", ""))
    out["username"] = encrypt_if_possible(out.get("username", ""))
    out["password"] = encrypt_if_possible(out.get("password", ""))
    n = out.setdefault("notifications", {})
    n["kavenegar_api_key"] = encrypt_if_possible(n.get("kavenegar_api_key", ""))
    return out


def _decrypt_monitor_sensitive(raw):
    out = deepcopy(raw)
    out["host"] = decrypt_if_needed(out.get("host", ""))
    out["index"] = decrypt_if_needed(out.get("index", ""))
    out["username"] = decrypt_if_needed(out.get("username", ""))
    out["password"] = decrypt_if_needed(out.get("password", ""))
    n = out.setdefault("notifications", {})
    n["kavenegar_api_key"] = decrypt_if_needed(n.get("kavenegar_api_key", ""))
    return out


def validate_bale_notifications(monitor, *, bot_url_global):
    bale = (monitor.get("notifications") or {}).get("bale") or {}
    if not bale.get("enabled"):
        return True, ""
    token = (bale.get("token") or "").strip()
    script_name = (bale.get("script_name") or "").strip()
    if not token or not script_name:
        return False, "When Bale alerts are enabled, token and script name cannot be empty."
    if not (bot_url_global or "").strip():
        return (
            False,
            "Bale bot URL is not configured. A superuser must set it under Management.",
        )
    return True, ""


def _migrate_legacy(data):
    if "global_settings" in data:
        migrated = data
    else:
        migrated = {
            "global_settings": {
                "default_check_interval": data.get("global", {}).get("check_interval", 60),
                "default_window_seconds": data.get("global", {}).get("window_seconds", 60),
                "contacts": data.get("global", {}).get("contacts", []),
            },
            "monitors": data.get("monitors", []),
        }
    migrated["monitors"] = [_normalize_monitor(_decrypt_monitor_sensitive(m)) for m in migrated.get("monitors", [])]
    return migrated


class ConfigStore:
    def __init__(self, path="monitors.json"):
        self.path = path
        self.data = deepcopy(DEFAULT_CONFIG)

    def load(self):
        if not os.path.exists(self.path):
            self.save(DEFAULT_CONFIG)
            self.data = deepcopy(DEFAULT_CONFIG)
            return self.data
        raw = load_json(self.path, deepcopy(DEFAULT_CONFIG))
        self.data = _migrate_legacy(raw)
        self.save(self.data)
        return self.data

    def save(self, data):
        self.data = data
        to_disk = deepcopy(self.data)
        to_disk["monitors"] = [_encrypt_monitor_sensitive(m) for m in to_disk.get("monitors", [])]
        save_json(self.path, to_disk)

    def upsert_monitor(self, monitor):
        monitors = self.data.setdefault("monitors", [])
        for idx, item in enumerate(monitors):
            if item["id"] == monitor["id"]:
                monitors[idx] = monitor
                self.save(self.data)
                return
        monitors.append(monitor)
        self.save(self.data)

    def delete_monitor(self, monitor_id):
        self.data["monitors"] = [m for m in self.data.get("monitors", []) if m["id"] != monitor_id]
        self.save(self.data)

