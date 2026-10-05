import os
import time
import ipaddress
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
from elkcheck.persistence.secure_json import load_json, save_json

_TZ_TEHRAN = ZoneInfo("Asia/Tehran")


def _now_local_str():
    return datetime.now(timezone.utc).astimezone(_TZ_TEHRAN).strftime("%Y-%m-%d %H:%M:%S (Tehran)")


class SecurityStore:
    def __init__(self, path="security.json"):
        self.path = path
        self.data = {
            "cooldowns": {},
            "superuser_fail_by_ip": {},
            "banned_ips": {},
            "manual_blacklist": {},
            "whitelist": {"enabled": False, "ips": []},
            "superuser_warning": {"pending": False, "message": ""},
        }
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.save()
            return self.data
        try:
            raw = load_json(self.path, {})
            if isinstance(raw, dict):
                self.data.update(raw)
        except Exception:
            pass
        self.data.setdefault("cooldowns", {})
        self.data.setdefault("superuser_fail_by_ip", {})
        self.data.setdefault("banned_ips", {})
        self.data.setdefault("manual_blacklist", {})
        self.data.setdefault("whitelist", {"enabled": False, "ips": []})
        self.data["whitelist"].setdefault("enabled", False)
        self.data["whitelist"].setdefault("ips", [])
        self.data.setdefault("superuser_warning", {"pending": False, "message": ""})
        return self.data

    def save(self):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        save_json(self.path, self.data)

    @staticmethod
    def normalize_ip(ip_text):
        text = str(ip_text or "").strip()
        if not text:
            return "unknown"
        if "," in text:
            text = text.split(",")[0].strip()
        if text.lower() == "unknown":
            return "unknown"
        if text.startswith("::ffff:"):
            text = text[7:]
        # Strip :port for IPv4 entries like 192.168.1.10:51234
        if text.count(":") == 1 and "." in text:
            host, port = text.rsplit(":", 1)
            if port.isdigit():
                text = host
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text

    @staticmethod
    def _key(ip, username):
        return f"{SecurityStore.normalize_ip(ip)}|{(username or '').strip().lower()}"

    def cooldown_remaining(self, ip, username, *, min_seconds=5):
        key = self._key(ip, username)
        last = float((self.data.get("cooldowns") or {}).get(key) or 0)
        left = min_seconds - (time.time() - last)
        return max(0.0, left)

    def mark_attempt(self, ip, username):
        cds = self.data.setdefault("cooldowns", {})
        cds[self._key(ip, username)] = time.time()
        cutoff = time.time() - 3600
        self.data["cooldowns"] = {k: v for k, v in cds.items() if float(v) >= cutoff}
        self.save()

    def is_ip_banned(self, ip):
        ip = self.normalize_ip(ip)
        return ip in (self.data.get("banned_ips") or {})

    def is_ip_denied_access(self, ip):
        ip = self.normalize_ip(ip)
        if ip in (self.data.get("banned_ips") or {}):
            return True, "This IP is blocked."
        if ip in (self.data.get("manual_blacklist") or {}):
            return True, "This IP is blacklisted by administrator."
        wl = self.data.get("whitelist") or {}
        if bool(wl.get("enabled")):
            ips = set(wl.get("ips") or [])
            if ip not in ips:
                return True, "Access denied"
        return False, ""

    def list_banned_ips(self):
        out = []
        for ip, row in (self.data.get("banned_ips") or {}).items():
            out.append(
                {
                    "ip": ip,
                    "reason": row.get("reason") or "Blocked after brute-force attempts on superuser.",
                    "banned_at": row.get("banned_at") or "",
                    "attempts": int(row.get("attempts") or 0),
                }
            )
        return sorted(out, key=lambda x: x.get("banned_at", ""), reverse=True)

    def list_manual_blacklist(self):
        out = []
        for ip, row in (self.data.get("manual_blacklist") or {}).items():
            out.append(
                {
                    "ip": ip,
                    "reason": row.get("reason") or "Blacklisted by administrator.",
                    "added_at": row.get("added_at") or "",
                }
            )
        return sorted(out, key=lambda x: x.get("added_at", ""), reverse=True)

    def get_whitelist(self):
        wl = self.data.get("whitelist") or {}
        return {"enabled": bool(wl.get("enabled")), "ips": list(wl.get("ips") or [])}

    def unban_ip(self, ip):
        ip = self.normalize_ip(ip)
        bans = self.data.setdefault("banned_ips", {})
        fails = self.data.setdefault("superuser_fail_by_ip", {})
        bans.pop(ip, None)
        fails.pop(ip, None)
        self.save()

    def blacklist_ip(self, ip, reason=""):
        ip = self.normalize_ip(ip)
        if not ip:
            return
        b = self.data.setdefault("manual_blacklist", {})
        b[ip] = {"reason": (reason or "").strip() or "Blacklisted by administrator.", "added_at": _now_local_str()}
        self.save()

    def unblacklist_ip(self, ip):
        ip = self.normalize_ip(ip)
        b = self.data.setdefault("manual_blacklist", {})
        b.pop(ip, None)
        self.save()

    def add_whitelist_ip(self, ip):
        ip = self.normalize_ip(ip)
        if not ip:
            return
        wl = self.data.setdefault("whitelist", {"enabled": False, "ips": []})
        ips = list(wl.get("ips") or [])
        if ip not in ips:
            ips.append(ip)
        wl["ips"] = sorted(set(ips))
        self.save()

    def remove_whitelist_ip(self, ip):
        ip = self.normalize_ip(ip)
        wl = self.data.setdefault("whitelist", {"enabled": False, "ips": []})
        ips = [x for x in (wl.get("ips") or []) if x != ip]
        wl["ips"] = ips
        if wl.get("enabled") and len(ips) == 0:
            wl["enabled"] = False
        self.save()

    def set_whitelist_enabled(self, enabled):
        wl = self.data.setdefault("whitelist", {"enabled": False, "ips": []})
        want = bool(enabled)
        if want and len(wl.get("ips") or []) == 0:
            raise ValueError("Whitelist must include at least one IP before enabling.")
        wl["enabled"] = want
        self.save()

    def register_superuser_failure(self, ip, username, *, threshold=5):
        ip = self.normalize_ip(ip)
        fails = self.data.setdefault("superuser_fail_by_ip", {})
        row = dict(fails.get(ip) or {})
        row["count"] = int(row.get("count") or 0) + 1
        row["last_at"] = _now_local_str()
        row["username"] = username
        fails[ip] = row
        banned_now = False
        if row["count"] >= threshold:
            bans = self.data.setdefault("banned_ips", {})
            if ip not in bans:
                bans[ip] = {
                    "reason": "Blocked after repeated failed superuser login attempts.",
                    "banned_at": _now_local_str(),
                    "attempts": row["count"],
                }
                banned_now = True
            self.data["superuser_warning"] = {
                "pending": True,
                "message": f"Security warning: brute-force attempt blocked. IP {ip} was banned at {_now_local_str()}.",
            }
        self.save()
        return {"count": row["count"], "banned_now": banned_now}

    def get_superuser_warning(self):
        w = self.data.get("superuser_warning") or {}
        return {"pending": bool(w.get("pending")), "message": w.get("message") or ""}

    def clear_superuser_warning(self):
        self.data["superuser_warning"] = {"pending": False, "message": ""}
        self.save()

