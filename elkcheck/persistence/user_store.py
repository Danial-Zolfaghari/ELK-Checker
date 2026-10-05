import os
import secrets
import uuid
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

from werkzeug.security import check_password_hash, generate_password_hash
from elkcheck.persistence.secure_json import load_json, save_json

_TZ_TEHRAN = ZoneInfo("Asia/Tehran")


class UserStore:
    def __init__(self, path="users.json"):
        self.path = path
        self.users = []
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.users = []
            self.save()
            return
        self.users = load_json(self.path, [])
        self._migrate_roles()
        self._migrate_active()
        self._migrate_security_fields()

    def _migrate_roles(self):
        changed = False
        for user in self.users:
            if user.get("role") == "admin":
                user["role"] = "superuser"
                changed = True
        if changed:
            self.save()

    def _migrate_active(self):
        changed = False
        for user in self.users:
            if "active" not in user:
                user["active"] = True
                changed = True
        if changed:
            self.save()

    def _migrate_security_fields(self):
        changed = False
        for user in self.users:
            if "failed_login_attempts" not in user:
                user["failed_login_attempts"] = 0
                changed = True
            if "last_login_local" not in user:
                user["last_login_local"] = None
                changed = True
            if "daily_login_counts" not in user or not isinstance(user.get("daily_login_counts"), dict):
                user["daily_login_counts"] = {}
                changed = True
        if changed:
            self.save()

    def save(self):
        save_json(self.path, self.users)

    def ensure_admin(self):
        if self.users:
            return
        username = os.getenv("ELK_ADMIN_USERNAME", "admin").strip() or "admin"
        password = os.getenv("ELK_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
        if not os.getenv("ELK_ADMIN_PASSWORD"):
            print("[ELK-Checker] First-run admin password:", password)
            print("[ELK-Checker] Set ELK_ADMIN_PASSWORD before first run in production.")
        self.users.append(
            {
                "id": "admin",
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": "superuser",
                "active": True,
                "failed_login_attempts": 0,
                "last_login_local": None,
                "daily_login_counts": {},
            }
        )
        self.save()

    def authenticate(self, username, password):
        for user in self.users:
            if not user.get("active", True):
                continue
            if user["username"] == username and check_password_hash(user["password_hash"], password):
                return {"id": user["id"], "username": user["username"], "role": user.get("role", "user")}
        return None

    def list_public(self):
        today = datetime.now(timezone.utc).astimezone(_TZ_TEHRAN).strftime("%Y-%m-%d")
        return [
            {
                "id": u["id"],
                "username": u["username"],
                "role": u.get("role", "user"),
                "active": u.get("active", True),
                "failed_login_attempts": int(u.get("failed_login_attempts") or 0),
                "last_login_local": u.get("last_login_local"),
                "login_count_today": int((u.get("daily_login_counts") or {}).get(today) or 0),
            }
            for u in self.users
        ]

    def find_by_id(self, user_id):
        for user in self.users:
            if user["id"] == user_id:
                return user
        return None

    def find_by_username(self, username):
        for user in self.users:
            if user["username"] == username:
                return user
        return None

    def create_user(self, username, password, role="user"):
        username = (username or "").strip()
        if not username or not password:
            raise ValueError("Username and password are required.")
        if self.find_by_username(username):
            raise ValueError("Username already exists.")
        role = role if role in ("user", "superuser") else "user"
        self.users.append(
            {
                "id": str(uuid.uuid4()),
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": role,
                "active": True,
                "failed_login_attempts": 0,
                "last_login_local": None,
                "daily_login_counts": {},
            }
        )
        self.save()
        return self.find_by_username(username)

    def set_password(self, user_id, new_password):
        u = self.find_by_id(user_id)
        if not u:
            raise ValueError("User not found.")
        pw = (new_password or "").strip()
        if len(pw) < 4:
            raise ValueError("Password must be at least 4 characters.")
        u["password_hash"] = generate_password_hash(pw)
        self.save()
        return u

    def change_own_password(self, user_id, current_password, new_password):
        u = self.find_by_id(user_id)
        if not u or not u.get("active", True):
            raise ValueError("Invalid user.")
        if not check_password_hash(u["password_hash"], current_password):
            raise ValueError("Current password is incorrect.")
        pw = (new_password or "").strip()
        if len(pw) < 4:
            raise ValueError("New password must be at least 4 characters.")
        u["password_hash"] = generate_password_hash(pw)
        self.save()
        return u

    def admin_update_user(self, target_id, *, password=None, active=None):
        u = self.find_by_id(target_id)
        if not u:
            raise ValueError("User not found.")
        if active is not None:
            want = bool(active)
            if not want and u.get("role") == "superuser":
                active_supers = [
                    x
                    for x in self.users
                    if x.get("role") == "superuser" and x.get("active", True)
                ]
                if len(active_supers) <= 1:
                    raise ValueError("Cannot disable the last active superuser.")
            u["active"] = want
        if password is not None:
            pw = (password or "").strip()
            if len(pw) < 4:
                raise ValueError("Password must be at least 4 characters.")
            u["password_hash"] = generate_password_hash(pw)
        self.save()
        return u

    def record_failed_login(self, username, *, threshold=5):
        u = self.find_by_username((username or "").strip())
        if not u:
            return {"found": False, "disabled_now": False, "attempts": 0, "is_superuser": False}
        attempts = int(u.get("failed_login_attempts") or 0) + 1
        u["failed_login_attempts"] = attempts
        disabled_now = False
        if u.get("role") != "superuser" and attempts >= int(threshold or 5) and u.get("active", True):
            u["active"] = False
            disabled_now = True
        self.save()
        return {
            "found": True,
            "disabled_now": disabled_now,
            "attempts": attempts,
            "is_superuser": u.get("role") == "superuser",
        }

    def record_login_success(self, user_id):
        u = self.find_by_id(user_id)
        if not u:
            return
        now_local = datetime.now(timezone.utc).astimezone(_TZ_TEHRAN)
        day_key = now_local.strftime("%Y-%m-%d")
        counts = dict(u.get("daily_login_counts") or {})
        keys = sorted(counts.keys())
        if len(keys) > 30:
            for k in keys[:-30]:
                counts.pop(k, None)
        counts[day_key] = int(counts.get(day_key) or 0) + 1
        u["daily_login_counts"] = counts
        u["last_login_local"] = now_local.strftime("%Y-%m-%d %H:%M:%S (Tehran)")
        u["failed_login_attempts"] = 0
        self.save()

    def delete_user(self, user_id):
        victim = self.find_by_id(user_id)
        if not victim:
            raise ValueError("User not found.")
        superusers = [u for u in self.users if u.get("role") == "superuser"]
        if victim.get("role") == "superuser" and len(superusers) <= 1:
            raise ValueError("Cannot delete the last superuser account.")
        self.users = [u for u in self.users if u["id"] != user_id]
        self.save()
