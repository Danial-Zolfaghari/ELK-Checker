import os

from flask import Blueprint, current_app, jsonify, request, session

from elkcheck.persistence.data_paths import data_dir
from elkcheck.services.alert_history import get_store

from .auth import superuser_required_json

bp = Blueprint("admin", __name__, url_prefix="")


@bp.get("/api/admin/users")
@superuser_required_json
def list_users():
    try:
        return jsonify({"status": "ok", "users": current_app.user_store.list_public()})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/admin/security-status")
@superuser_required_json
def security_status():
    try:
        wl = current_app.security_store.get_whitelist()
        detected_ip_raw = (
            request.headers.get("X-Forwarded-For")
            or request.headers.get("X-Real-IP")
            or request.headers.get("CF-Connecting-IP")
            or request.remote_addr
            or "unknown"
        )
        return jsonify(
            {
                "status": "ok",
                "detected_ip": current_app.security_store.normalize_ip(detected_ip_raw),
                "banned_ips": current_app.security_store.list_banned_ips(),
                "manual_blacklist": current_app.security_store.list_manual_blacklist(),
                "whitelist_enabled": wl.get("enabled", False),
                "whitelist_ips": wl.get("ips", []),
                "warning": current_app.security_store.get_superuser_warning(),
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/unban-ip")
@superuser_required_json
def unban_ip():
    try:
        payload = request.json or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400
        current_app.security_store.unban_ip(ip)
        return jsonify({"status": "ok", "ip": ip})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/blacklist")
@superuser_required_json
def add_blacklist_ip():
    try:
        payload = request.json or {}
        ip = (payload.get("ip") or "").strip()
        reason = (payload.get("reason") or "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400
        current_app.security_store.blacklist_ip(ip, reason=reason)
        return jsonify({"status": "ok", "ip": ip})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/unblacklist")
@superuser_required_json
def remove_blacklist_ip():
    try:
        payload = request.json or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400
        current_app.security_store.unblacklist_ip(ip)
        return jsonify({"status": "ok", "ip": ip})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/whitelist/add")
@superuser_required_json
def add_whitelist_ip():
    try:
        payload = request.json or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400
        current_app.security_store.add_whitelist_ip(ip)
        return jsonify({"status": "ok", "ip": ip})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/whitelist/remove")
@superuser_required_json
def remove_whitelist_ip():
    try:
        payload = request.json or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP is required."}), 400
        current_app.security_store.remove_whitelist_ip(ip)
        return jsonify({"status": "ok", "ip": ip})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/security/whitelist/enable")
@superuser_required_json
def set_whitelist_enabled():
    try:
        payload = request.json or {}
        enabled = bool(payload.get("enabled"))
        current_app.security_store.set_whitelist_enabled(enabled)
        wl = current_app.security_store.get_whitelist()
        return jsonify({"status": "ok", "whitelist_enabled": wl.get("enabled", False), "whitelist_ips": wl.get("ips", [])})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/users")
@superuser_required_json
def create_user():
    try:
        payload = request.json or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
        role = payload.get("role", "user")
        user = current_app.user_store.create_user(username, password, role=role)
        return jsonify(
            {
                "status": "ok",
                "user": {"id": user["id"], "username": user["username"], "role": user.get("role", "user")},
            }
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/admin/bale-settings")
@superuser_required_json
def get_bale_settings():
    try:
        current_app.app_settings_store.load()
        data = current_app.app_settings_store.get()
        bale = data.get("bale") or {}
        return jsonify({"status": "ok", "bot_url": bale.get("bot_url", "")})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/bale-settings")
@superuser_required_json
def set_bale_settings():
    try:
        payload = request.json or {}
        bot_url = (payload.get("bot_url") or "").strip()
        current_app.app_settings_store.update_bale_bot_url(bot_url)
        return jsonify({"status": "ok", "bot_url": bot_url})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/admin/session-settings")
@superuser_required_json
def get_session_settings():
    try:
        current_app.app_settings_store.load()
        m = current_app.app_settings_store.get_session_timeout_minutes()
        t = current_app.app_settings_store.get_brute_force_threshold()
        return jsonify({"status": "ok", "session_timeout_minutes": m, "brute_force_threshold": t})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/session-settings")
@superuser_required_json
def set_session_settings():
    try:
        payload = request.json or {}
        raw = payload.get("session_timeout_minutes", 15)
        thr = payload.get("brute_force_threshold", 5)
        current_app.app_settings_store.update_session_timeout_minutes(raw)
        current_app.app_settings_store.update_brute_force_threshold(thr)
        m = current_app.app_settings_store.get_session_timeout_minutes()
        t = current_app.app_settings_store.get_brute_force_threshold()
        return jsonify({"status": "ok", "session_timeout_minutes": m, "brute_force_threshold": t})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/admin/servers")
@superuser_required_json
def list_servers():
    try:
        current_app.server_store.load()
        return jsonify({"status": "ok", "servers": current_app.server_store.list_public()})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/servers")
@superuser_required_json
def upsert_server():
    try:
        payload = request.json or {}
        current_app.server_store.load()
        item = current_app.server_store.upsert(payload)
        return jsonify(
            {
                "status": "ok",
                "server": {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "hostname": item.get("hostname"),
                },
            }
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.delete("/api/admin/servers/<server_id>")
@superuser_required_json
def delete_server(server_id):
    try:
        current_app.server_store.load()
        current_app.server_store.delete(server_id)
        return jsonify({"status": "ok"})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


def _file_meta(abs_path, *, label, category, file_id, flushable=False):
    try:
        size = os.path.getsize(abs_path) if os.path.isfile(abs_path) else 0
    except OSError:
        size = 0
    rel = os.path.relpath(abs_path, os.getcwd()) if os.path.isabs(abs_path) else abs_path
    try:
        rel = os.path.normpath(rel)
    except Exception:
        pass
    return {
        "id": file_id,
        "label": label,
        "category": category,
        "path": rel.replace("\\", "/"),
        "size_bytes": size,
        "flushable": flushable,
    }


@bp.get("/api/admin/storage")
@superuser_required_json
def storage_status():
    try:
        ah = get_store()
        cfg = current_app.config_store.path
        usr = current_app.user_store.path
        app_set = current_app.app_settings_store.path
        rows = [
            _file_meta(cfg, label="Monitor configuration", category="configuration", file_id="monitors"),
            _file_meta(usr, label="Users & passwords", category="configuration", file_id="users"),
            _file_meta(app_set, label="App settings (e.g. Bale URL)", category="configuration", file_id="app_settings"),
            _file_meta(ah.path, label="Alert activity log", category="logs", file_id="alert_history", flushable=True),
        ]
        root = data_dir()
        extras = []
        try:
            if os.path.isdir(root):
                for name in sorted(os.listdir(root)):
                    if not name.endswith(".json"):
                        continue
                    low = name.lower()
                    if low in ("monitors.json", "users.json", "app_settings.json", "alert_history.json"):
                        continue
                    p = os.path.join(root, name)
                    if os.path.isfile(p):
                        extras.append(
                            _file_meta(
                                p,
                                label=name,
                                category="data",
                                file_id=f"extra:{name}",
                                flushable=False,
                            )
                        )
        except OSError:
            pass
        return jsonify({"status": "ok", "data_directory": root.replace("\\", "/"), "files": rows + extras})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/admin/storage/flush")
@superuser_required_json
def storage_flush():
    try:
        payload = request.json or {}
        target = (payload.get("target") or "").strip()
        if target != "alert_history":
            return jsonify({"status": "error", "message": "Unsupported or missing target."}), 400
        get_store().clear()
        ah = get_store()
        try:
            size_after = os.path.getsize(ah.path) if os.path.isfile(ah.path) else 0
        except OSError:
            size_after = 0
        return jsonify({"status": "ok", "target": target, "size_bytes_after": size_after})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.patch("/api/admin/users/<user_id>")
@superuser_required_json
def patch_user(user_id):
    try:
        payload = request.json or {}
        kw = {}
        if "password" in payload:
            pw = (payload.get("password") or "").strip()
            if len(pw) < 4:
                return jsonify({"status": "error", "message": "Password must be at least 4 characters."}), 400
            kw["password"] = pw
        if "active" in payload:
            kw["active"] = bool(payload.get("active"))
        if not kw:
            return jsonify({"status": "error", "message": "No changes (send password and/or active)."}), 400
        current_app.user_store.admin_update_user(user_id, **kw)
        u = current_app.user_store.find_by_id(user_id)
        return jsonify(
            {
                "status": "ok",
                "user": {
                    "id": u["id"],
                    "username": u["username"],
                    "role": u.get("role", "user"),
                    "active": u.get("active", True),
                },
            }
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.delete("/api/admin/users/<user_id>")
@superuser_required_json
def delete_user(user_id):
    try:
        acting = session.get("user") or {}
        if acting.get("id") == user_id:
            return jsonify({"status": "error", "message": "You cannot delete your own account."}), 400
        current_app.user_store.delete_user(user_id)
        return jsonify({"status": "ok"})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
