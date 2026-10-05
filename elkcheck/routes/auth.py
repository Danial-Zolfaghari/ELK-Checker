import time
import secrets
from functools import wraps

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

bp = Blueprint("auth", __name__)


def _client_ip():
    for header in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
        raw = (request.headers.get(header) or "").strip()
        if raw:
            return current_app.security_store.normalize_ip(raw)
    return current_app.security_store.normalize_ip(request.remote_addr or "unknown")


def _session_timed_out():
    login_at = session.get("login_at")
    try:
        start = float(login_at) if login_at is not None else None
    except (TypeError, ValueError):
        start = None
    minutes = current_app.app_settings_store.get_session_timeout_minutes()
    limit_sec = minutes * 60
    if start is None or (time.time() - start) > limit_sec:
        session.pop("user", None)
        session.pop("login_at", None)
        session.pop("sid", None)
        return True
    return False


def _session_user_valid():
    sid = session.get("sid")
    if not sid or not isinstance(sid, str):
        session.pop("user", None)
        session.pop("login_at", None)
        session.pop("security_warning_ack", None)
        return False
    u = session.get("user")
    if not u:
        return False
    if _session_timed_out():
        return False
    row = current_app.user_store.find_by_id(u.get("id"))
    if not row or not row.get("active", True):
        session.pop("user", None)
        return False
    session["user"] = {
        "id": row["id"],
        "username": row["username"],
        "role": row.get("role", "user"),
    }
    session.setdefault("security_warning_ack", False)
    return True


def login_required_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if not _session_user_valid():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


def login_required_page(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.login_page"))
        if not _session_user_valid():
            return redirect(url_for("auth.login_page"))
        return fn(*args, **kwargs)

    return wrapper


def superuser_required_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if not _session_user_valid():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if session.get("user", {}).get("role") != "superuser":
            return jsonify({"status": "error", "message": "Forbidden"}), 403
        return fn(*args, **kwargs)

    return wrapper


def superuser_required_page(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user:
            return redirect(url_for("auth.login_page"))
        if not _session_user_valid():
            return redirect(url_for("auth.login_page"))
        if session.get("user", {}).get("role") != "superuser":
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)

    return wrapper


@bp.get("/login")
def login_page():
    return render_template("login.html")


@bp.post("/api/auth/login")
def login():
    try:
        payload = request.json or {}
        username = (payload.get("username") or "").strip()
        password = payload.get("password", "")
        ip = _client_ip()
        threshold = current_app.app_settings_store.get_brute_force_threshold()

        remain = current_app.security_store.cooldown_remaining(ip, username, min_seconds=5)
        if remain > 0:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": f"Please wait {int(remain) + 1} seconds before trying again.",
                    }
                ),
                429,
            )

        target = current_app.user_store.find_by_username(username)
        if target and target.get("role") == "superuser" and current_app.security_store.is_ip_banned(ip):
            current_app.security_store.mark_attempt(ip, username)
            return jsonify({"status": "error", "message": "Access denied from this IP for superuser login."}), 403

        user = current_app.user_store.authenticate(username, password)
        if not user:
            fail_info = current_app.user_store.record_failed_login(username, threshold=threshold)
            if fail_info.get("is_superuser"):
                current_app.security_store.register_superuser_failure(ip, username, threshold=threshold)
            current_app.security_store.mark_attempt(ip, username)
            if fail_info.get("disabled_now"):
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": f"Account disabled after {threshold} failed login attempts. Ask an admin to enable it.",
                        }
                    ),
                    403,
                )
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        current_app.user_store.record_login_success(user["id"])
        current_app.security_store.mark_attempt(ip, username)
        # Rotate the session context on each login so each auth session has a unique ID.
        session.clear()
        session["user"] = user
        session["login_at"] = time.time()
        session["sid"] = secrets.token_urlsafe(32)
        warn = current_app.security_store.get_superuser_warning()
        session["security_warning_ack"] = not (user.get("role") == "superuser" and warn.get("pending"))
        return jsonify({"status": "ok", "user": user})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/auth/logout")
def logout():
    try:
        session.pop("user", None)
        session.pop("login_at", None)
        session.pop("sid", None)
        session.pop("security_warning_ack", None)
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/auth/session")
def auth_session():
    try:
        if not session.get("user"):
            return jsonify({"authenticated": False})
        if not _session_user_valid():
            return jsonify({"authenticated": False})
        user = session["user"]
        security_warning = None
        if user.get("role") == "superuser":
            warn = current_app.security_store.get_superuser_warning()
            if warn.get("pending") and not session.get("security_warning_ack", False):
                security_warning = {"required": True, "message": warn.get("message") or "Security warning detected."}
        return jsonify({"authenticated": True, "user": user, "security_warning": security_warning})
    except Exception as exc:
        return jsonify({"authenticated": False, "error": str(exc)}), 200


@bp.post("/api/auth/security-warning/ack")
@login_required_json
def security_warning_ack():
    try:
        user = session.get("user") or {}
        if user.get("role") != "superuser":
            return jsonify({"status": "error", "message": "Forbidden"}), 403
        session["security_warning_ack"] = True
        current_app.security_store.clear_superuser_warning()
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/account/password")
@login_required_page
def account_password_page():
    return render_template("account_password.html")


@bp.post("/api/auth/change-password")
@login_required_json
def change_password():
    try:
        payload = request.json or {}
        current_pw = payload.get("current_password", "")
        new_pw = (payload.get("new_password") or "").strip()
        confirm = (payload.get("new_password_confirm") or "").strip()
        if new_pw != confirm:
            return jsonify({"status": "error", "message": "New password fields do not match."}), 400
        uid = session["user"]["id"]
        current_app.user_store.change_own_password(uid, current_pw, new_pw or "")
        return jsonify({"status": "ok"})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
