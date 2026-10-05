import uuid

from flask import Blueprint, current_app, jsonify, request

from .auth import login_required_json
from elkcheck.persistence.config_store import _normalize_monitor, validate_bale_notifications
from elkcheck.services.monitor_resolver import resolve_monitor_connection
from elkcheck.services.query_validate import validate_monitor_query

bp = Blueprint("monitors", __name__)


def _merge_saved_manual_auth(payload, config_store):
    """
    If the monitor uses a manual ES host (no server_id) and the client sends an
    empty username/password, reuse the values already stored for that monitor id.

    The dashboard often submits blank passwords on edit (password inputs are not
    re-filled or the user saves without retyping). Without this merge, validation
    hits Elasticsearch with no credentials and returns 401.
    """
    if (payload.get("server_id") or "").strip():
        return payload
    mid = (payload.get("id") or "").strip()
    if not mid:
        return payload
    cfg = config_store.load()
    existing = next((m for m in cfg.get("monitors", []) if m.get("id") == mid), None)
    if not existing:
        return payload
    out = dict(payload)
    if not str(out.get("password") or "").strip():
        out["password"] = existing.get("password") or ""
    if not str(out.get("username") or "").strip():
        out["username"] = existing.get("username") or ""
    return out


def _has_any_alert_channel(monitor):
    notifications = monitor.get("notifications") or {}
    sms = notifications.get("sms") or {}
    call = notifications.get("call") or {}
    bale = notifications.get("bale") or {}
    rec = notifications.get("recovery") or {}
    rec_sms = rec.get("sms") or {}
    rec_call = rec.get("call") or {}
    rec_bale = rec.get("bale") or {}
    if sms.get("enabled") and (sms.get("message") or "").strip():
        return True
    if call.get("enabled") and (call.get("message") or "").strip():
        return True
    if bale.get("enabled") and (bale.get("message") or "").strip():
        return True
    if rec_sms.get("enabled") and (rec_sms.get("message") or "").strip():
        return True
    if rec_call.get("enabled") and (rec_call.get("message") or "").strip():
        return True
    if rec_bale.get("enabled") and (rec_bale.get("message") or "").strip():
        return True
    return False


@bp.get("/api/config")
@login_required_json
def get_config():
    try:
        cfg = current_app.config_store.load()
        current_app.app_settings_store.load()
        bot_url = (current_app.app_settings_store.get().get("bale") or {}).get("bot_url", "").strip()
        return jsonify({**cfg, "_meta": {"bale_bot_url_configured": bool(bot_url)}})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/monitors/validate")
@login_required_json
def validate_monitor():
    try:
        payload = request.json or {}
        if not isinstance(payload, dict):
            return jsonify({"status": "error", "message": "Invalid JSON body"}), 400
        temp = dict(payload)
        temp["id"] = temp.get("id") or str(uuid.uuid4())
        temp = _merge_saved_manual_auth(temp, current_app.config_store)
        monitor = _normalize_monitor(temp)
        monitor_resolved = resolve_monitor_connection(monitor, current_app.server_store)
        ok, message = validate_monitor_query(monitor_resolved)
        if not ok:
            return jsonify({"status": "error", "message": message or "Validation failed"}), 400
        if not _has_any_alert_channel(monitor):
            return jsonify({"status": "error", "message": "No alert channel is configured. Enable at least one channel and set its message text."}), 400
        current_app.app_settings_store.load()
        bot_url = (current_app.app_settings_store.get().get("bale") or {}).get("bot_url", "").strip()
        ok_b, msg_b = validate_bale_notifications(monitor, bot_url_global=bot_url)
        if not ok_b:
            return jsonify({"status": "error", "message": msg_b}), 400
        return jsonify({"status": "ok"})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/monitors")
@login_required_json
def save_monitor():
    try:
        payload = request.json or {}
        if not isinstance(payload, dict):
            return jsonify({"status": "error", "message": "Invalid JSON body"}), 400
        payload["id"] = payload.get("id") or str(uuid.uuid4())
        payload = _merge_saved_manual_auth(payload, current_app.config_store)
        monitor = _normalize_monitor(payload)
        monitor_resolved = resolve_monitor_connection(monitor, current_app.server_store)
        ok, message = validate_monitor_query(monitor_resolved)
        if not ok:
            return jsonify({"status": "error", "message": message or "Query validation failed"}), 400
        if not _has_any_alert_channel(monitor):
            return jsonify({"status": "error", "message": "No alert channel is configured. Enable at least one channel and set its message text."}), 400
        current_app.app_settings_store.load()
        bot_url = (current_app.app_settings_store.get().get("bale") or {}).get("bot_url", "").strip()
        ok_b, msg_b = validate_bale_notifications(monitor, bot_url_global=bot_url)
        if not ok_b:
            return jsonify({"status": "error", "message": msg_b}), 400
        current_app.config_store.upsert_monitor(monitor)
        return jsonify({"status": "ok", "monitor": monitor})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.delete("/api/monitors/<monitor_id>")
@login_required_json
def delete_monitor(monitor_id):
    try:
        current_app.config_store.delete_monitor(monitor_id)
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.get("/api/servers")
@login_required_json
def list_servers():
    try:
        current_app.server_store.load()
        return jsonify({"status": "ok", "servers": current_app.server_store.list_public()})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/monitoring/start")
@login_required_json
def start_monitoring():
    try:
        current_app.scheduler.start()
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@bp.post("/api/monitoring/stop")
@login_required_json
def stop_monitoring():
    try:
        current_app.scheduler.stop()
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
