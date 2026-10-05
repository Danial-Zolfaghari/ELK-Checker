from flask import Blueprint, jsonify, request

from elkcheck.routes.auth import login_required_json
from elkcheck.services.alert_history import get_store

bp = Blueprint("history", __name__)


@bp.get("/api/alert-history")
@login_required_json
def alert_history():
    try:
        limit = int(request.args.get("limit", 80))
    except ValueError:
        limit = 80
    try:
        return jsonify({"status": "ok", "entries": get_store().recent(limit=limit)})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc), "entries": []}), 500
