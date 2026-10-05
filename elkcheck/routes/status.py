from flask import Blueprint, current_app, jsonify

from .auth import login_required_json

bp = Blueprint("status", __name__)


@bp.get("/api/status")
@login_required_json
def get_status():
    try:
        states = current_app.state_store.get_all()
        return jsonify(
            {
                "running": bool(
                    current_app.scheduler
                    and current_app.scheduler._thread
                    and current_app.scheduler._thread.is_alive()
                ),
                "states": states,
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc), "states": {}}), 500

