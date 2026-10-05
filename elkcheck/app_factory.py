import os

from flask import Flask, Response, redirect, render_template, request, url_for

from elkcheck.persistence.data_paths import data_file, migrate_legacy_json_from_project_root
from elkcheck.persistence.security_store import SecurityStore
from elkcheck.persistence.app_settings_store import AppSettingsStore
from elkcheck.persistence.secret_store import SecretStore
from elkcheck.persistence.config_store import ConfigStore
from elkcheck.persistence.server_store import ServerStore
from elkcheck.persistence.user_store import UserStore
from elkcheck.routes.admin import bp as admin_bp
from elkcheck.routes.auth import bp as auth_bp, login_required_page, superuser_required_page
from elkcheck.routes.monitors import bp as monitors_bp
from elkcheck.routes.status import bp as status_bp
from elkcheck.routes.history import bp as history_bp
from elkcheck.services.alert_history import configure as configure_alert_history
from elkcheck.services.scheduler import MonitorScheduler
from elkcheck.services.state_store import StateStore


def _celery_installed():
    try:
        import celery

        return True
    except ImportError:
        return False


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    secret_store = SecretStore(path=os.getenv("SECRETS_FILE", data_file("secrets.json")))
    app.secret_key = os.getenv("SECRET_KEY") or secret_store.get_or_create("flask_secret_key")
    app.config["SESSION_COOKIE_NAME"] = os.getenv("SESSION_COOKIE_NAME", "elk_checker_script_session")

    migrate_legacy_json_from_project_root()

    configure_alert_history(os.getenv("ALERT_HISTORY_FILE", data_file("alert_history.json")))

    app.config_store = ConfigStore(path=os.getenv("CONFIG_FILE", data_file("monitors.json")))
    app.config_store.load()
    app.server_store = ServerStore(path=os.getenv("SERVERS_FILE", data_file("servers.json")))
    app.server_store.load()
    app.app_settings_store = AppSettingsStore(path=os.getenv("APP_SETTINGS_FILE", data_file("app_settings.json")))
    app.app_settings_store.load()
    app.user_store = UserStore(path=os.getenv("USERS_FILE", data_file("users.json")))
    app.user_store.ensure_admin()
    app.security_store = SecurityStore(path=os.getenv("SECURITY_FILE", data_file("security.json")))

    @app.before_request
    def ip_access_control():
        ip_raw = (
            request.headers.get("X-Forwarded-For")
            or request.headers.get("X-Real-IP")
            or request.headers.get("CF-Connecting-IP")
            or request.remote_addr
            or "unknown"
        )
        ip = app.security_store.normalize_ip(ip_raw)
        denied, msg = app.security_store.is_ip_denied_access(ip)
        if denied:
            return Response(msg or "Access denied.", status=403, mimetype="text/plain")

    app.state_store = StateStore()
    want_celery = os.getenv("USE_CELERY", "0") == "1"
    use_celery = want_celery and _celery_installed()
    app.scheduler = MonitorScheduler(app.config_store, app.state_store, use_celery=use_celery)

    @app.get("/")
    def root():
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required_page
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/management")
    @login_required_page
    @superuser_required_page
    def management():
        return render_template("management.html")

    app.register_blueprint(auth_bp)
    app.register_blueprint(monitors_bp)
    app.register_blueprint(status_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(history_bp)

    try:
        app.scheduler.start()
    except Exception:
        pass
    return app

