import os
import shutil


def data_dir():
    return os.path.abspath(os.getenv("DATA_DIR", "data"))


def data_file(name: str) -> str:
    return os.path.join(data_dir(), name)


def ensure_data_dir():
    os.makedirs(data_dir(), exist_ok=True)


def migrate_legacy_json_from_project_root():
    ensure_data_dir()
    names = ("monitors.json", "users.json", "app_settings.json", "alert_history.json")
    for name in names:
        root_path = os.path.abspath(name)
        dest = data_file(name)
        if os.path.isfile(root_path) and not os.path.isfile(dest):
            try:
                shutil.move(root_path, dest)
            except OSError:
                pass
