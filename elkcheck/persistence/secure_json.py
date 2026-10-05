import json
import os
from typing import Any

from elkcheck.persistence.monitor_crypto import decrypt_if_needed, encrypt_if_possible


def load_json(path: str, default: Any):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fp:
            raw_text = fp.read()
    except Exception:
        return default
    text = (raw_text or "").strip()
    if not text:
        return default
    try:
        # If encrypted, decrypt then parse JSON payload.
        if text.startswith("enc:v1:"):
            text = decrypt_if_needed(text)
        data = json.loads(text)
        return data
    except Exception:
        return default


def save_json(path: str, data: Any):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    json_text = json.dumps(data, indent=2, ensure_ascii=False)
    encrypted = encrypt_if_possible(json_text)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(encrypted)
