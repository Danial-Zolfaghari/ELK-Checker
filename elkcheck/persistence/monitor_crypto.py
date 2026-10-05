import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from elkcheck.persistence.data_paths import data_file
from elkcheck.persistence.secret_store import SecretStore

_ENC_PREFIX = "enc:v1:"


def _resolve_secret():
    direct = os.getenv("MONITOR_ENCRYPTION_KEY") or os.getenv("SECRET_KEY")
    if direct:
        return direct
    store = SecretStore(path=os.getenv("SECRETS_FILE", data_file("secrets.json")))
    return store.get_or_create("monitor_encryption_key")


def _fernet():
    secret = _resolve_secret().encode("utf-8")
    if not secret:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def _fernet_from_secret(secret_text: str):
    secret = (secret_text or "").encode("utf-8")
    if not secret:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_if_possible(value: str) -> str:
    if value is None:
        return ""
    text = str(value)
    if text == "":
        return text
    if text.startswith(_ENC_PREFIX):
        return text
    f = _fernet()
    if f is None:
        return text
    token = f.encrypt(text.encode("utf-8")).decode("utf-8")
    return _ENC_PREFIX + token


def decrypt_if_needed(value: str) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text.startswith(_ENC_PREFIX):
        return text
    token = text[len(_ENC_PREFIX) :]
    f = _fernet()
    if f is not None:
        try:
            return f.decrypt(token.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError):
            pass
    legacy = _fernet_from_secret("change-me")
    if legacy is not None:
        try:
            return legacy.decrypt(token.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError):
            pass
    return text

