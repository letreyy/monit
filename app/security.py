from __future__ import annotations

import os
from typing import Protocol


class SecretCodec(Protocol):
    def encrypt(self, value: str) -> str: ...

    def decrypt(self, value: str) -> str: ...


class PassthroughSecretCodec:
    def encrypt(self, value: str) -> str:
        return value

    def decrypt(self, value: str) -> str:
        return value


class FernetSecretCodec:
    def __init__(self, key: str) -> None:
        from cryptography.fernet import Fernet

        self._fernet = Fernet(key.encode("utf-8"))

    def encrypt(self, value: str) -> str:
        token = self._fernet.encrypt(value.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, value: str) -> str:
        try:
            decoded = self._fernet.decrypt(value.encode("utf-8"))
            return decoded.decode("utf-8")
        except Exception:
            # compatibility with previously stored plaintext values
            return value


def build_secret_codec() -> SecretCodec:
    key = os.getenv("APP_SECRET_KEY", "").strip()
    if not key:
        return PassthroughSecretCodec()

    try:
        return FernetSecretCodec(key)
    except Exception:
        return PassthroughSecretCodec()
