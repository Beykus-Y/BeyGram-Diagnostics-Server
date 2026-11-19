"""Защита данных BG Push at rest.

Чувствительные поля подписок (endpoint, ключи, ingress auth) шифруются
AES-256-GCM под ключом из файла PUSH_STORAGE_KEY_FILE. Файл лежит вне базы.
Псевдонимы владельца, токена, pairing-секрета и ingress-capability считаются
HMAC под производным ключом, поэтому дамп БД без файла ключа не позволяет
ни расшифровать значения, ни проверить догадку.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..util import b64url_decode, b64url_encode


class VaultError(ValueError):
    """Ошибка ключа или зашифрованного значения. Сообщения не содержат секретов."""


class Vault:
    def __init__(self, storage_key: bytes) -> None:
        if len(storage_key) != 32:
            raise VaultError("storage key must be 32 bytes")
        self._aead = AESGCM(storage_key)
        self._mac_key = hmac.new(storage_key, b"bg-push/mac/v1", hashlib.sha256).digest()

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Vault:
        file = Path(path)
        if not file.is_file():
            raise VaultError(f"storage key file not found: {file}")
        try:
            raw = b64url_decode(file.read_text(encoding="ascii").strip())
        except (ValueError, UnicodeDecodeError) as exc:
            raise VaultError("storage key file must contain base64url text") from exc
        return cls(raw)

    def seal(self, plaintext: str, *, aad: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self._aead.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
        return b64url_encode(nonce + ciphertext)

    def open(self, token: str, *, aad: str) -> str:
        try:
            raw = b64url_decode(token)
            plaintext = self._aead.decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
        except (ValueError, InvalidTag) as exc:
            raise VaultError("cannot open sealed value") from exc
        return plaintext.decode("utf-8")

    def digest(self, label: str, value: str) -> str:
        """HMAC-SHA256 с доменной меткой label; возвращает hex-строку."""
        message = label.encode("ascii") + b"\x00" + value.encode("utf-8")
        return hmac.new(self._mac_key, message, hashlib.sha256).hexdigest()
