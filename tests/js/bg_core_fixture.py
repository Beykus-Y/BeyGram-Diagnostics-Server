"""Фикстура для Node-теста bg-core.js.

Шифрует тестовое сообщение серверной функцией encrypt_aes128gcm и печатает JSON в stdout:
приватный ключ получателя (PKCS#8), публичную точку, auth-секрет, тело записи и открытый текст.
Ключ создаётся заново при каждом запуске, на диск не пишется и в репозиторий не попадает.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from app.push.crypto import encrypt_aes128gcm  # noqa: E402


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def main() -> None:
    receiver = ec.generate_private_key(ec.SECP256R1())
    public_raw = receiver.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    auth = os.urandom(16)
    inner = {
        "v": 1,
        "k": "msg",
        "id": "fixture1",
        "t": "Анна",
        "b": "Привет из теста",
        "account": "1001",
        "peer": "-100200",
        "msg": "42",
        # Поле l клиент обязан игнорировать: ссылка строится только из проверенных id.
        "l": "https://evil.example/steal",
    }
    plaintext = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body = encrypt_aes128gcm(plaintext, ua_public=public_raw, auth_secret=auth)
    pkcs8 = receiver.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    json.dump(
        {
            "privatePkcs8": _b64(pkcs8),
            "publicRaw": _b64(public_raw),
            "auth": _b64(auth),
            "body": _b64(body),
            "plaintext": plaintext.decode("utf-8"),
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
