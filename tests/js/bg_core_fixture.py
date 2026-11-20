"""Фикстура для Node-теста bg-core.js.

Печатает JSON в stdout: приватный ключ получателя (PKCS#8), публичную точку, auth-секрет, открытый текст и
две записи, которые расшифровывает PWA:
* body: запись aes128gcm от серверной функции encrypt_aes128gcm;
* aesgcmEnvelope: конверт aesgcm. Запись создаёт эталонная библиотека http_ece (version='aesgcm'), а конверт
  собирает серверная функция aesgcm_envelope из значений заголовков Encryption и Crypto-Key.

Ключи создаются заново при каждом запуске, на диск не пишутся и в репозиторий не попадают.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import http_ece  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from app.push.crypto import aesgcm_envelope, encrypt_aes128gcm  # noqa: E402


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_public(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def main() -> None:
    receiver = ec.generate_private_key(ec.SECP256R1())
    public_raw = _raw_public(receiver)
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

    sender = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(16)
    record = http_ece.encrypt(
        plaintext, salt=salt, private_key=sender, dh=public_raw, auth_secret=auth, version="aesgcm"
    )
    envelope = aesgcm_envelope(
        record,
        encryption=f"salt={_b64url(salt)}",
        crypto_key=f"dh={_b64url(_raw_public(sender))}",
    )

    pkcs8 = receiver.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    json.dump(
        {
            "privatePkcs8": _b64(pkcs8),
            "publicRaw": _b64(public_raw),
            "auth": _b64(auth),
            "body": _b64(body),
            "aesgcmEnvelope": _b64(envelope),
            "plaintext": plaintext.decode("utf-8"),
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
