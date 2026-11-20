"""Криптография BG Push.

* RFC 8188 (aes128gcm) и RFC 8291 (Web Push message encryption), одна запись;
* RFC 8292 (VAPID): ES256-JWT в заголовке `Authorization: vapid t=..., k=...`.

Сервер шифрует внешний слой под ключ PWA-подписки и тестовые сообщения под
публичный ingress-ключ. Приватного ingress-ключа сервер не получает и не хранит.
Реализация опирается на библиотеку `cryptography`; совместимость с эталонной
реализацией http_ece проверяется в тестах.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..util import b64url_decode, b64url_encode

RECORD_SIZE = 4096
PUBLIC_KEY_LEN = 65
AUTH_SECRET_LEN = 16
# Одна запись: 1 байт разделителя и 16 байт тега GCM.
MAX_PLAINTEXT = RECORD_SIZE - 17
VAPID_MAX_TTL_SECONDS = 24 * 3600


class PushCryptoError(ValueError):
    """Некорректный ключ, формат записи или подпись."""


def public_key_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_public_point(raw: bytes) -> ec.EllipticCurvePublicKey:
    """Проверяет и загружает несжатую точку P-256 (65 байт, начинается с 0x04)."""
    if len(raw) != PUBLIC_KEY_LEN or raw[0] != 0x04:
        raise PushCryptoError("P-256 public key must be a 65-byte uncompressed point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise PushCryptoError("invalid P-256 public key") from exc


def _ikm(shared_secret: bytes, ua_public: bytes, as_public: bytes, auth_secret: bytes) -> bytes:
    # RFC 8291, раздел 3.3: key_info = "WebPush: info" || 0x00 || ua_public || as_public
    key_info = b"WebPush: info\x00" + ua_public + as_public
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret, info=key_info).derive(shared_secret)


def _cek_and_nonce(ikm: bytes, salt: bytes) -> tuple[bytes, bytes]:
    cek = HKDF(
        algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\x00"
    ).derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\x00").derive(ikm)
    return cek, nonce


def encrypt_aes128gcm(
    plaintext: bytes,
    *,
    ua_public: bytes,
    auth_secret: bytes,
    salt: bytes | None = None,
    ephemeral_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """Шифрует одну запись RFC 8188 для получателя с ключом ua_public (RFC 8291).

    Заголовок: salt (16) || rs (4, big-endian) || idlen (1) || keyid (65, ephemeral public).
    """
    if len(plaintext) > MAX_PLAINTEXT:
        raise PushCryptoError("plaintext does not fit into a single aes128gcm record")
    if len(auth_secret) != AUTH_SECRET_LEN:
        raise PushCryptoError("auth secret must be 16 bytes")
    receiver = load_public_point(ua_public)
    sender = ephemeral_key or ec.generate_private_key(ec.SECP256R1())
    sender_public = public_key_bytes(sender.public_key())
    shared = sender.exchange(ec.ECDH(), receiver)
    salt = salt if salt is not None else os.urandom(16)
    cek, nonce = _cek_and_nonce(_ikm(shared, ua_public, sender_public, auth_secret), salt)
    record = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + struct.pack(">I", RECORD_SIZE) + bytes([len(sender_public)]) + sender_public
    return header + record


def decrypt_aes128gcm(body: bytes, *, private_key: ec.EllipticCurvePrivateKey, auth_secret: bytes) -> bytes:
    """Расшифровывает одну запись aes128gcm на стороне получателя.

    Используется в тестах и диагностике; в продакшене расшифровка выполняется
    только в service worker на устройстве пользователя.
    """
    if len(body) < 21 + PUBLIC_KEY_LEN + 17:
        raise PushCryptoError("record is too short")
    salt = body[:16]
    (record_size,) = struct.unpack(">I", body[16:20])
    id_len = body[20]
    if id_len != PUBLIC_KEY_LEN:
        raise PushCryptoError("unexpected key id length")
    sender_public = body[21 : 21 + id_len]
    record = body[21 + id_len :]
    if record_size < 18 or len(record) > record_size:
        raise PushCryptoError("record size mismatch")
    ua_public = public_key_bytes(private_key.public_key())
    shared = private_key.exchange(ec.ECDH(), load_public_point(sender_public))
    cek, nonce = _cek_and_nonce(_ikm(shared, ua_public, sender_public, auth_secret), salt)
    try:
        padded = AESGCM(cek).decrypt(nonce, record, None)
    except InvalidTag as exc:
        raise PushCryptoError("authentication failed") from exc
    end = len(padded) - 1
    while end >= 0 and padded[end] == 0:
        end -= 1
    if end < 0 or padded[end] != 0x02:
        raise PushCryptoError("invalid record padding")
    return padded[:end]


# --- VAPID (RFC 8292) -------------------------------------------------------


@dataclass(frozen=True)
class VapidKey:
    private_key: ec.EllipticCurvePrivateKey
    public_key_b64: str  # applicationServerKey для PushManager.subscribe

    @classmethod
    def from_pem(cls, pem: bytes) -> VapidKey:
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise PushCryptoError("VAPID private key must be an unencrypted PEM key") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise PushCryptoError("VAPID private key must be a P-256 EC key")
        return cls(private_key=key, public_key_b64=b64url_encode(public_key_bytes(key.public_key())))


def generate_vapid_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _json_b64(value: dict) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def vapid_authorization(
    vapid: VapidKey, *, audience: str, subject: str, now: float, ttl: int = 12 * 3600
) -> str:
    """Значение заголовка Authorization для одного запроса к push-провайдеру."""
    if not 60 <= ttl <= VAPID_MAX_TTL_SECONDS:
        raise PushCryptoError("VAPID ttl must be between 60 seconds and 24 hours")
    signing_input = (
        _json_b64({"typ": "JWT", "alg": "ES256"})
        + "."
        + _json_b64({"aud": audience, "exp": int(now) + ttl, "sub": subject})
    )
    der = vapid.private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    token = f"{signing_input}.{b64url_encode(signature)}"
    return f"vapid t={token}, k={vapid.public_key_b64}"


def verify_vapid_authorization(header: str, *, public_key_b64: str, now: float) -> dict:
    """Проверяет подпись VAPID и срок действия; возвращает claims. Для тестов и диагностики."""
    prefix = "vapid "
    if not header.startswith(prefix):
        raise PushCryptoError("not a vapid authorization header")
    fields = dict(part.strip().split("=", 1) for part in header[len(prefix) :].split(","))
    if fields.get("k") != public_key_b64:
        raise PushCryptoError("VAPID key mismatch")
    parts = fields.get("t", "").split(".")
    if len(parts) != 3:
        raise PushCryptoError("malformed VAPID token")
    header_json = json.loads(b64url_decode(parts[0]))
    if header_json.get("alg") != "ES256":
        raise PushCryptoError("unexpected VAPID algorithm")
    raw_signature = b64url_decode(parts[2])
    if len(raw_signature) != 64:
        raise PushCryptoError("malformed VAPID signature")
    der = encode_dss_signature(
        int.from_bytes(raw_signature[:32], "big"), int.from_bytes(raw_signature[32:], "big")
    )
    public = load_public_point(b64url_decode(public_key_b64))
    try:
        public.verify(der, f"{parts[0]}.{parts[1]}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise PushCryptoError("VAPID signature mismatch") from exc
    claims = json.loads(b64url_decode(parts[1]))
    if claims.get("exp", 0) <= now:
        raise PushCryptoError("VAPID token expired")
    return claims
