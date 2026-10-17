"""Криптографические примитивы: работа с одноразовым nonce и подписанными токенами.

Ключевые правила:
* сервер НИКОГДА не хранит сырой nonce — только HMAC-SHA256 под pepper;
* nonce генерируется клиентом (SecureRandom 256 бит), сервер лишь валидирует форму;
* status-токен подписывается тем же pepper, чтобы клиент мог узнать состояние
  отчёта, не засвечивая сам nonce.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass

from .util import b64url_decode, b64url_encode

NONCE_BYTES = 32
# 32 байта в base64url без padding => ровно 43 символа.
NONCE_LENGTH = 43
STATUS_TOKEN_BYTES = 24


class NonceFormatError(ValueError):
    """Nonce не соответствует требуемому формату (256 бит base64url без padding)."""


@dataclass(frozen=True)
class Nonce:
    """Проверенный nonce: сырое значение живёт только в памяти запроса."""

    raw: str
    raw_bytes: bytes

    @property
    def fingerprint(self) -> str:
        raise NotImplementedError("use hash_nonce() with the server pepper")


def validate_nonce(nonce: str) -> Nonce:
    """Строгая проверка формата nonce.

    Требуем ровно 43 символа base64url без padding, которые декодируются
    ровно в 32 байта. Это не даёт клиенту подсунуть слабый/предсказуемый токен.
    """
    if not isinstance(nonce, str):
        raise NonceFormatError("nonce must be a string")
    if len(nonce) != NONCE_LENGTH:
        raise NonceFormatError("nonce must be 43 base64url characters")
    try:
        raw = b64url_decode(nonce)
    except ValueError as exc:
        raise NonceFormatError("nonce is not valid base64url") from exc
    if len(raw) != NONCE_BYTES:
        raise NonceFormatError("nonce must encode exactly 32 bytes")
    return Nonce(raw=nonce, raw_bytes=raw)


def hash_nonce(pepper: str, nonce: str) -> str:
    """HMAC-SHA256(pepper, "nonce:" || nonce). Возвращает hex-строку.

    Контекстный префикс не даёт переиспользовать хэш nonce в другой роли.
    """
    key = pepper.encode("utf-8")
    msg = b"nonce:" + nonce.encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def hash_ip(pepper: str, ip: str | None) -> str:
    """Псевдонимизирует IP-адрес для rate limit; сырой IP не хранится."""
    key = pepper.encode("utf-8")
    msg = b"ip:" + (ip or "unknown").encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]


def make_status_token(pepper: str, report_id: str, telegram_user_id: int) -> str:
    """Подписанный токен для проверки статуса конкретного отчёта.

    Клиент получает его в ответе на POST и использует в GET
    /api/v1/bug-reports/{report_id} — повторно nonce для этого не нужен.
    """
    key = pepper.encode("utf-8")
    msg = f"status:{report_id}:{telegram_user_id}".encode()
    digest = hmac.new(key, msg, hashlib.sha256).digest()[:STATUS_TOKEN_BYTES]
    return b64url_encode(digest)


def verify_status_token(pepper: str, token: str, report_id: str, telegram_user_id: int) -> bool:
    expected = make_status_token(pepper, report_id, telegram_user_id)
    return constant_time_equals(expected, token)


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def generate_nonce() -> str:
    """Генерация nonce на стороне сервера.

    В боевом потоке nonce создаёт приложение BeyGram; функция нужна для
    CLI-утилит, тестов и локальной отладки.
    """
    return b64url_encode(secrets.token_bytes(NONCE_BYTES))


def new_report_id() -> str:
    """UUID4 для локальной отладки (в бою report_id создаёт клиент)."""
    return str(uuid.uuid4())
