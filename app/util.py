"""Небольшие утилиты: время, base64url, канонический JSON, разбор id."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Время
# ---------------------------------------------------------------------------


def now() -> float:
    """Текущее время (UTC, epoch-секунды с дробной частью)."""
    return time.time()


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# base64url без padding (как в требованиях к nonce и status-токену)
# ---------------------------------------------------------------------------

_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Декодирует base64url без padding; бросает ValueError при мусоре."""
    if not value:
        raise ValueError("empty base64url value")
    if any(ch not in _B64URL_ALPHABET for ch in value):
        raise ValueError("not a base64url string")
    pad = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + pad)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - защита от экзотики
        raise ValueError("invalid base64url payload") from exc


# ---------------------------------------------------------------------------
# Идентификаторы
# ---------------------------------------------------------------------------


def is_uuid4(value: str) -> bool:
    """True, если строка — канонический UUID версии 4 (без выбора id клиентом)."""
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed.version == 4 and str(parsed) == value.lower()


# ---------------------------------------------------------------------------
# Хэширование
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(payload: Any) -> bytes:
    """Стабильное представление JSON для сверки идемпотентных повторов."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


# ---------------------------------------------------------------------------
# Прочее
# ---------------------------------------------------------------------------


def clamp_text(value: str, limit: int) -> str:
    """Обрезает строку по символам (не по байтам) с индикатором усечения."""
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "\u2026"
