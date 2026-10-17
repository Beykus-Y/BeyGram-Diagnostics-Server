"""Серверный реестр административных сессий.

Проблема, которую решает: подписанная cookie детерминирована (одинаковый
срок → одинаковая cookie) и не зависит от сервера — logout удалял её только
в браузере, а сохранённая копия оставалась действительной до конца TTL.

Решение: сессия получает случайный id, который хранится в kv-реестре.
Cookie = `{expires}.{sid}.{hmac}`. Проверка сессии требует:
1. валидную подпись (включает ADMIN_TOKEN — ротация отзывает всё);
2. неистёкший срок;
3. наличия sid в серверном реестре.

Logout удаляет запись из реестра, так что сохранённая копия cookie больше
не работает. Просроченные записи чистит maintenance (prune_expired).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .repository import kv
from .security import constant_time_equals
from .util import b64url_encode, now

KEY_PREFIX = "admin_session:"
SESSION_ID_BYTES = 18  # 24 символа base64url
COOKIE_NAME = "admin_session"


def _sign(settings, purpose: str, message: str) -> str:
    """Подпись; ADMIN_TOKEN входит в ключ — ротация токена отзывает всё."""
    key = f"{settings.nonce_pepper}:admin:{purpose}:{settings.admin_token}".encode()
    digest = hmac.new(key, message.encode(), hashlib.sha256).digest()[:24]
    return digest.hex()


def create_session(conn, settings) -> tuple[str, str]:
    """Создаёт сессию: пишет id в реестр, возвращает (cookie, csrf).

    Случайный sid делает каждую сессию уникальной, включая созданные
    в одну секунду.
    """
    expires = int(now() + settings.admin_session_ttl_seconds)
    sid = b64url_encode(secrets.token_bytes(SESSION_ID_BYTES))
    payload = f"{expires}.{sid}"
    cookie = f"{payload}.{_sign(settings, 'session', payload)}"
    csrf = _sign(settings, "csrf", payload)
    kv.set_value(conn, KEY_PREFIX + sid, str(expires), at=now())
    return cookie, csrf


def read_session(conn, settings, cookie_value: str | None) -> tuple[float, str] | None:
    """Проверяет cookie: подпись, срок и наличие в реестре.

    Возвращает (expires_at, csrf) или None.
    """
    if not cookie_value or cookie_value.count(".") != 2:
        return None
    expires_raw, sid, signature = cookie_value.split(".", 2)
    payload = f"{expires_raw}.{sid}"
    if not constant_time_equals(_sign(settings, "session", payload), signature):
        return None
    try:
        expires = float(expires_raw)
    except ValueError:
        return None
    if expires < now():
        return None
    stored = kv.get_value(conn, KEY_PREFIX + sid)
    if stored is None:
        # Logout (или очистка) удалил сессию на сервере — копия cookie
        # недействительна.
        return None
    try:
        server_expires = float(stored)
    except ValueError:
        return None
    if server_expires < now():
        return None
    return expires, _sign(settings, "csrf", payload)


def revoke_session(conn, cookie_value: str | None) -> bool:
    """Удаляет сессию из реестра. Возвращает True, если сессия существовала."""
    if not cookie_value or cookie_value.count(".") != 2:
        return False
    _, sid, _ = cookie_value.split(".", 2)
    return kv.delete(conn, KEY_PREFIX + sid)


def prune_expired(conn, *, at: float | None = None) -> int:
    """Удаляет просроченные записи реестра (вызывается maintenance)."""
    ts = at if at is not None else now()
    rows = conn.execute(
        "SELECT key, value FROM kv WHERE key LIKE ?", (KEY_PREFIX + "%",)
    ).fetchall()
    removed = 0
    for row in rows:
        try:
            expires = float(row["value"])
        except (TypeError, ValueError):
            expires = 0.0
        if expires < ts:
            kv.delete(conn, row["key"])
            removed += 1
    return removed
