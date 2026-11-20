"""Бизнес-логика BG Push: регистрации, привязка PWA, приём пушей и учёт доставки.

Функции принимают открытое соединение push-базы. Транзакцию открывает
вызывающий код (router или worker) через Database.transaction(), поэтому
ошибка откатывает частичные изменения. Лимиты, которые должны сохраняться
даже при отказе операции (защита от перебора), вызывающий код считает в
отдельной транзакции.
"""

from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..config import Settings
from ..errors import ERR_NOT_FOUND, ApiError, payload_invalid, rate_limited, unauthorized
from ..repository import kv, rate_limit
from ..util import b64url_decode, b64url_encode, now
from .crypto import AUTH_SECRET_LEN, PushCryptoError, encrypt_aes128gcm, load_public_point
from .urls import EndpointError, validate_endpoint
from .vault import Vault

STATE_PENDING = "pending"
STATE_ACTIVE = "active"
STATE_REVOKED = "revoked"
STATE_EXPIRED = "expired"

KIND_TELEGRAM = "telegram"
KIND_TEST = "test"

SWITCH_INGRESS = "ingress_enabled"
SWITCH_OUTBOUND = "outbound_enabled"

TEST_TTL_SECONDS = 600
LEASE_SECONDS = 120
BASE_BACKOFF_SECONDS = 30
MAX_BACKOFF_SECONDS = 3600
DELIVERY_RETENTION_SECONDS = 86400
REGISTRATION_RETENTION_SECONDS = 7 * 86400
COUNTER_RETENTION_DAYS = 40


# --- Служебные функции ------------------------------------------------------


def bump(conn: sqlite3.Connection, metric: str, *, at: float | None = None) -> None:
    """Увеличивает суточный счётчик. Счётчики агрегированы: без идентификаторов."""
    conn.execute(
        "INSERT INTO push_counters (day, metric, value) VALUES (?, ?, 1) "
        "ON CONFLICT(day, metric) DO UPDATE SET value = value + 1",
        (_day(at if at is not None else now()), metric),
    )


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")


def switch_enabled(conn: sqlite3.Connection, name: str) -> bool:
    return kv.get_value(conn, name) != "off"


def set_switch(conn: sqlite3.Connection, name: str, enabled: bool) -> None:
    kv.set_value(conn, name, "on" if enabled else "off")


def _same(expected: str | None, actual: str | None) -> bool:
    if expected is None or actual is None:
        return False
    return hmac.compare_digest(expected.encode("ascii"), actual.encode("ascii"))


def get_row(conn: sqlite3.Connection, registration_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM push_registrations WHERE registration_id = ?", (registration_id,)
    ).fetchone()


def role_for(row: sqlite3.Row | None, vault: Vault, bearer: str) -> str | None:
    """Определяет роль предъявителя: владелец (нативный клиент), токен PWA или никто."""
    if row is None:
        return None
    if _same(row["owner_digest"], vault.digest("owner", bearer)):
        return "owner"
    if _same(row["token_digest"], vault.digest("token", bearer)):
        return "token"
    return None


def effective_state(row: sqlite3.Row, at: float) -> str:
    if row["state"] == STATE_PENDING and row["pairing_expires_at"] <= at:
        return STATE_EXPIRED
    return str(row["state"])


def view(row: sqlite3.Row, vault: Vault, *, at: float, owner: bool) -> dict[str, Any]:
    """Ответ о регистрации. Ключи ingress отдаются только владельцу (нативному клиенту)."""
    rid = str(row["registration_id"])
    result: dict[str, Any] = {
        "registration_id": rid,
        "state": effective_state(row, at),
        "platform": row["platform"],
        "created_at": row["created_at"],
        "activated_at": row["activated_at"],
        "telegram_confirmed_at": row["telegram_confirmed_at"],
        "last_push_ok_at": row["last_push_ok_at"],
        "last_push_error": row["last_push_error"],
        "ack_at": row["ack_at"],
    }
    if result["state"] == STATE_PENDING:
        result["expires_at"] = row["pairing_expires_at"]
    if owner and row["state"] == STATE_ACTIVE:
        result["telegram_keys"] = {
            "p256dh": row["ingress_p256dh"],
            "auth": vault.open(row["ingress_auth_sealed"], aad=f"{rid}:ingress_auth"),
        }
    return result


# --- Регистрация и привязка -------------------------------------------------


def create_pending(
    conn: sqlite3.Connection, *, settings: Settings, vault: Vault, owner_bearer: str, at: float
) -> dict[str, Any]:
    """Создаёт ожидающую привязку. Возвращает одноразовые секреты (только один раз)."""
    owner = vault.digest("owner", owner_bearer)
    active = conn.execute(
        "SELECT COUNT(*) FROM push_registrations WHERE owner_digest = ? AND state IN ('pending', 'active')",
        (owner,),
    ).fetchone()[0]
    if active >= settings.push_max_registrations_per_owner:
        raise ApiError(
            "registration_limit",
            "Достигнут лимит регистраций BG Push для этого приложения.",
            409,
        )
    registration_id = b64url_encode(secrets.token_bytes(16))
    pairing_secret = b64url_encode(secrets.token_bytes(32))
    capability = b64url_encode(secrets.token_bytes(32))
    expires = at + settings.push_pairing_ttl_seconds
    conn.execute(
        """INSERT INTO push_registrations (
               registration_id, state, platform, owner_digest, pairing_digest, capability_digest,
               pairing_expires_at, created_at, updated_at)
           VALUES (?, 'pending', 'ios_pwa', ?, ?, ?, ?, ?, ?)""",
        (
            registration_id,
            owner,
            vault.digest("pairing", pairing_secret),
            vault.digest("capability", capability),
            expires,
            at,
            at,
        ),
    )
    bump(conn, "registration_created", at=at)
    return {
        "registration_id": registration_id,
        "pairing_secret": pairing_secret,
        "capability": capability,
        "expires_at": expires,
    }


def _point(text: str) -> bytes:
    try:
        raw = b64url_decode(text)
        load_public_point(raw)
    except (ValueError, PushCryptoError) as exc:
        raise payload_invalid(message="Ключ должен быть публичным ключом P-256 в base64url.") from exc
    return raw


def _secret16(text: str) -> bytes:
    try:
        raw = b64url_decode(text)
    except ValueError as exc:
        raise payload_invalid(message="Некорректный auth secret.") from exc
    if len(raw) != AUTH_SECRET_LEN:
        raise payload_invalid(message="Некорректный auth secret.")
    return raw


def complete(
    conn: sqlite3.Connection,
    *,
    vault: Vault,
    allowed_hosts: tuple[str, ...],
    registration_id: str,
    pairing_secret: str,
    payload: dict[str, Any],
    at: float,
) -> str:
    """Завершает привязку из PWA и возвращает токен управления регистрацией (один раз)."""
    row = get_row(conn, registration_id)
    if (
        row is None
        or row["state"] != STATE_PENDING
        or row["pairing_expires_at"] <= at
        or not _same(row["pairing_digest"], vault.digest("pairing", pairing_secret))
    ):
        raise unauthorized()
    try:
        host = validate_endpoint(payload["endpoint"], allowed_hosts)
    except EndpointError as exc:
        raise payload_invalid(message=f"Адрес подписки отклонён: {exc}.") from exc
    p256dh = _point(payload["keys"]["p256dh"])
    auth = _secret16(payload["keys"]["auth"])
    ingress_p256dh = _point(payload["ingress"]["p256dh"])
    ingress_auth = _secret16(payload["ingress"]["auth"])
    token = b64url_encode(secrets.token_bytes(32))
    cursor = conn.execute(
        """UPDATE push_registrations SET
               state = 'active', pairing_digest = NULL, token_digest = ?, platform = ?,
               endpoint_host = ?, endpoint_sealed = ?, p256dh_sealed = ?, auth_sealed = ?,
               ingress_p256dh = ?, ingress_auth_sealed = ?, activated_at = ?, updated_at = ?
           WHERE registration_id = ? AND state = 'pending'""",
        (
            vault.digest("token", token),
            payload["platform"],
            host,
            vault.seal(payload["endpoint"], aad=f"{registration_id}:endpoint"),
            vault.seal(b64url_encode(p256dh), aad=f"{registration_id}:p256dh"),
            vault.seal(b64url_encode(auth), aad=f"{registration_id}:auth"),
            b64url_encode(ingress_p256dh),
            vault.seal(b64url_encode(ingress_auth), aad=f"{registration_id}:ingress_auth"),
            at,
            at,
            registration_id,
        ),
    )
    if cursor.rowcount != 1:
        raise unauthorized()
    bump(conn, "registration_activated", at=at)
    return token


def confirm_telegram(conn: sqlite3.Connection, *, registration_id: str, at: float) -> float | None:
    """Нативный клиент подтверждает, что зарегистрировал ingress в Telegram."""
    cursor = conn.execute(
        """UPDATE push_registrations SET
               telegram_confirmed_at = COALESCE(telegram_confirmed_at, ?), updated_at = ?
           WHERE registration_id = ? AND state = 'active'""",
        (at, at, registration_id),
    )
    if cursor.rowcount != 1:
        raise ApiError("registration_inactive", "Регистрация не активна.", 409)
    row = get_row(conn, registration_id)
    return row["telegram_confirmed_at"] if row is not None else None


def revoke(conn: sqlite3.Connection, *, registration_id: str, reason: str, at: float) -> bool:
    """Отзывает регистрацию, стирает зашифрованные данные и снимает очередь."""
    cursor = conn.execute(
        """UPDATE push_registrations SET
               state = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ?,
               pairing_digest = NULL, token_digest = NULL, endpoint_sealed = NULL,
               p256dh_sealed = NULL, auth_sealed = NULL, ingress_auth_sealed = NULL
           WHERE registration_id = ? AND state IN ('pending', 'active')""",
        (at, reason, at, registration_id),
    )
    if cursor.rowcount != 1:
        return False
    conn.execute(
        """UPDATE push_deliveries SET state = 'failed', last_error = ?, lease_until = NULL
           WHERE registration_id = ? AND state IN ('queued', 'inflight')""",
        (reason, registration_id),
    )
    bump(conn, "registration_revoked", at=at)
    return True


# --- Приём и тесты ----------------------------------------------------------


def insert_delivery(
    conn: sqlite3.Connection,
    *,
    settings: Settings,
    registration_id: str,
    kind: str,
    body: bytes,
    at: float,
    ttl: int,
    test_id: str | None = None,
) -> None:
    per_registration = conn.execute(
        "SELECT COUNT(*) FROM push_deliveries WHERE registration_id = ? AND state IN ('queued', 'inflight')",
        (registration_id,),
    ).fetchone()[0]
    if per_registration >= settings.push_queue_max_per_registration:
        raise ApiError("queue_full", "Очередь уведомлений переполнена.", 503, retry_after=60)
    total = conn.execute(
        "SELECT COUNT(*) FROM push_deliveries WHERE state IN ('queued', 'inflight')"
    ).fetchone()[0]
    if total >= settings.push_queue_max_total:
        raise ApiError("queue_full", "Очередь уведомлений переполнена.", 503, retry_after=60)
    conn.execute(
        """INSERT INTO push_deliveries (
               registration_id, kind, test_id, state, body, created_at, expires_at, next_attempt_at)
           VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)""",
        (registration_id, kind, test_id, body, at, at + ttl, at),
    )


def accept_ingress(
    conn: sqlite3.Connection,
    *,
    settings: Settings,
    vault: Vault,
    capability: str,
    body: bytes,
    ttl: int | None,
    at: float,
) -> None:
    """Принимает непрозрачный Telegram-payload и ставит его в очередь. Ответ отдаётся после commit.

    Попытка считается здесь же: при отказе транзакция откатывается, и счётчик отказа пишет роутер.
    """
    bump(conn, "ingress_attempt", at=at)
    if not switch_enabled(conn, SWITCH_INGRESS):
        raise ApiError("ingress_disabled", "Приём BG Push временно приостановлен.", 503, retry_after=300)
    row = conn.execute(
        "SELECT registration_id, state FROM push_registrations WHERE capability_digest = ?",
        (vault.digest("capability", capability),),
    ).fetchone()
    if row is None or row["state"] != STATE_ACTIVE:
        raise ApiError(ERR_NOT_FOUND, "Ресурс не найден.", 404)
    rid = str(row["registration_id"])
    for scope, key, limit, window in (
        ("push_ingress", vault.digest("rate-registration", rid), settings.rl_push_ingress_per_hour, 3600),
        ("push_ingress_global", None, settings.rl_push_ingress_global_per_hour, 3600),
    ):
        ok, delay = rate_limit.check_and_record(
            conn, scope=scope, key=key, limit=limit, window_seconds=window, at=at
        )
        if not ok:
            raise rate_limited(max(1, int(delay)), "Превышен лимит входящих уведомлений.")
    ttl_seconds = min(max(ttl if ttl is not None else settings.push_default_ttl_seconds, 0), settings.push_max_ttl_seconds)
    insert_delivery(
        conn,
        settings=settings,
        registration_id=rid,
        kind=KIND_TELEGRAM,
        body=body,
        at=at,
        ttl=ttl_seconds,
    )
    conn.execute(
        "UPDATE push_registrations SET last_ingress_at = ?, updated_at = ? WHERE registration_id = ?",
        (at, at, rid),
    )
    bump(conn, "ingress_accepted", at=at)


def enqueue_test(
    conn: sqlite3.Connection, *, settings: Settings, vault: Vault, registration_id: str, at: float
) -> str:
    """Ставит тестовое уведомление, зашифрованное под ingress-ключ (как Telegram-пуш)."""
    row = get_row(conn, registration_id)
    if row is None or row["state"] != STATE_ACTIVE:
        raise ApiError("registration_inactive", "Регистрация не активна.", 409)
    ok, delay = rate_limit.check_and_record(
        conn,
        scope="push_test",
        key=vault.digest("rate-test", registration_id),
        limit=settings.rl_push_test_per_hour,
        window_seconds=3600,
        at=at,
    )
    if not ok:
        raise rate_limited(max(1, int(delay)), "Лимит тестовых уведомлений исчерпан.")
    test_id = b64url_encode(secrets.token_bytes(12))
    inner = json.dumps(
        {"v": 1, "k": "test", "id": test_id, "t": "BG Push", "b": "Тестовое уведомление: привязка работает."},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    body = encrypt_aes128gcm(
        inner,
        ua_public=b64url_decode(row["ingress_p256dh"]),
        auth_secret=b64url_decode(vault.open(row["ingress_auth_sealed"], aad=f"{registration_id}:ingress_auth")),
    )
    insert_delivery(
        conn,
        settings=settings,
        registration_id=registration_id,
        kind=KIND_TEST,
        body=body,
        at=at,
        ttl=TEST_TTL_SECONDS,
        test_id=test_id,
    )
    bump(conn, "test_queued", at=at)
    return test_id


def acknowledge(conn: sqlite3.Connection, *, registration_id: str, test_id: str, at: float) -> bool:
    """PWA подтверждает получение тестового уведомления (best effort)."""
    cursor = conn.execute(
        """UPDATE push_registrations SET ack_at = COALESCE(ack_at, ?), updated_at = ?
           WHERE registration_id = ? AND state = 'active' AND EXISTS (
               SELECT 1 FROM push_deliveries d
               WHERE d.registration_id = push_registrations.registration_id
                 AND d.kind = 'test' AND d.test_id = ?)""",
        (at, at, registration_id, test_id),
    )
    return cursor.rowcount == 1


# --- Очередь доставки (используется воркером) -------------------------------


@dataclass(frozen=True)
class PushTarget:
    registration_id: str
    endpoint: str
    p256dh: bytes
    auth: bytes


def load_target(conn: sqlite3.Connection, vault: Vault, registration_id: str) -> PushTarget | None:
    row = get_row(conn, registration_id)
    if row is None or row["state"] != STATE_ACTIVE:
        return None
    try:
        return PushTarget(
            registration_id=registration_id,
            endpoint=vault.open(row["endpoint_sealed"], aad=f"{registration_id}:endpoint"),
            p256dh=b64url_decode(vault.open(row["p256dh_sealed"], aad=f"{registration_id}:p256dh")),
            auth=b64url_decode(vault.open(row["auth_sealed"], aad=f"{registration_id}:auth")),
        )
    except ValueError:
        return None


def claim_due(conn: sqlite3.Connection, *, at: float, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT id, registration_id, body, expires_at, attempts FROM push_deliveries
           WHERE state = 'queued' AND next_attempt_at <= ?
           ORDER BY next_attempt_at, id LIMIT ?""",
        (at, limit),
    ).fetchall()
    claimed: list[dict[str, Any]] = []
    for row in rows:
        cursor = conn.execute(
            """UPDATE push_deliveries SET state = 'inflight', lease_until = ?, attempts = attempts + 1
               WHERE id = ? AND state = 'queued'""",
            (at + LEASE_SECONDS, row["id"]),
        )
        if cursor.rowcount == 1:
            claimed.append(
                {
                    "id": row["id"],
                    "registration_id": row["registration_id"],
                    "body": bytes(row["body"]),
                    "expires_at": row["expires_at"],
                    "attempts": row["attempts"] + 1,
                }
            )
    return claimed


def settle_success(
    conn: sqlite3.Connection, *, delivery_id: int, registration_id: str, attempts: int, status: int, at: float
) -> bool:
    """Фиксирует успех. Результат принимается только от текущей аренды: state inflight и тот же номер попытки."""
    cursor = conn.execute(
        """UPDATE push_deliveries SET state = 'done', last_status = ?, last_error = NULL, lease_until = NULL
           WHERE id = ? AND state = 'inflight' AND attempts = ?""",
        (status, delivery_id, attempts),
    )
    if cursor.rowcount != 1:
        return False
    conn.execute(
        "UPDATE push_registrations SET last_push_ok_at = ?, last_push_error = NULL, updated_at = ? WHERE registration_id = ?",
        (at, at, registration_id),
    )
    bump(conn, "outbound_accepted", at=at)
    return True


def settle_retry(
    conn: sqlite3.Connection,
    *,
    delivery_id: int,
    attempts: int,
    status: int | None,
    error: str,
    at: float,
    retry_after: float | None = None,
) -> bool:
    delay = retry_after if retry_after is not None else min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * 2 ** max(0, attempts - 1))
    cursor = conn.execute(
        """UPDATE push_deliveries SET state = 'queued', next_attempt_at = ?, last_status = ?,
               last_error = ?, lease_until = NULL
           WHERE id = ? AND state = 'inflight' AND attempts = ?""",
        (at + delay, status, error, delivery_id, attempts),
    )
    if cursor.rowcount != 1:
        return False
    bump(conn, "outbound_retry", at=at)
    return True


def settle_failure(
    conn: sqlite3.Connection,
    *,
    delivery_id: int,
    registration_id: str,
    attempts: int,
    status: int | None,
    error: str,
    at: float,
) -> bool:
    cursor = conn.execute(
        """UPDATE push_deliveries SET state = 'failed', last_status = ?, last_error = ?, lease_until = NULL
           WHERE id = ? AND state = 'inflight' AND attempts = ?""",
        (status, error, delivery_id, attempts),
    )
    if cursor.rowcount != 1:
        return False
    conn.execute(
        "UPDATE push_registrations SET last_push_error = ?, updated_at = ? WHERE registration_id = ?",
        (error, at, registration_id),
    )
    bump(conn, "outbound_failed", at=at)
    return True


def settle_expired(conn: sqlite3.Connection, *, delivery_id: int, attempts: int) -> bool:
    cursor = conn.execute(
        """UPDATE push_deliveries SET state = 'expired', last_error = 'ttl', lease_until = NULL
           WHERE id = ? AND state = 'inflight' AND attempts = ?""",
        (delivery_id, attempts),
    )
    return cursor.rowcount == 1


def maintain(conn: sqlite3.Connection, *, at: float, max_attempts: int | None = None) -> dict[str, int]:
    """Истечение сроков, восстановление зависших лизов, очистка старых строк."""
    pending = conn.execute(
        "UPDATE push_registrations SET state = 'expired', updated_at = ? WHERE state = 'pending' AND pairing_expires_at <= ?",
        (at, at),
    ).rowcount
    expired = conn.execute(
        """UPDATE push_deliveries SET state = 'expired', last_error = 'ttl', lease_until = NULL
           WHERE state = 'queued' AND expires_at <= ?""",
        (at,),
    ).rowcount
    exhausted = 0
    if max_attempts is not None:
        # Задача, чья аренда истекала уже max_attempts раз (например, процесс падал на ней), не повторяется бесконечно.
        exhausted = conn.execute(
            """UPDATE push_deliveries SET state = 'failed', last_error = 'lease_exhausted', lease_until = NULL
               WHERE state = 'inflight' AND lease_until <= ? AND attempts >= ?""",
            (at, max_attempts),
        ).rowcount
    for _ in range(exhausted):
        bump(conn, "outbound_failed", at=at)
    recovered = conn.execute(
        """UPDATE push_deliveries SET state = 'queued', lease_until = NULL, next_attempt_at = ?
           WHERE state = 'inflight' AND lease_until <= ?""",
        (at, at),
    ).rowcount
    conn.execute(
        "DELETE FROM push_deliveries WHERE state IN ('done', 'failed', 'expired') AND created_at < ?",
        (at - DELIVERY_RETENTION_SECONDS,),
    )
    conn.execute(
        "DELETE FROM push_registrations WHERE state IN ('revoked', 'expired') AND updated_at < ?",
        (at - REGISTRATION_RETENTION_SECONDS,),
    )
    rate_limit.prune(conn, keep_seconds=86400, at=at)
    conn.execute("DELETE FROM push_counters WHERE day < ?", (_day(at - COUNTER_RETENTION_DAYS * 86400),))
    return {
        "pending_expired": pending,
        "deliveries_expired": expired,
        "deliveries_recovered": recovered,
        "deliveries_exhausted": exhausted,
    }


# --- Снимки для health и админки (без идентификаторов подписок) -------------


def health_snapshot(conn: sqlite3.Connection, *, at: float) -> dict[str, Any]:
    queued = conn.execute("SELECT COUNT(*) FROM push_deliveries WHERE state = 'queued'").fetchone()[0]
    oldest = conn.execute("SELECT MIN(created_at) FROM push_deliveries WHERE state = 'queued'").fetchone()[0]
    return {
        "queue_depth": queued,
        "oldest_queued_age_seconds": (at - oldest) if oldest is not None else None,
        "ingress_enabled": switch_enabled(conn, SWITCH_INGRESS),
        "outbound_enabled": switch_enabled(conn, SWITCH_OUTBOUND),
    }


def admin_snapshot(conn: sqlite3.Connection, *, at: float) -> dict[str, Any]:
    states = {r[0]: r[1] for r in conn.execute("SELECT state, COUNT(*) FROM push_registrations GROUP BY state")}
    platforms = {
        r[0]: r[1]
        for r in conn.execute(
            "SELECT platform, COUNT(*) FROM push_registrations WHERE state = 'active' GROUP BY platform"
        )
    }
    queue = {r[0]: r[1] for r in conn.execute("SELECT state, COUNT(*) FROM push_deliveries GROUP BY state")}
    counters = {
        r[0]: r[1]
        for r in conn.execute(
            "SELECT metric, SUM(value) FROM push_counters WHERE day >= ? GROUP BY metric",
            (_day(at - 6 * 86400),),
        )
    }
    recent = [
        dict(row)
        for row in conn.execute(
            """SELECT registration_id, state, platform, endpoint_host, created_at, activated_at,
                      telegram_confirmed_at, last_push_ok_at, last_push_error, ack_at
               FROM push_registrations ORDER BY created_at DESC LIMIT 50"""
        ).fetchall()
    ]
    return {
        "registrations": states,
        "active_platforms": platforms,
        "queue": queue,
        "health": health_snapshot(conn, at=at),
        "counters_7d": counters,
        "recent": recent,
    }
