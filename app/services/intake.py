"""Приём отчётов (POST /api/v1/bug-reports) и выдача статуса.

Ключевые гарантии:
* nonce проверяется по HMAC-хэшу, сырое значение нигде не сохраняется;
* переход ISSUED → PROCESSING → ACCEPTED выполняется в одной транзакции
  (BEGIN IMMEDIATE), поэтому повторная отправка не создаёт второй отчёт;
* повтор того же report_id с тем же содержимым — идемпотентный ответ;
* повтор с тем же report_id, но другим содержимым — 409;
* использование nonce для другого report_id — 409;
* лимиты применяются до создания отчёта;
* отказ по неизвестному/просроченному/отозванному токену неотличим (401).
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field

from ..config import Settings
from ..db import Database
from ..errors import (
    ERR_CONFLICT,
    ERR_DISABLED,
    ERR_LIMIT,
    ApiError,
    body_too_large,
    intake_disabled,
    payload_invalid,
    rate_limited,
    report_conflict,
    unauthorized,
)
from ..redaction import RedactionStats, redact_text, scrub_attr_value
from ..repository import allowlist, audit, nonces, rate_limit, reports
from ..schemas import BugReportIn
from ..security import hash_ip, hash_nonce, make_status_token
from ..state import (
    CLIENT_STATUS_DELIVERED,
    CLIENT_STATUS_FAILED,
    CLIENT_STATUS_QUEUED,
    NONCE_ACCEPTED,
    NONCE_DELIVERED,
    NONCE_ISSUED,
    NONCE_PROCESSING,
    NONCE_REVOKED,
    REPORT_DELIVERED,
    REPORT_FAILED,
)
from ..util import fingerprint, now
from .settings_service import intake_enabled

log = logging.getLogger(__name__)


@dataclass
class IntakeResult:
    report_id: str
    status: str
    accepted_at: float
    status_token: str
    idempotent_replay: bool
    redactions: dict[str, int] = field(default_factory=dict)
    detail: str = ""


# --- Публичный вход ---------------------------------------------------------


async def submit_report(
    db: Database,
    settings: Settings,
    *,
    payload: BugReportIn,
    nonce: str,
    client_ip: str | None,
    body_bytes: int,
) -> IntakeResult:
    """Обрабатывает отчёт целиком в одной транзакции."""
    if body_bytes > settings.max_body_bytes:
        raise body_too_large(settings.max_body_bytes)

    nonce_hash = hash_nonce(settings.nonce_pepper, nonce)
    ip_key = hash_ip(settings.nonce_pepper, client_ip)

    def _do() -> IntakeResult:
        with db.transaction() as conn:
            return _process(
                conn,
                settings=settings,
                payload=payload,
                nonce_hash=nonce_hash,
                ip_key=ip_key,
                body_bytes=body_bytes,
            )

    try:
        return await db.run(_do)
    except ApiError:
        raise
    except sqlite3.OperationalError as exc:  # перегрузка/блокировка — временная ошибка
        log.warning("database busy during intake", extra={"error": str(exc)})
        raise ApiError(
            "temporarily_unavailable",
            "Сервер перегружен, попробуйте ещё раз.",
            503,
        ) from exc


# --- Ядро транзакции --------------------------------------------------------


def _process(
    conn: sqlite3.Connection,
    *,
    settings: Settings,
    payload: BugReportIn,
    nonce_hash: str,
    ip_key: str,
    body_bytes: int,
) -> IntakeResult:
    if not intake_enabled(conn, settings):
        raise intake_disabled()

    record = nonces.get(conn, nonce_hash)
    if record is None:
        raise unauthorized()

    # Просроченный ISSUED-токен гасим явно, чтобы он не остался «живым».
    if record.state == NONCE_ISSUED and record.expires_at <= now():
        nonces.set_state(conn, nonce_hash, "EXPIRED")
        raise unauthorized()

    if record.state in {"EXPIRED", NONCE_REVOKED}:
        raise unauthorized()

    # Проверяем allowlist на момент приёма: пользователь мог быть отозван после
    # выдачи токена. Отзыв гасит и токен, и его непереданные отчёты.
    if not allowlist.is_active(conn, record.telegram_user_id):
        nonces.revoke_for_user(conn, record.telegram_user_id)
        reports.drop_pending_for_user(
            conn, record.telegram_user_id, reason="allowlist revoked", at=now()
        )
        raise unauthorized()

    request_fingerprint = _fingerprint_payload(payload)

    # --- Идемпотентность: токен уже привязан к отчёту ----------------------
    if record.state in {NONCE_PROCESSING, NONCE_ACCEPTED, NONCE_DELIVERED}:
        return _handle_replay(conn, settings, record, payload, request_fingerprint)

    # --- Лимиты (только для действительно новых отчётов) -------------------
    _enforce_limits(conn, settings, record.telegram_user_id, ip_key)

    # --- Атомарный claim + создание отчёта ---------------------------------
    redacted_description, redacted_summary, events, client_meta, stats = _sanitize(
        settings, payload
    )

    claimed = nonces.claim(
        conn,
        nonce_hash=nonce_hash,
        telegram_user_id=record.telegram_user_id,
        report_id=payload.report_id,
        request_fingerprint=request_fingerprint,
    )
    if claimed is None:
        # Кто-то успел погасить токен между проверкой и claim.
        raise unauthorized()

    report = reports.insert(
        conn,
        report_id=payload.report_id,
        telegram_user_id=record.telegram_user_id,
        nonce_hash=nonce_hash,
        description=redacted_description,
        summary=redacted_summary,
        events=events,
        client_meta=client_meta,
        payload_fingerprint=request_fingerprint,
        body_bytes=body_bytes,
        app_version=(client_meta or {}).get("app_version"),
        max_attempts=settings.worker_max_attempts,
        retention_days=settings.retention_days,
    )
    nonces.mark_accepted(conn, nonce_hash)

    audit.write(
        conn,
        actor="api",
        action="report_accepted",
        target=payload.report_id,
        detail={
            "telegram_user_id": record.telegram_user_id,
            "events": len(events),
            "body_bytes": body_bytes,
            "redactions": stats.to_dict(),
        },
    )

    return IntakeResult(
        report_id=report.report_id,
        status=CLIENT_STATUS_QUEUED,
        accepted_at=report.created_at,
        status_token=make_status_token(
            settings.nonce_pepper, report.report_id, record.telegram_user_id
        ),
        idempotent_replay=False,
        redactions=stats.to_dict(),
        detail="Отчёт принят и поставлен в очередь на доставку.",
    )


def _handle_replay(
    conn: sqlite3.Connection,
    settings: Settings,
    record,
    payload: BugReportIn,
    request_fingerprint: str,
) -> IntakeResult:
    """Повторный POST с уже использованным nonce.

    * тот же report_id и то же содержимое → идемпотентный ответ (без дубля);
    * другой report_id → 409: токен нельзя использовать для другого отчёта;
    * тот же report_id, но другое содержимое → 409.
    """
    if record.report_id != payload.report_id:
        audit.write(
            conn,
            actor="api",
            action="report_conflict",
            target=payload.report_id,
            detail={"reason": "nonce_bound_to_other_report", "bound": record.report_id},
        )
        raise report_conflict()

    if record.request_fingerprint != request_fingerprint:
        audit.write(
            conn,
            actor="api",
            action="report_conflict",
            target=payload.report_id,
            detail={"reason": "content_changed_for_report_id"},
        )
        raise report_conflict()

    report = reports.get(conn, payload.report_id)
    if report is None:
        raise unauthorized()

    status = {
        REPORT_DELIVERED: CLIENT_STATUS_DELIVERED,
        REPORT_FAILED: CLIENT_STATUS_FAILED,
    }.get(report.status, CLIENT_STATUS_QUEUED)

    return IntakeResult(
        report_id=report.report_id,
        status=status,
        accepted_at=report.created_at,
        status_token=make_status_token(
            settings.nonce_pepper, report.report_id, record.telegram_user_id
        ),
        idempotent_replay=True,
        detail="Этот отчёт уже был принят ранее (повторная отправка не создала дубль).",
    )


# --- Лимиты -----------------------------------------------------------------


def _enforce_limits(
    conn: sqlite3.Connection,
    settings: Settings,
    telegram_user_id: int,
    ip_key: str,
) -> None:
    """Проверяет и фиксирует лимиты. Порядок: пользователь → IP → глобальный."""
    ts = now()

    ok, retry = rate_limit.check_and_record(
        conn,
        scope=rate_limit.SCOPE_USER_REPORT,
        key=str(telegram_user_id),
        limit=settings.rl_user_reports_per_day,
        window_seconds=86400,
        at=ts,
    )
    if not ok:
        raise rate_limited(int(retry), "Достигнут дневной лимит отчётов. Попробуйте позже.")

    ok, retry = rate_limit.check_and_record(
        conn,
        scope=rate_limit.SCOPE_USER_REPORT,
        key=f"{telegram_user_id}:window",
        limit=settings.rl_user_reports_per_window,
        window_seconds=settings.rl_user_reports_window_seconds,
        at=ts,
    )
    if not ok:
        raise rate_limited(
            int(retry),
            "Слишком частые отправки. Подождите несколько минут и повторите.",
        )

    ok, retry = rate_limit.check_and_record(
        conn,
        scope=rate_limit.SCOPE_IP_REPORT,
        key=ip_key,
        limit=settings.rl_ip_reports_per_hour,
        window_seconds=3600,
        at=ts,
    )
    if not ok:
        raise rate_limited(int(retry), "Слишком много отчётов с одного адреса.")

    ok, retry = rate_limit.check_and_record(
        conn,
        scope=rate_limit.SCOPE_GLOBAL_REPORT,
        key=None,
        limit=settings.rl_global_reports_per_day,
        window_seconds=86400,
        at=ts,
    )
    if not ok:
        raise rate_limited(int(retry), "Сервер временно не принимает отчёты: общий лимит.")


# --- Санитизация содержимого ------------------------------------------------


def _sanitize(
    settings: Settings,
    payload: BugReportIn,
) -> tuple[str, str | None, list[dict], dict | None, RedactionStats]:
    """Применяет вторую линию защиты ко всем строкам отчёта."""
    stats = RedactionStats()

    description = redact_text(payload.description, stats)[: settings.max_description_chars]
    summary = None
    if payload.summary:
        summary = redact_text(payload.summary, stats)[: settings.max_summary_chars]

    events: list[dict] = []
    for event in payload.events[: settings.max_events]:
        attrs: dict[str, str] = {}
        for key, value in list(event.attrs.items())[: settings.max_event_attrs]:
            cleaned = scrub_attr_value(key, value, stats)
            attrs[key[:64]] = cleaned[: settings.max_event_attr_value_chars]

        events.append(
            {
                "seq": event.seq,
                "at": event.at,
                "kind": event.kind,
                "severity": event.severity,
                "code": event.code,
                "message": redact_text(event.message, stats)[: settings.max_event_message_chars],
                "attrs": attrs,
            }
        )

    client_meta = payload.client_meta.to_public_dict() if payload.client_meta else None
    return description, summary, events, client_meta, stats


def _fingerprint_payload(payload: BugReportIn) -> str:
    """Отпечаток содержимого для проверки идемпотентности.

    Считается по сырому payload до редактирования, чтобы повторная отправка
    того же тела клиентом всегда давала один и тот же отпечаток.
    """
    return fingerprint(payload.model_dump(mode="json", exclude_none=False))


# --- Статус отчёта ----------------------------------------------------------


@dataclass
class StatusResult:
    report_id: str
    status: str
    accepted_at: float
    updated_at: float
    delivered_at: float | None
    attempts: int
    detail: str


async def get_status(
    db: Database,
    settings: Settings,
    *,
    report_id: str,
    status_token: str,
) -> StatusResult:
    """Возвращает состояние отчёта по подписанному status-токену.

    Неверный/чужой токен и отсутствующий отчёт дают одинаковый ответ 401/404
    без раскрытия факта существования.
    """

    def _do() -> StatusResult:
        report = reports.get(db.connection, report_id)
        if report is None:
            raise unauthorized()

        from ..security import verify_status_token

        if not verify_status_token(
            settings.nonce_pepper, status_token, report_id, report.telegram_user_id
        ):
            raise unauthorized()

        status = {
            REPORT_DELIVERED: CLIENT_STATUS_DELIVERED,
            REPORT_FAILED: CLIENT_STATUS_FAILED,
        }.get(report.status, CLIENT_STATUS_QUEUED)

        detail = {
            CLIENT_STATUS_QUEUED: "Отчёт в очереди на доставку.",
            CLIENT_STATUS_DELIVERED: "Отчёт доставлен разработчику.",
            CLIENT_STATUS_FAILED: "Не удалось доставить отчёт. Используйте ручной экспорт.",
        }.get(status, "")

        return StatusResult(
            report_id=report.report_id,
            status=status,
            accepted_at=report.created_at,
            updated_at=report.updated_at,
            delivered_at=report.delivered_at,
            attempts=report.attempts,
            detail=detail,
        )

    return await db.run(_do)


__all__ = ["IntakeResult", "StatusResult", "get_status", "submit_report", "ERR_CONFLICT", "ERR_DISABLED", "ERR_LIMIT", "payload_invalid"]
