"""Воркер доставки: забирает отчёты из очереди и отправляет разработчику.

Свойства:
* атомарный claim через lease (PROCESSING + lease_until) — один отчёт
  доставляется ровно один раз при живом воркере;
* истёкшие lease возвращаются в очередь (рестарт/падение процесса);
* временные ошибки Bot API → экспоненциальный ретрай с ограничением попыток;
* после исчерпания попыток отчёт помечается FAILED, клиент увидит это в статусе;
* подтверждённая доставка (получен message_id) → DELIVERED, nonce гасится;
* при выключателе приёма доставка уже принятых отчётов продолжается, но новые
  не берутся, если приём отключён глобально.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from ..config import Settings
from ..db import Database
from ..repository import audit, nonces, reports
from ..state import NONCE_DELIVERED, REPORT_DELIVERED, REPORT_FAILED, REPORT_QUEUED
from ..telegram import TelegramError, TelegramPermanentError, TelegramTemporaryError
from ..util import now
from .formatting import build_ack_message, build_report_message

log = logging.getLogger(__name__)


async def run(ctx) -> None:
    settings: Settings = ctx.settings
    log.info("delivery worker started", extra={"interval": settings.worker_poll_interval_seconds})

    while not ctx.stopping.is_set():
        try:
            processed = await _process_one(ctx)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("delivery worker iteration failed")
            processed = False

        if not processed:
            await _sleep(ctx, settings.worker_poll_interval_seconds)


async def _process_one(ctx) -> bool:
    """Обрабатывает максимум один отчёт. True, если что-то делал."""
    settings: Settings = ctx.settings
    db: Database = ctx.db

    def _claim():
        with db.transaction() as conn:
            # Сначала возвращаем в очередь всё, чей lease протух.
            reports.requeue_expired_leases(conn)
            return reports.claim_next_for_delivery(
                conn, lease_seconds=settings.worker_lease_seconds
            )

    report = await db.run(_claim)
    if report is None:
        return False

    try:
        message_ids = await _deliver(ctx, report)
    except TelegramPermanentError as exc:
        # Постоянная ошибка (бот заблокирован, чат неверный) — ретраить бессмысленно.
        await _finalize_failure(ctx, report, error=f"permanent: {exc}", retryable=False)
        return True
    except TelegramTemporaryError as exc:
        await _finalize_failure(ctx, report, error=f"temporary: {exc}", retryable=True)
        return True
    except TelegramError as exc:  # pragma: no cover - общий случай
        await _finalize_failure(ctx, report, error=f"telegram: {exc}", retryable=True)
        return True

    def _mark_delivered():
        with db.transaction() as conn:
            reports.mark_delivered(
                conn, report.report_id, message_id=message_ids[0] if message_ids else None
            )
            nonces.mark_delivered(conn, report.nonce_hash)
            audit.write(
                conn,
                actor="worker",
                action="report_delivered",
                target=report.report_id,
                detail={"attempts": report.attempts, "messages": len(message_ids)},
            )

    await db.run(_mark_delivered)
    log.info(
        "report delivered",
        extra={"report_id": report.report_id, "attempts": report.attempts},
    )

    # Уведомляем пользователя о доставке (не критично, если не получится).
    await _notify_user(ctx, report, delivered=True)
    return True


async def _deliver(ctx, report) -> list[int]:
    """Отправляет отчёт в служебный чат. Возвращает id отправленных сообщений."""
    settings: Settings = ctx.settings
    chat_id = settings.delivery_chat_id

    chunks = build_report_message(report)
    message_ids: list[int] = []
    for chunk in chunks:
        result = await ctx.delivery_bot.send_message(chat_id, chunk, disable_notification=False)
        message_id = result.get("message_id")
        if isinstance(message_id, int):
            message_ids.append(message_id)
    return message_ids


async def _finalize_failure(ctx, report, *, error: str, retryable: bool) -> None:
    settings: Settings = ctx.settings
    db: Database = ctx.db

    # Экспоненциальный backoff: base * 2^(attempts-1), с потолком 30 минут.
    attempt = max(1, report.attempts)
    delay = min(settings.worker_backoff_base_seconds * (2 ** (attempt - 1)), 1800)
    if not retryable:
        delay = 0

    def _do() -> str:
        with db.transaction() as conn:
            if not retryable:
                # Невосстановимая ошибка: сразу FAILED, попытки не тратим.
                conn.execute(
                    "UPDATE reports SET status = ?, last_error = ?, updated_at = ?, lease_until = NULL"
                    " WHERE report_id = ?",
                    (REPORT_FAILED, error[:1000], now(), report.report_id),
                )
                new_state = REPORT_FAILED
            else:
                new_state = reports.schedule_retry(
                    conn, report.report_id, error=error, delay_seconds=delay
                )

            audit.write(
                conn,
                actor="worker",
                action="report_delivery_failed",
                target=report.report_id,
                detail={
                    "error": error[:300],
                    "retryable": retryable,
                    "state": new_state,
                    "attempt": report.attempts,
                    "delay_seconds": delay,
                },
            )
            return new_state

    new_state = await db.run(_do)

    if new_state == REPORT_FAILED:
        log.error(
            "report delivery failed permanently",
            extra={"report_id": report.report_id, "attempts": report.attempts},
        )
        await _notify_user(ctx, report, delivered=False)
    else:
        log.warning(
            "report delivery retry scheduled",
            extra={"report_id": report.report_id, "delay": delay, "attempt": report.attempts},
        )


async def _notify_user(ctx, report, *, delivered: bool) -> None:
    """Сообщает пользователю итог доставки через бота подтверждения.

    Если пользователь заблокировал бота, это не считается ошибкой доставки:
    отчёт уже ушёл разработчику.
    """
    if not ctx.report_bot.has_token:
        return
    try:
        await ctx.report_bot.send_message(
            report.telegram_user_id,
            build_ack_message(report, delivered=delivered),
            disable_notification=True,
        )
    except TelegramError as exc:
        log.info("cannot notify user about delivery", extra={"reason": exc.__class__.__name__})


async def _sleep(ctx, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(ctx.stopping.wait(), timeout=seconds)


__all__ = ["run", "NONCE_DELIVERED", "REPORT_DELIVERED", "REPORT_FAILED", "REPORT_QUEUED"]
