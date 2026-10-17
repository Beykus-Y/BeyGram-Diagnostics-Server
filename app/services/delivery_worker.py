"""Воркер доставки: забирает отчёты из очереди и отправляет разработчику.

Свойства:
* атомарный claim через lease (PROCESSING + lease_until + claim_version) —
  один отчёт доставляется одним воркером при живом процессе;
* fencing: все записи состояния принимаются только с актуальным
  claim_version, поэтому воркер, «переживший» отзыв отчёта (DROPPED) или
  истечение lease, не может перезаписать новое состояние;
* истёкшие lease возвращаются в очередь (рестарт/падение процесса);
* прогресс доставки (число отправленных частей) сохраняется после каждого
  подтверждённого sendMessage: ретрай продолжит со следующей части;
* семантика доставки — **at-least-once**: sendMessage не идемпотентен, при
  потере ответа/падении между отправкой и фиксацией прогресса часть может
  быть отправлена дважды. Все части помечены «часть i/n · report_id», чтобы
  дубли было легко опознать и отбросить;
* временные ошибки Bot API → экспоненциальный ретрай с ограничением попыток;
* после исчерпания попыток отчёт помечается FAILED, клиент увидит это в статусе;
* подтверждённая доставка → DELIVERED, nonce гасится (только при живом claim);
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
from ..state import REPORT_DELIVERED, REPORT_DROPPED, REPORT_FAILED, REPORT_QUEUED
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
            ctx.worker_failure("delivery-worker", "iteration failed")
            processed = False

        if not processed:
            await _sleep(ctx, settings.worker_poll_interval_seconds)


async def _process_one(ctx) -> bool:
    """Обрабатывает максимум один отчёт. True, если что-то делало."""
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
        ctx.worker_success("delivery-worker")
        return False

    claim_version = report.claim_version
    try:
        await _deliver(ctx, report)
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

    def _mark_delivered() -> bool:
        with db.transaction() as conn:
            ok = reports.mark_delivered(
                conn,
                report.report_id,
                claim_version=claim_version,
                message_id=None,
            )
            if not ok:
                # Claim устарел: отчёт отозван (DROPPED) или перезахвачен.
                audit.write(
                    conn,
                    actor="worker",
                    action="delivery_fenced",
                    target=report.report_id,
                    detail={"claim_version": claim_version},
                )
                return False
            nonces.mark_delivered(conn, report.nonce_hash)
            audit.write(
                conn,
                actor="worker",
                action="report_delivered",
                target=report.report_id,
                detail={"attempts": report.attempts},
            )
            return True

    delivered = await db.run(_mark_delivered)
    if not delivered:
        log.warning(
            "delivery result discarded by fencing token",
            extra={"report_id": report.report_id, "claim_version": claim_version},
        )
        return True

    ctx.worker_success("delivery-worker")
    log.info(
        "report delivered",
        extra={"report_id": report.report_id, "attempts": report.attempts},
    )

    # Уведомляем пользователя о доставке (не критично, если не получится).
    await _notify_user(ctx, report, delivered=True)
    return True


async def _deliver(ctx, report) -> None:
    """Отправляет отчёт в служебный чат, докупая с подтверждённой части.

    Прогресс (число отправленных частей) фиксируется в БД после каждого
    успешного sendMessage, поэтому после падения/ретрая уже отправленные
    части повторно не отправляются — кроме случая, когда ответ Bot API был
    потерян (неопределённый исход): тогда часть уйдёт повторно (at-least-once).
    """
    settings: Settings = ctx.settings
    db: Database = ctx.db
    chat_id = settings.delivery_chat_id
    claim_version = report.claim_version

    chunks = build_report_message(report)
    start = min(report.delivered_parts, len(chunks))
    if start:
        log.info(
            "resuming delivery from saved progress",
            extra={"report_id": report.report_id, "from_part": start + 1, "parts": len(chunks)},
        )

    for index in range(start, len(chunks)):
        # Отзыв может произойти между частями: перед каждой отправкой
        # перечитываем состояние и прекращаем доставку снятых отчётов.
        def _status() -> str | None:
            record = reports.get(db.connection, report.report_id)
            return record.status if record else None

        if await db.run(_status) == REPORT_DROPPED:
            log.warning(
                "report dropped mid-delivery; stopping",
                extra={"report_id": report.report_id, "part": index + 1},
            )
            return

        result = await ctx.delivery_bot.send_message(
            chat_id, chunks[index], disable_notification=False
        )
        message_id = result.get("message_id")
        parts_done = index + 1

        def _save_progress(
            _parts_done: int = parts_done, _message_id: int | None = message_id
        ) -> bool:
            # Значения цикла привязаны через дефолты (B023): db.run вызовет
            # замыкание в этой же итерации, но явная привязка безопаснее.
            with db.transaction() as conn:
                return reports.save_delivery_progress(
                    conn,
                    report.report_id,
                    claim_version=claim_version,
                    parts_delivered=_parts_done,
                    message_id=_message_id if isinstance(_message_id, int) else None,
                )

        if not await db.run(_save_progress):
            # Claim потерян — продолжать бессмысленно.
            log.warning(
                "delivery progress rejected by fencing token; stopping",
                extra={"report_id": report.report_id, "part": parts_done},
            )
            return
        ctx.worker_success("delivery-worker")


async def _finalize_failure(ctx, report, *, error: str, retryable: bool) -> None:
    settings: Settings = ctx.settings
    db: Database = ctx.db

    # Экспоненциальный backoff: base * 2^(attempts-1), с потолком 30 минут.
    attempt = max(1, report.attempts)
    delay = min(settings.worker_backoff_base_seconds * (2 ** (attempt - 1)), 1800)
    if not retryable:
        delay = 0

    def _do() -> str | None:
        with db.transaction() as conn:
            if not retryable:
                # Невосстановимая ошибка: сразу FAILED, попытки не тратим.
                cur = conn.execute(
                    "UPDATE reports SET status = ?, last_error = ?, updated_at = ?,"
                    " lease_until = NULL WHERE report_id = ? AND status = 'PROCESSING'"
                    " AND claim_version = ?",
                    (REPORT_FAILED, error[:1000], now(), report.report_id, report.claim_version),
                )
                new_state = REPORT_FAILED if cur.rowcount == 1 else None
            else:
                new_state = reports.schedule_retry(
                    conn,
                    report.report_id,
                    claim_version=report.claim_version,
                    error=error,
                    delay_seconds=delay,
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
    ctx.worker_failure("delivery-worker", error[:200])

    if new_state is None:
        # Fencing: состояние уже изменено админом/другим воркером — не трогаем.
        log.warning(
            "failure handling discarded by fencing token",
            extra={"report_id": report.report_id, "claim_version": report.claim_version},
        )
        return

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


__all__ = ["run", "REPORT_DELIVERED", "REPORT_FAILED", "REPORT_QUEUED"]
