"""Периодическое обслуживание: очистка, ротация, отчёты о состоянии.

Задачи:
* пометить EXPIRED непривязанные ISSUED nonce с истёкшим TTL и удалить
  старые погашенные, а также nonce удалённых отчётов;
* удалить доставленные/проваленные отчёты старше срока хранения;
* почистить счётчики rate limit и старый аудит;
* сделать WAL-checkpoint, чтобы файл БД не разрастался;
* записать в лог статистику очереди (мониторинг без внешних зависимостей).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from ..admin_sessions import prune_expired as prune_expired_sessions
from ..config import Settings
from ..db import Database
from ..repository import analytics, audit, nonces, rate_limit, reports
from ..util import now

log = logging.getLogger(__name__)

# Счётчики лимитов живут не дольше самого длинного окна (сутки) + запас.
_RATE_KEEP_SECONDS = 2 * 86400
# WAL-checkpoint выполняем не чаще, чем раз в час.
_CHECKPOINT_MIN_INTERVAL_SECONDS = 3600


async def run(ctx) -> None:
    settings: Settings = ctx.settings
    log.info("maintenance started", extra={"interval": settings.maintenance_interval_seconds})

    last_checkpoint = now()

    while not ctx.stopping.is_set():
        try:
            last_checkpoint = await _tick(ctx, settings, last_checkpoint=last_checkpoint)
            ctx.worker_success("maintenance")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            ctx.worker_failure("maintenance", "tick failed")
            log.exception("maintenance iteration failed")

        await _sleep(ctx, settings.maintenance_interval_seconds)


async def _tick(ctx, settings: Settings, *, last_checkpoint: float) -> float:
    db: Database = ctx.db
    ts = now()
    retention_cutoff = ts - settings.retention_days * 86400

    def _do() -> dict[str, object]:
        with db.transaction() as conn:
            expired = nonces.expire_stale(conn, at=ts)
            removed_nonces = nonces.delete_terminal_older_than(conn, retention_cutoff)
            # Сначала отчёты, потом осиротевшие nonce — окно гонки не страшно:
            # следующий тик дочистит остаток.
            removed_reports = reports.delete_older_than(conn, retention_cutoff)
            removed_orphans = nonces.delete_orphaned_bound(conn, retention_cutoff)
            removed_audit = audit.prune(
                conn, keep_seconds=settings.audit_retention_days * 86400, at=ts
            )
            removed_rate = rate_limit.prune(conn, keep_seconds=_RATE_KEEP_SECONDS, at=ts)
            removed_sessions = prune_expired_sessions(conn, at=ts)
            removed_analytics = analytics.prune(
                conn, at=ts, retention_days=settings.analytics_retention_days
            )
            return {
                "expired_nonces": expired,
                "removed_nonces": removed_nonces,
                "removed_orphan_nonces": removed_orphans,
                "removed_reports": removed_reports,
                "removed_audit": removed_audit,
                "removed_rate_events": removed_rate,
                "removed_admin_sessions": removed_sessions,
                "removed_analytics_installations": removed_analytics,
                "queue_depth": reports.queue_depth(conn),
                "queue": reports.queue_stats(conn),
                "nonce_states": nonces.count_by_state(conn),
            }

    result = await db.run(_do)

    cleaned = sum(
        int(result.get(key, 0))  # type: ignore[arg-type]
        for key in ("removed_nonces", "removed_reports", "removed_audit", "removed_rate_events", "removed_analytics_installations")
    )
    if cleaned:
        log.info("maintenance cleanup", extra=result)
    else:
        log.debug("maintenance tick", extra=result)

    if result.get("queue_depth"):
        log.info("queue depth", extra={"depth": result["queue_depth"], "queue": result["queue"]})

    if ts - last_checkpoint >= _CHECKPOINT_MIN_INTERVAL_SECONDS:
        await db.checkpoint()
        last_checkpoint = ts

    return last_checkpoint


async def _sleep(ctx, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(ctx.stopping.wait(), timeout=seconds)
