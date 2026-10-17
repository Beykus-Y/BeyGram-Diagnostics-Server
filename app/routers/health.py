"""Health/readiness-эндпоинты для оркестратора и reverse proxy.

/healthz — дешёвый liveness без тяжёлых проверок и внешних вызовов.
/readyz — readiness: целостность БД, здоровье фоновых воркеров (жив ли,
когда последний успешный цикл) и возраст старейшего недоставленного отчёта.
Частичная деградация отражается отдельными полями и статусом degraded.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from .. import __version__
from ..context import AppContext
from ..dependencies import get_context
from ..repository import kv, reports
from ..schemas import HealthResponse
from ..services.settings_service import intake_enabled
from ..util import now

router = APIRouter(tags=["health"])

ContextDep = Annotated[AppContext, Depends(get_context)]

# Воркер считается «отставшим», если успешных циклов не было дольше этого.
_STALE_WORKER_SECONDS = 15 * 60


@router.get("/healthz", response_model=HealthResponse)
async def healthz(ctx: ContextDep) -> HealthResponse:
    """Liveness: сервер отвечает и БД доступна."""
    settings = ctx.settings

    def _check() -> tuple[bool, int]:
        enabled = intake_enabled(ctx.db.connection, settings)
        depth = ctx.db.connection.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE status IN ('QUEUED', 'PROCESSING')"
        ).fetchone()
        return enabled, int(depth["c"]) if depth else 0

    enabled, depth = await ctx.db.run(_check)
    return HealthResponse(
        status="ok",
        version=__version__,
        intake_enabled=enabled,
        queue_depth=depth,
        time=now(),
    )


@router.get("/readyz")
async def readyz(ctx: ContextDep) -> dict[str, object]:
    """Readiness: БД, воркеры, глубина и возраст очереди.

    degraded, если: БД повреждена; включённый воркер не запущен (или давно
    без успешных циклов) при непустой очереди/включённом боте.
    """
    settings = ctx.settings
    ts = now()

    def _check() -> dict[str, object]:
        integrity = ctx.db.integrity_check()
        depth = ctx.db.connection.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE status IN ('QUEUED', 'PROCESSING')"
        ).fetchone()
        note = kv.get_value(ctx.db.connection, kv.KEY_INTAKE_NOTE) or ""
        return {
            "integrity": integrity,
            "depth": int(depth["c"]) if depth else 0,
            "note": note,
            "oldest_queued_age": reports.oldest_queued_age(ctx.db.connection, at=ts),
        }

    info = await ctx.db.run(_check)
    workers = {name: entry.to_dict() for name, entry in sorted(ctx.health.items())}

    problems: list[str] = []
    if info["integrity"] != "ok":
        problems.append("database integrity")

    if settings.enable_worker and ctx.delivery_bot.has_token and settings.delivery_chat_id:
        if not ctx.worker_running("delivery-worker"):
            problems.append("delivery-worker not running")
        elif _is_stale(ctx, "delivery-worker", ts):
            problems.append("delivery-worker stale")

    if settings.enable_bot and ctx.report_bot.has_token:
        if not ctx.worker_running("bot-worker"):
            problems.append("bot-worker not running")
        elif _is_stale(ctx, "bot-worker", ts):
            problems.append("bot-worker stale")

    if info["depth"] and settings.enable_worker:
        age = info.get("oldest_queued_age")
        if isinstance(age, int | float) and age > _STALE_WORKER_SECONDS:
            problems.append("queue not draining")

    return {
        "status": "degraded" if problems else "ok",
        "problems": problems,
        "database": info["integrity"],
        "queue_depth": info["depth"],
        "oldest_queued_age_seconds": info.get("oldest_queued_age"),
        "intake_enabled": await ctx.db.run(
            lambda: intake_enabled(ctx.db.connection, settings)
        ),
        "intake_note": info["note"],
        "workers": workers,
        "version": __version__,
        "time": ts,
    }


def _is_stale(ctx: AppContext, name: str, ts: float) -> bool:
    entry = ctx.health.get(name)
    if entry is None:
        return True
    reference = entry.last_success_at or entry.started_at
    if reference is None:
        return True
    # Лёгкая скидка на прогрев: воркер мог ещё не завершить первую итерацию.
    if entry.last_success_at is None and ts - entry.started_at < _STALE_WORKER_SECONDS:
        return False
    return (ts - reference) > _STALE_WORKER_SECONDS
