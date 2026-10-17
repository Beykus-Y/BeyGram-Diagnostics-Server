"""Health/readiness-эндпоинты для оркестратора и reverse proxy."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from .. import __version__
from ..context import AppContext
from ..dependencies import get_context
from ..repository import kv
from ..schemas import HealthResponse
from ..services.settings_service import intake_enabled
from ..util import now

router = APIRouter(tags=["health"])

ContextDep = Annotated[AppContext, Depends(get_context)]


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
    """Readiness: готовность зависимостей и глубина очереди."""
    settings = ctx.settings

    def _check() -> dict[str, object]:
        integrity = ctx.db.integrity_check()
        depth = ctx.db.connection.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE status IN ('QUEUED', 'PROCESSING')"
        ).fetchone()
        note = kv.get_value(ctx.db.connection, kv.KEY_INTAKE_NOTE) or ""
        return {"integrity": integrity, "depth": int(depth["c"]) if depth else 0, "note": note}

    info = await ctx.db.run(_check)
    ready = info["integrity"] == "ok"
    return {
        "status": "ok" if ready else "degraded",
        "database": info["integrity"],
        "queue_depth": info["depth"],
        "intake_enabled": await ctx.db.run(
            lambda: intake_enabled(ctx.db.connection, settings)
        ),
        "intake_note": info["note"],
        "version": __version__,
    }
