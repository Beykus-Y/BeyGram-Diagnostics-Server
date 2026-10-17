"""Точка входа FastAPI: сборка приложения, middleware, lifespan, обработчики ошибок.

Запуск (dev):   uvicorn app.main:app --reload
Запуск (prod):  uvicorn app.main:app --host 0.0.0.0 --port 8080 --proxy-headers
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import API_PREFIX, Settings, get_settings
from .context import AppContext
from .db import Database
from .errors import ERR_INTERNAL, ERR_NOT_FOUND, ERR_PAYLOAD_INVALID, ApiError
from .logging_setup import setup_logging
from .middleware import (
    BodySizeLimitMiddleware,
    HttpsEnforcementMiddleware,
    RequestContextMiddleware,
    error_response,
)
from .repository import allowlist, audit
from .routers import admin, bug_reports, health
from .services.settings_service import set_intake_enabled

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    setup_logging(resolved.log_level, resolved.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ctx = AppContext.build(resolved)
        app.state.context = ctx

        await _bootstrap(ctx)
        ctx.start_background_tasks()
        log.info(
            "report server started",
            extra={
                "version": __version__,
                "env": resolved.app_env,
                "https_required": resolved.require_https,
                "bot_enabled": resolved.enable_bot,
                "worker_enabled": resolved.enable_worker,
            },
        )
        try:
            yield
        finally:
            log.info("report server stopping")
            await ctx.shutdown()

    app = FastAPI(
        title="BeyGram Report Server",
        version=__version__,
        description=(
            "Приём диагностических отчётов BeyGram: подтверждение владения "
            "Telegram-аккаунтом через бота и доставка отчёта разработчику."
        ),
        lifespan=lifespan,
        docs_url="/docs" if not resolved.is_production else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not resolved.is_production else None,
    )

    # Порядок добавления обратен порядку выполнения: последний добавленный —
    # самый внешний. Нам нужно, чтобы RequestContext оборачивал всё остальное.
    app.add_middleware(BodySizeLimitMiddleware, settings=resolved)
    app.add_middleware(HttpsEnforcementMiddleware, settings=resolved)
    app.add_middleware(RequestContextMiddleware)

    _register_error_handlers(app)

    app.include_router(health.router)
    app.include_router(bug_reports.router, prefix=API_PREFIX)
    # Админ-панель: вне /api/v1, выключена без ADMIN_TOKEN (404 на все /admin*).
    app.include_router(admin.router)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {"service": "beygram-report-server", "version": __version__}

    return app


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        return error_response(exc, request_id)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"loc": list(err.get("loc", ())), "type": err.get("type", "invalid")}
            for err in exc.errors()[:20]
        ]
        request_id = getattr(request.state, "request_id", None)
        content = {
            "error": {
                "code": ERR_PAYLOAD_INVALID,
                "message": "Запрос не соответствует схеме.",
                "details": details,
            }
        }
        if request_id:
            content["error"]["request_id"] = request_id
        return JSONResponse(status_code=422, content=content)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        if exc.status_code == 404:
            code, message = ERR_NOT_FOUND, "Ресурс не найден."
        elif exc.status_code == 405:
            code, message = "method_not_allowed", "Метод не поддерживается."
        else:
            code, message = ERR_INTERNAL, "Ошибка запроса."
        content = {"error": {"code": code, "message": message}}
        if request_id:
            content["error"]["request_id"] = request_id
        return JSONResponse(status_code=exc.status_code, content=content, headers=getattr(exc, "headers", None))


async def _bootstrap(ctx: AppContext) -> None:
    """Инициализация при старте: allowlist, выключатель приёма, проверка БД."""
    settings = ctx.settings
    db: Database = ctx.db

    def _seed() -> dict[str, object]:
        with db.transaction() as conn:
            added = allowlist.seed(conn, settings.bootstrap_allowlist_ids)
            # Начальное состояние выключателя приёма из конфигурации.
            if conn.execute("SELECT 1 FROM kv WHERE key = ?", ("accept_reports",)).fetchone() is None:
                set_intake_enabled(
                    conn,
                    settings.accept_reports,
                    actor="bootstrap",
                    note="initial value from configuration",
                )
            counts = allowlist.count_entries(conn)
            audit.write(
                conn,
                actor="bootstrap",
                action="startup",
                detail={"allowlist": counts, "bootstrap_added": added},
            )
            return {"added": added, **counts}

    result = await db.run(_seed)
    log.info("bootstrap complete", extra=result)

    integrity = await db.run(db.integrity_check)
    if integrity != "ok":
        log.error("database integrity check failed", extra={"result": integrity})


app = create_app()
