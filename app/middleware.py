"""Middleware уровня приложения: HTTPS, лимит тела, корреляция, ошибки.

Порядок важен: RequestContext ставится первым (внешним), затем HTTPS-проверка,
затем лимит тела. Так отказ по размеру и по схеме уже имеет correlation id.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .config import Settings
from .errors import ERR_BODY_TOO_LARGE, ERR_INTERNAL, ERR_NOT_HTTPS, ApiError

log = logging.getLogger(__name__)

CORRELATION_HEADER = "X-Request-ID"

# Внешний request id принимаем только в безопасном формате: он попадает в
# JSON-логи и HTTP-ответы, поэтому произвольные строки (переводы строк,
# кавычки, управляющие символы, фальшивые Authorization-заголовки) недопустимы.
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


def _sanitize_request_id(raw: str | None) -> str | None:
    if not raw:
        return None
    candidate = raw.strip()
    if _CORRELATION_RE.match(candidate):
        return candidate
    return None


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Присваивает request id, пишет строку доступа и ловит необработанные ошибки.

    Заголовки запроса (в частности Authorization) в лог НЕ попадают.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Внешний id используем только если он прошёл форматную проверку,
        # иначе генерируем свой — в логи не должно попадать ничего кроме
        # ограниченного безопасного алфавита.
        request_id = _sanitize_request_id(request.headers.get(CORRELATION_HEADER)) or secrets.token_hex(8)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except ApiError as exc:
            response = error_response(exc, request_id)
        except Exception:  # noqa: BLE001 - наружу не должно утечь ничего
            log.exception("unhandled error", extra={"request_id": request_id, "path": request.url.path})
            response = JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": ERR_INTERNAL,
                        "message": "Внутренняя ошибка сервера.",
                        "request_id": request_id,
                    }
                },
            )
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers[CORRELATION_HEADER] = request_id
        # Логируем только метод/путь/код/время: тело и заголовки не пишем.
        if request.url.path not in {"/healthz", "/readyz"}:
            log.info(
                "http",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                    "client": _client_bucket(request),
                },
            )
        return response


class HttpsEnforcementMiddleware(BaseHTTPMiddleware):
    """Требует HTTPS для приёма отчётов (кроме health-check).

    За обратным прокси ориентируемся на X-Forwarded-Proto, но только если
    непосредственный клиент — доверенный прокси. Иначе злоумышленник мог бы
    подделать заголовок и обойти требование.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if not self._settings.require_https:
            return await call_next(request)
        if request.url.path in {"/healthz", "/readyz", "/"}:
            return await call_next(request)

        if request.url.scheme == "https" or _forwarded_proto_trusted(request, self._settings) == "https":
            return await call_next(request)

        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": ERR_NOT_HTTPS,
                    "message": "Требуется HTTPS.",
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Ограничивает размер тела запроса до чтения обработчиком.

    Проверяем и Content-Length, и фактический поток: заголовок может врать.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._limit = settings.max_body_bytes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self._limit:
                    return _too_large(self._limit, request)
            except ValueError:
                return _too_large(self._limit, request)

        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > self._limit:
                return _too_large(self._limit, request)

        # Перезаписываем receive, чтобы обработчик прочитал уже собранное тело.
        request._body = body  # noqa: SLF001 - штатный способ для BaseHTTPMiddleware

        async def _receive() -> dict:
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = _receive  # noqa: SLF001
        return await call_next(request)


# --- Вспомогательные функции ------------------------------------------------


def _too_large(limit: int, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={
            "error": {
                "code": ERR_BODY_TOO_LARGE,
                "message": f"Размер тела превышает лимит {limit} байт.",
                "request_id": getattr(request.state, "request_id", None),
            }
        },
    )


def _forwarded_proto_trusted(request: Request, settings: Settings) -> str | None:
    """Возвращает X-Forwarded-Proto, только если непосредственный клиент доверенный."""
    direct = request.client.host if request.client else None
    if direct is None:
        return None
    try:
        addr = ipaddress.ip_address(direct)
    except ValueError:
        return None
    if not any(addr in net for net in settings.trusted_proxy_networks):
        return None

    # X-Forwarded-Proto может быть списком: каждый прокси дописывает своё
    # значение справа. Значение, добавленное последним доверенным прокси,
    # находится на позиции trust_proxy_hops от конца.
    forwarded = request.headers.get("x-forwarded-proto", "")
    parts = [p.strip().lower() for p in forwarded.split(",") if p.strip()]
    if not parts:
        return None
    hops = max(1, settings.trust_proxy_hops)
    index = len(parts) - hops
    if index < 0:
        index = 0
    return parts[index]


def _client_bucket(request: Request) -> str:
    """Группирует клиента по сети /24 или /48, чтобы не логировать полный IP."""
    direct = request.client.host if request.client else None
    if not direct:
        return "unknown"
    try:
        addr = ipaddress.ip_address(direct)
    except ValueError:
        return "invalid"
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/48", strict=False))


def error_response(exc: ApiError, request_id: str | None) -> JSONResponse:
    content = exc.to_response()
    if request_id:
        content["error"]["request_id"] = request_id
    return JSONResponse(status_code=exc.http_status, content=content, headers=exc.headers)
