"""Единый формат ошибок API.

Ответы об ошибках не должны раскрывать:
* разрешён ли конкретный Telegram id (для неавторизованных запросов);
* существует ли nonce/отчёт (для неизвестных и просроченных токенов — один и тот же код);
* содержимое внутренних ошибок (никаких трейсбеков наружу).
"""

from __future__ import annotations

from typing import Any

from fastapi import status


class ApiError(Exception):
    """Ошибка, которая сериализуется в JSON-конверт {error: {...}}."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status: int,
        *,
        retry_after: int | None = None,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details or []
        self.headers = dict(headers or {})
        if retry_after is not None:
            self.headers["Retry-After"] = str(int(retry_after))

    def to_response(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"error": error}


# --- Коды ошибок ------------------------------------------------------------

ERR_UNAUTHORIZED = "invalid_token"
ERR_PAYLOAD_INVALID = "payload_invalid"
ERR_BODY_TOO_LARGE = "body_too_large"
ERR_CONFLICT = "report_conflict"
ERR_LIMIT = "rate_limited"
ERR_DISABLED = "intake_disabled"
ERR_NOT_HTTPS = "https_required"
ERR_NOT_FOUND = "not_found"
ERR_INTERNAL = "internal_error"
ERR_METHOD_NOT_ALLOWED = "method_not_allowed"


def unauthorized(message: str = "Токен недействителен, просрочен или уже использован.") -> ApiError:
    """Единый ответ для неизвестного/просроченного/погашенного/отозванного токена."""
    return ApiError(ERR_UNAUTHORIZED, message, status.HTTP_401_UNAUTHORIZED)


def payload_invalid(details: list[dict[str, Any]] | None = None, message: str | None = None) -> ApiError:
    return ApiError(
        ERR_PAYLOAD_INVALID,
        message or "Тело отчёта не соответствует схеме.",
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=details,
    )


def body_too_large(limit: int) -> ApiError:
    return ApiError(
        ERR_BODY_TOO_LARGE,
        f"Размер тела превышает лимит {limit} байт.",
        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    )


def rate_limited(retry_after: int, message: str | None = None) -> ApiError:
    return ApiError(
        ERR_LIMIT,
        message or "Лимит отправки отчётов исчерпан. Попробуйте позже.",
        status.HTTP_429_TOO_MANY_REQUESTS,
        retry_after=retry_after,
    )


def intake_disabled() -> ApiError:
    return ApiError(
        ERR_DISABLED,
        "Приём отчётов временно приостановлен.",
        status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def report_conflict() -> ApiError:
    return ApiError(
        ERR_CONFLICT,
        "report_id уже использован для другого содержимого.",
        status.HTTP_409_CONFLICT,
    )
