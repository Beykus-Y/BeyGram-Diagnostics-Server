"""FastAPI-зависимости: доступ к контексту и разбор клиентского IP/токена.

Здесь же реализовано доверенное определение реального IP клиента за прокси —
от него зависит IP-лимит. Если непосредственный клиент не входит в доверенные
сети, X-Forwarded-For игнорируется целиком (иначе лимит обходится подделкой).
"""

from __future__ import annotations

import ipaddress
import re

from fastapi import Request

from .config import Settings
from .context import AppContext
from .errors import unauthorized
from .security import validate_nonce

_BEARER_RE = re.compile(r"^Bearer\s+(\S+)$", re.IGNORECASE)


def get_context(request: Request) -> AppContext:
    ctx = getattr(request.app.state, "context", None)
    if ctx is None:  # pragma: no cover - защита от неправильной сборки приложения
        raise RuntimeError("AppContext is not initialized")
    return ctx


def get_settings_dep(request: Request) -> Settings:
    return get_context(request).settings


def client_ip(request: Request, settings: Settings) -> str | None:
    """Реальный IP клиента с учётом доверенных прокси.

    Алгоритм: если непосредственный адрес доверенный, берём из
    X-Forwarded-For значение, добавленное ближайшим доверенным прокси
    (trust_proxy_hops от конца списка). Иначе — адрес сокета.
    """
    direct = request.client.host if request.client else None
    if direct is None:
        return None

    try:
        direct_addr = ipaddress.ip_address(direct)
    except ValueError:
        return None

    if not any(direct_addr in net for net in settings.trusted_proxy_networks):
        return direct

    forwarded = request.headers.get("x-forwarded-for", "")
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    if not parts:
        return direct

    hops = max(1, settings.trust_proxy_hops)
    index = len(parts) - hops
    if index < 0:
        index = 0
    candidate = parts[index].strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return direct
    return candidate


def bearer_nonce(request: Request) -> str:
    """Извлекает и валидирует nonce из заголовка Authorization: Bearer <nonce>.

    Ничего не логирует: значение nonce наружу и в логи не попадает.
    """
    header = request.headers.get("authorization")
    if not header:
        raise unauthorized()
    match = _BEARER_RE.match(header.strip())
    if not match:
        raise unauthorized()
    token = match.group(1)
    try:
        validate_nonce(token)
    except ValueError:
        # Неверный формат неотличим от просроченного токена.
        raise unauthorized() from None
    return token


def status_token_from_request(request: Request) -> str:
    header = request.headers.get("authorization")
    if header:
        match = _BEARER_RE.match(header.strip())
        if match:
            return match.group(1)
    # Резервный способ для сред, где нельзя задать заголовок (например, тесты).
    return request.query_params.get("status_token", "")
