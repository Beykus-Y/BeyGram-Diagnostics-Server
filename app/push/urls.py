"""Проверка Web Push endpoint-ов: только HTTPS и известные провайдеры.

Endpoint приходит от PWA, то есть от недоверенной стороны. Без проверки сервер
стал бы открытым прокси (SSRF). Поэтому принимаем только https на порту 443 и
хосты из белого списка (PUSH_ALLOWED_ENDPOINT_HOSTS). IP-литералы, учётные
данные в URL и фрагменты отклоняются.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = (
    "web.push.apple.com",
    "push.services.mozilla.com",
    "fcm.googleapis.com",
)
MAX_ENDPOINT_LENGTH = 2048
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class EndpointError(ValueError):
    """Endpoint не прошёл проверку. Текст безопасен для ответа клиенту."""


def parse_allowed_hosts(raw: str) -> tuple[str, ...]:
    """Разбирает список хостов из конфигурации; пустой список даёт значения по умолчанию."""
    hosts: list[str] = []
    for chunk in raw.replace(";", ",").split(","):
        host = chunk.strip().lower().rstrip(".")
        if not host:
            continue
        if not _HOST_RE.match(host):
            raise ValueError(f"invalid host in PUSH_ALLOWED_ENDPOINT_HOSTS: {host!r}")
        hosts.append(host)
    return tuple(hosts) or DEFAULT_ALLOWED_HOSTS


def validate_endpoint(endpoint: str, allowed_hosts: tuple[str, ...]) -> str:
    """Возвращает host endpoint-а, если он допустим; иначе бросает EndpointError."""
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > MAX_ENDPOINT_LENGTH:
        raise EndpointError("endpoint length is invalid")
    if not endpoint.isascii() or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in endpoint):
        raise EndpointError("endpoint contains forbidden characters")
    try:
        parts = urlsplit(endpoint)
        port = parts.port
    except ValueError as exc:
        raise EndpointError("endpoint is not a valid URL") from exc
    if parts.scheme != "https":
        raise EndpointError("endpoint must use https")
    if parts.username is not None or parts.password is not None:
        raise EndpointError("endpoint must not contain credentials")
    if port not in (None, 443):
        raise EndpointError("endpoint port is not allowed")
    if parts.fragment:
        raise EndpointError("endpoint must not contain a fragment")
    host = (parts.hostname or "").lower()
    if host.endswith("."):
        # Точка в конце попадает в audience VAPID, провайдер такой audience отклоняет.
        raise EndpointError("endpoint host must not end with a dot")
    if not host or not _HOST_RE.match(host):
        raise EndpointError("endpoint host is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EndpointError("IP literals are not allowed")
    if not any(host == allowed or host.endswith("." + allowed) for allowed in allowed_hosts):
        raise EndpointError("endpoint host is not an allowed push provider")
    return host
