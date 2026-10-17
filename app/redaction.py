"""Серверная редакция (redaction) — вторая линия защиты после клиента.

Клиент обязан сам не включать переписки, токены и секреты в отчёт, но
полагаться только на клиент нельзя: любая строка, попавшая в события,
проходит здесь через:

1. детектор запрещённых образцов (номера телефонов, токены ботов, ссылки на
   подписки, приватные IP/хосты, YAML-ключи) — они вырезаются;
2. нормализацию URL/хостов — остаётся только схема и обфусцированный хост.

Функция возвращает статистику: сколько совпадений вырезано по категориям.
Это позволяет предупредить пользователя, что часть полей отредактирована,
и не отправлять разработчику лишнего.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

REDACTED = "[redacted]"

# --- Образцы ----------------------------------------------------------------

_BOT_TOKEN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_\-]{30,}\b")
_JWT_LIKE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{12,}")
_API_HASH = re.compile(r"(?i)\b(api[_\-]?hash)\b\s*[:=]\s*([0-9a-f]{16,})")
_PHONE = re.compile(r"(?<![\w.])(?:\+\d[\d\s\-\(\)]{7,}\d|\(\d{2,4}\)[\d\s\-]{6,}\d)(?![\w.])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SUBSCRIPTION_URL = re.compile(
    r"(?i)\b(?:https?|vless|vmess|trojan|ss|ssr|hysteria2?|tuic)://[^\s\"'<>]+"
)
_TG_LINK = re.compile(r"(?i)\bhttps?://t\.me/[^\s\"'<>]+")
_UUID_V4 = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_PRIVATE_IP_SHAPE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")
# Кандидаты в IPv6 (полная 8-групповая форма, сжатая с "::" и "::"-префикс).
# Regex только находит кандидатов — реальная проверка делается ipaddress.ip_address,
# поэтому «похожие» строки (время 12:34:56, MAC) остаются нетронутыми.
_IPV6 = re.compile(
    r"(?<![\w:.])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,7})?"
    r")"
    r"(?![\w:])"
)
_PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.DOTALL)
_SECRET_KV = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|token|session|auth[_-]?key|private[_-]?key|
        proxy[_-]?url|subscription|sub[_-]?url)\b\s*[:=]\s*("?)([^\s,;"']{6,})\2"""
)
_YAML_KEY = re.compile(
    r"(?im)^\s*(uuid|password|server|host|path|alterId|public-key|short-id)\s*:.*$"
)
_HOSTNAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)

_SECRET_KEY_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "auth",
    "session",
    "private_key",
    "privatekey",
    "api_hash",
    "apihash",
    "proxy_url",
    "subscription",
    "sub_url",
    "uuid",
    "cookie",
)

# Схемы URL, которые нельзя пропускать целиком (содержат креды/идентификаторы).
_OPAQUE_SCHEMES = (
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "tuic",
    "socks",
    "socks5",
)

# Домены, которые полезны для диагностики и не выдают пользователя.
_ALLOWED_HOST_SUFFIXES = (
    "telegram.org",
    "t.me",
    "telesco.pe",
    "telegram.dog",
    "google.com",
    "googleapis.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "github.com",
    "githubusercontent.com",
    "whatsapp.net",
    "facebook.com",
)


@dataclass
class RedactionStats:
    """Сколько совпадений вырезано по категориям."""

    counts: dict[str, int] = field(default_factory=dict)

    def bump(self, category: str, amount: int = 1) -> None:
        if amount <= 0:
            return
        self.counts[category] = self.counts.get(category, 0) + amount

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict[str, int]:
        return dict(sorted(self.counts.items()))


def _redact_pattern(pattern: re.Pattern[str], text: str, stats: RedactionStats, category: str) -> str:
    def _sub(_match: re.Match[str]) -> str:
        stats.bump(category)
        return REDACTED

    return pattern.sub(_sub, text)


def _redact_group(
    pattern: re.Pattern[str],
    text: str,
    stats: RedactionStats,
    category: str,
    *,
    keep_group: int,
) -> str:
    """Заменяет совпадение, сохраняя префиксную группу (например, имя ключа)."""

    def _sub(match: re.Match[str]) -> str:
        stats.bump(category)
        return f"{match.group(keep_group)}={REDACTED}"

    return pattern.sub(_sub, text)


def _is_private_or_sensitive_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _sanitize_url(match: re.Match[str], stats: RedactionStats) -> str:
    raw = match.group(0)
    scheme = raw.split("://", 1)[0].lower()

    # Для прокси-схем возвращаем только схему: остальное — инфраструктура
    # пользователя и не должно уходить разработчику.
    if scheme in _OPAQUE_SCHEMES:
        stats.bump("proxy_config")
        return f"{scheme}://{REDACTED}"

    try:
        from urllib.parse import urlsplit

        parts = urlsplit(raw)
        host = parts.hostname or ""
    except ValueError:  # pragma: no cover - неожиданный мусор
        stats.bump("sensitive_url")
        return REDACTED

    if _is_private_or_sensitive_host(host):
        stats.bump("private_host")
        return f"{scheme}://{REDACTED}"
    if host and not any(host == s or host.endswith("." + s) for s in _ALLOWED_HOST_SUFFIXES):
        stats.bump("external_host")
        return f"{scheme}://{REDACTED}"

    stats.bump("url_scrubbed")
    # Оставляем схему и хост, но убираем query/fragment/креды.
    return f"{scheme}://{host}"


def _redact_ipv6(text: str, stats: RedactionStats) -> str:
    """Вырезает IPv6-адреса; приватные/локальные — всегда, глобальные — тоже
    (в диагностику они не нужны, а приватность важнее)."""

    def _sub(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            addr = ipaddress.ip_address(candidate.strip("[]"))
        except ValueError:
            return candidate
        if addr.version != 6:
            return candidate
        stats.bump("ip_address")
        return REDACTED

    return _IPV6.sub(_sub, text)


def redact_text(text: str, stats: RedactionStats | None = None) -> str:
    """Вычищает секреты из произвольной строки.

    Полнота важнее точности: hostname и IPv6 вырезаются и здесь, чтобы
    вызывающие, забывшие про scrub_attr_value/redact_hostname, не пропустили
    инфраструктурные данные.
    """
    if not text:
        return text
    stats = stats if stats is not None else RedactionStats()
    result = text

    result = _redact_pattern(_PEM, result, stats, "pem_block")
    result = _redact_pattern(_BOT_TOKEN, result, stats, "bot_token")
    result = _redact_pattern(_JWT_LIKE, result, stats, "jwt")
    result = _redact_pattern(_BEARER, result, stats, "bearer")
    result = _redact_group(_API_HASH, result, stats, "api_hash", keep_group=1)
    result = _redact_pattern(_SECRET_KV, result, stats, "secret_kv")
    result = _redact_pattern(_YAML_KEY, result, stats, "yaml_secret")
    result = _redact_pattern(_TG_LINK, result, stats, "telegram_link")
    result = _redact_pattern(_EMAIL, result, stats, "email")
    result = _redact_pattern(_PHONE, result, stats, "phone")
    result = _redact_pattern(_PRIVATE_IP_SHAPE, result, stats, "ip_address")
    result = _redact_ipv6(result, stats)
    result = _redact_pattern(_UUID_V4, result, stats, "uuid")
    # Ссылки подписок/прокси — последними: для них нужна своя замена, а не [redacted].
    result = _SUBSCRIPTION_URL.sub(lambda m: _sanitize_url(m, stats), result)
    result = redact_hostname(result, stats)

    return result


def redact_hostname(text: str, stats: RedactionStats | None = None) -> str:
    """Обфусцирует доменные имена, не относящиеся к известным сервисам."""
    if not text:
        return text
    stats = stats if stats is not None else RedactionStats()

    def _sub(match: re.Match[str]) -> str:
        host = match.group(0).lower()
        if any(host == s or host.endswith("." + s) for s in _ALLOWED_HOST_SUFFIXES):
            return match.group(0)
        stats.bump("hostname")
        return REDACTED

    return _HOSTNAME.sub(_sub, text)


def is_sensitive_key(name: str) -> bool:
    """Ключ атрибута похож на секрет — значение вырезаем целиком."""
    lowered = name.lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def scrub_attr_value(key: str, value: str, stats: RedactionStats) -> str:
    """Обрабатывает значение атрибута события с учётом имени ключа."""
    if is_sensitive_key(key):
        stats.bump("sensitive_attr")
        return REDACTED
    cleaned = redact_text(value, stats)
    return redact_hostname(cleaned, stats)
