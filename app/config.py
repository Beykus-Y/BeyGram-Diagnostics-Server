"""Конфигурация сервера.

Все значения читаются из переменных окружения / .env (см. .env.example).
Секреты (NONCE_PEPPER, токены ботов) никогда не попадают в логи и никогда
не передаются клиенту.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Общее ---------------------------------------------------------------
    app_env: str = "development"
    log_level: str = "INFO"
    log_format: str = "json"

    # --- Хранилище -----------------------------------------------------------
    database_path: str = "/data/beygram_reports.db"

    # --- Telegram ------------------------------------------------------------
    telegram_api_base: str = "https://api.telegram.org"
    report_bot_token: str = ""
    delivery_bot_token: str = ""
    delivery_chat_id: int = 0

    enable_bot: bool = True
    enable_worker: bool = True
    enable_maintenance: bool = True

    # --- Секреты -------------------------------------------------------------
    # Используется для HMAC-хэширования nonce в покое и для подписи status-токенов.
    nonce_pepper: str = ""

    # --- Доступ --------------------------------------------------------------
    bootstrap_allowlist: str = ""
    accept_reports: bool = True

    # --- Админ-панель --------------------------------------------------------
    # Пустой ADMIN_TOKEN полностью выключает панель (все /admin* отвечают 404).
    # Панель предназначена для приватной сети / identity-aware proxy.
    admin_token: str = ""
    admin_session_ttl_seconds: int = 3600
    admin_login_attempts_per_hour: int = 10
    admin_page_size: int = 25

    # --- Протокол / лимиты ---------------------------------------------------
    nonce_ttl_seconds: int = 420
    max_body_bytes: int = 256 * 1024
    max_description_chars: int = 2000
    max_summary_chars: int = 8000
    max_events: int = 2000
    max_event_message_chars: int = 500
    max_event_attr_value_chars: int = 200
    max_event_attrs: int = 24

    # --- Транспорт -----------------------------------------------------------
    require_https: bool = True
    # Сколько прокси перед сервером доверяем при разборе X-Forwarded-For / -Proto.
    trust_proxy_hops: int = 1
    # Дополнительные доверенные сети прокси (CIDR через запятую).
    trusted_proxy_networks_raw: str = ""

    # --- Rate limits ---------------------------------------------------------
    rl_user_reports_per_day: int = 5
    rl_user_reports_per_window: int = 2
    rl_user_reports_window_seconds: int = 600
    rl_user_report_cmd_per_hour: int = 10
    rl_global_reports_per_day: int = 500
    rl_ip_reports_per_hour: int = 20
    rl_global_report_cmd_per_hour: int = 500

    # --- Воркер --------------------------------------------------------------
    worker_poll_interval_seconds: float = 5.0
    worker_max_attempts: int = 6
    worker_lease_seconds: int = 180
    worker_backoff_base_seconds: int = 15

    # --- Anonymous installation analytics (independent from bug reports) -------
    accept_analytics: bool = True
    analytics_retention_days: int = 90
    rl_analytics_ip_per_hour: int = 180
    rl_analytics_global_per_day: int = 30000
    rl_analytics_registrations_per_day: int = 20

    # --- Хранение / обслуживание --------------------------------------------
    retention_days: int = 30
    audit_retention_days: int = 60
    maintenance_interval_seconds: int = 900

    # --- Bot polling ---------------------------------------------------------
    bot_poll_timeout_seconds: int = 50
    bot_poll_interval_seconds: float = 1.0
    bot_error_backoff_seconds: float = 5.0

    # --- Валидаторы ----------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, v: str) -> str:
        return v.upper()

    @field_validator("log_format")
    @classmethod
    def _check_format(cls, v: str) -> str:
        v = v.lower()
        if v not in {"json", "text"}:
            raise ValueError("LOG_FORMAT must be 'json' or 'text'")
        return v

    @field_validator("telegram_api_base")
    @classmethod
    def _check_api_base(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("TELEGRAM_API_BASE must be an http(s) URL")
        return v

    @field_validator("max_body_bytes")
    @classmethod
    def _check_body_limit(cls, v: int) -> int:
        if not (16 * 1024 <= v <= 4 * 1024 * 1024):
            raise ValueError("MAX_BODY_BYTES must be between 16 KiB and 4 MiB")
        return v

    @field_validator("nonce_ttl_seconds")
    @classmethod
    def _check_ttl(cls, v: int) -> int:
        if not (60 <= v <= 900):
            raise ValueError("NONCE_TTL_SECONDS must be between 60 and 900")
        return v

    @field_validator("admin_session_ttl_seconds")
    @classmethod
    def _check_admin_ttl(cls, v: int) -> int:
        if not (300 <= v <= 86400):
            raise ValueError("ADMIN_SESSION_TTL_SECONDS must be between 300 and 86400")
        return v

    @model_validator(mode="after")
    def _finalize(self) -> Settings:
        if not self.nonce_pepper:
            if self.is_production:
                raise ValueError("NONCE_PEPPER must be set in production")
            # Dev/test: детерминированно-случайный пеппер на время жизни процесса.
            object.__setattr__(self, "nonce_pepper", secrets.token_urlsafe(48))
            log.warning("NONCE_PEPPER is not set - generated an ephemeral one (development only)")

        if len(self.nonce_pepper) < 32:
            raise ValueError("NONCE_PEPPER must be at least 32 characters long")

        if not self.delivery_bot_token:
            object.__setattr__(self, "delivery_bot_token", self.report_bot_token)

        if self.is_production:
            if not self.report_bot_token:
                raise ValueError("REPORT_BOT_TOKEN must be set in production")
            if not self.delivery_chat_id:
                raise ValueError("DELIVERY_CHAT_ID must be set in production")

        return self

    # --- Свойства ------------------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in {"prod", "production"}

    @property
    def bootstrap_allowlist_ids(self) -> set[int]:
        """Разбирает BOOTSTRAP_ALLOWLIST ("111, 222") в набор id."""
        ids: set[int] = set()
        for chunk in self.bootstrap_allowlist.replace(";", ",").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                ids.add(int(chunk))
            except ValueError:
                log.warning("Ignoring invalid Telegram id in BOOTSTRAP_ALLOWLIST: %r", chunk)
        return {i for i in ids if i > 0}

    @property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        """Сети/адреса прокси, которым доверяем заголовки X-Forwarded-*.

        Определены по умолчанию как localhost + приватные диапазоны, чтобы
        корректно работать за Docker-прокси. Дополнительные адреса задаются
        через TRUSTED_PROXY_NETWORKS (через запятую) в .env.
        """
        extra = self.trusted_proxy_networks_raw or ""
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        for chunk in str(extra).replace(";", ",").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                nets.append(ipaddress.ip_network(chunk, strict=False))
            except ValueError:
                log.warning("Ignoring invalid network in TRUSTED_PROXY_NETWORKS: %r", chunk)
        return tuple(nets)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Кэшированный доступ к настройкам (позволяет переопределять в тестах)."""
    return Settings()


def reset_settings_cache() -> None:
    """Сброс кэша настроек — используется в тестах."""
    get_settings.cache_clear()
