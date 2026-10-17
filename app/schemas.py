"""Pydantic-схемы API: строгий контракт входящих отчётов.

Принципы:
* extra="forbid" — клиент не может протащить неизвестные поля;
* все строки ограничены по длине, списки — по количеству элементов;
* структура фиксирована (никаких произвольных вложенных BLOB/base64-архивов);
* сервер не доверяет полям telegram_user_id / nonce внутри тела — они
  игнорируются как неизвестные именно потому, что schema их не содержит.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .config import Settings
from .util import is_uuid4

# --- Базовые типы -----------------------------------------------------------

EventKind = Literal[
    "connection",
    "network",
    "vpn",
    "tdlib",
    "update",
    "error",
    "performance",
    "ui",
    "other",
]

Severity = Literal["debug", "info", "warning", "error", "critical"]

# Строки без управляющих символов (кроме табов/переводов строк, нормализуем ниже).
TextStr = Annotated[str, StringConstraints(strip_whitespace=True)]
ShortStr = Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)]
TinyStr = Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]

_APP_VERSION = Annotated[str, StringConstraints(max_length=64, pattern=r"^[A-Za-z0-9._+\- ]*$")]


def _strip_controls(value: str) -> str:
    """Удаляет управляющие символы, оставляя \n и \t."""
    return "".join(ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32)


class BaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --- Входящая модель отчёта -------------------------------------------------


class DiagnosticEventIn(BaseIn):
    """Одно структурированное событие диагностики.

    Событие намеренно «плоское»: время, тип, важность, короткое сообщение и
    небольшой словарь атрибутов. Ничего, что похоже на переписку или секреты,
    схема не принимает по смыслу — а редакция вычищает остатки.
    """

    seq: int | None = Field(default=None, ge=0, le=1_000_000)
    at: float | None = Field(default=None, description="Unix-время события (секунды)")
    kind: EventKind = "other"
    severity: Severity = "info"
    code: TinyStr | None = None
    message: Annotated[str, StringConstraints(max_length=500)] = ""
    attrs: dict[TinyStr, Annotated[str, StringConstraints(max_length=200)]] = Field(default_factory=dict)

    @field_validator("message")
    @classmethod
    def _clean_message(cls, v: str) -> str:
        return _strip_controls(v)

    @field_validator("attrs")
    @classmethod
    def _limit_attrs(cls, v: dict[str, str]) -> dict[str, str]:
        return {k: _strip_controls(val) for k, val in v.items()}

    @model_validator(mode="after")
    def _cap_attrs(self) -> DiagnosticEventIn:
        if len(self.attrs) > 24:
            # Обрезаем по числу ключей: сохраняем первые 24 в стабильном порядке.
            self.attrs = dict(sorted(self.attrs.items())[:24])
        return self


class ClientMetaIn(BaseIn):
    """Необязательные несекретные метаданные клиента (только из фиксированного набора)."""

    app_version: _APP_VERSION | None = None
    app_version_code: int | None = Field(default=None, ge=0, le=2_000_000_000)
    platform: TinyStr | None = None
    os_version: TinyStr | None = None
    device_model: ShortStr | None = None
    locale: TinyStr | None = None
    vpn_active: bool | None = None
    proxy_enabled: bool | None = None
    tdlib_version: TinyStr | None = None
    event_count_total: int | None = Field(default=None, ge=0, le=1_000_000)
    buffer_overflowed: bool | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class BugReportIn(BaseIn):
    """Тело POST /api/v1/bug-reports.

    Обратите внимание: здесь НЕТ полей nonce и telegram_user_id.
    Токен приходит в заголовке Authorization, а принадлежность аккаунта
    подтверждена ботом; любые дополнительные поля будут отвергнуты (extra=forbid).
    """

    schema_version: Literal[1] = 1
    report_id: str
    description: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    summary: Annotated[str, StringConstraints(max_length=8000)] | None = None
    client_meta: ClientMetaIn | None = None
    events: list[DiagnosticEventIn] = Field(default_factory=list, max_length=2000)
    created_at: float | None = None

    @field_validator("report_id")
    @classmethod
    def _check_report_id(cls, v: str) -> str:
        if not is_uuid4(v):
            raise ValueError("report_id must be a canonical UUID v4")
        return v.lower()

    @field_validator("description")
    @classmethod
    def _clean_description(cls, v: str) -> str:
        return _strip_controls(v)

    @field_validator("summary")
    @classmethod
    def _clean_summary(cls, v: str | None) -> str | None:
        return _strip_controls(v) if v is not None else None

    @model_validator(mode="after")
    def _cap_events(self) -> BugReportIn:
        if len(self.events) > 2000:
            raise ValueError("too many events")
        return self


# --- Ответы API -------------------------------------------------------------


class AcceptedBugReport(BaseIn):
    """Ответ на успешный приём отчёта."""

    report_id: str
    status: Literal["queued", "delivered", "failed"]
    accepted_at: float
    status_token: str
    idempotent_replay: bool = False
    redactions: dict[str, int] = Field(default_factory=dict)
    detail: str = ""


class BugReportStatus(BaseIn):
    """Ответ GET /api/v1/bug-reports/{report_id}."""

    report_id: str
    status: Literal["queued", "delivered", "failed"]
    accepted_at: float
    updated_at: float
    delivered_at: float | None = None
    attempts: int = 0
    detail: str = ""


class HealthResponse(BaseIn):
    status: Literal["ok", "degraded"]
    version: str
    intake_enabled: bool
    queue_depth: int
    time: float


# --- Вспомогательные конструкторы -----------------------------------------


def apply_limits(schema: Settings) -> None:
    """Применяет лимиты из настроек к схемам (длины строк, число событий).

    Pydantic описывает статические максимумы, а настройки позволяют их
    ужесточить — это используется, если для закрытой беты нужны более
    строгие значения, чем жёстко зашитые.
    """
    # Статические максимумы уже соответствуют требованиям MVP; эта функция
    # оставлена точкой расширения и проверяет согласованность конфигурации.
    if schema.max_events > 2000:
        raise ValueError("MAX_EVENTS cannot exceed 2000 for the MVP schema")
    if schema.max_description_chars > 2000:
        raise ValueError("MAX_DESCRIPTION_CHARS cannot exceed 2000 for the MVP schema")
