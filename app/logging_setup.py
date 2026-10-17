"""Настройка логирования.

Важно: Authorization-заголовок и необработанные секреты не должны попадать
в логи, поэтому:
* используется фильтр, вычищающий потенциальные токены из сообщений;
* middleware API не логирует заголовки запроса вообще (только код, путь, время).
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

_REDACT_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*)(\S+)"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9_\-\.=]+)"),
    re.compile(r"(?i)(bot)(\d{6,}:[A-Za-z0-9_\-]{20,})"),
    re.compile(r"(?i)(nonce\s*[:=]\s*)([A-Za-z0-9_\-]{10,})"),
    re.compile(r"(?i)(token\s*[:=]\s*)([A-Za-z0-9_\-\.]{16,})"),
)

REDACTED = "[redacted]"


def redact(text: str) -> str:
    result = text
    for pattern in _REDACT_PATTERNS:
        result = pattern.sub(lambda m: m.group(1) + REDACTED, result)
    return result


class RedactingFilter(logging.Filter):
    """Вычищает токены из сообщений записи.

    Сообщение форматируется ЗАРАНЕЕ (getMessage) и args сбрасываются:
    редактрование превращает аргументы в строки, и ленивое %-форматирование
    (%d и т.п.) падало бы TypeError при последующем рендере записи.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = redact(record.getMessage())
            record.args = None
        except Exception:  # pragma: no cover - логирование не должно ломать запрос
            pass
        return True


class JsonFormatter(logging.Formatter):
    """Минималистичный JSON-формат для сбора логов на сервере."""

    _RESERVED = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Идемпотентная настройка корневого логгера."""
    root = logging.getLogger()
    resolved_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    handler.addFilter(RedactingFilter())

    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(resolved_level)

    # uvicorn добавляет свои хендлеры — отключаем дубли и прогоняем через фильтр.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(noisy)
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(resolved_level if noisy != "uvicorn.access" else max(resolved_level, logging.WARNING))

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
