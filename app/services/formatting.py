"""Форматирование отчёта для доставки в служебный чат разработчика.

Текст собирается из уже отредактированных данных. Никакой Markdown-разметки
по умолчанию (чтобы данные не могли влиять на форматирование), только
экранирование — сообщение отправляется как обычный текст.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

MAX_MESSAGE_CHARS = 4000


def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "—"


def _fmt_attrs(attrs: dict[str, Any]) -> str:
    if not attrs:
        return ""
    parts = [f"{k}={attrs[k]}" for k in sorted(attrs)]
    return " " + " ".join(parts)


def build_report_message(report) -> list[str]:
    """Возвращает список сообщений (каждое ≤ 4096 символов)."""
    meta = report.client_meta()

    header_lines = [
        "🐞 Новый диагностический отчёт BeyGram",
        "",
        f"report_id: {report.report_id}",
        f"Пользователь: {report.telegram_user_id}",
        f"Принят: {_fmt_time(report.created_at)}",
    ]
    if meta:
        meta_bits = [f"{k}={meta[k]}" for k in sorted(meta)]
        header_lines.append("Клиент: " + ", ".join(meta_bits))

    header_lines.append("")
    header_lines.append("— Описание —")
    header_lines.append(report.description or "(пусто)")

    if report.summary:
        header_lines.append("")
        header_lines.append("— Сводка —")
        header_lines.append(report.summary)

    header_lines.append("")
    header_lines.append(f"— События ({len(report.events())}) —")

    body = "\n".join(header_lines)
    chunks: list[str] = []
    current = body

    for event in report.events():
        line = _format_event(event)
        if len(current) + len(line) + 1 > MAX_MESSAGE_CHARS:
            chunks.append(current)
            current = ""
        current += ("\n" if current else "") + line

    chunks.append(current)
    return chunks


def _format_event(event: dict[str, Any]) -> str:
    at = event.get("at")
    when = ""
    if isinstance(at, int | float) and at:
        try:
            when = datetime.fromtimestamp(at, tz=UTC).strftime("%H:%M:%S ")
        except (OverflowError, OSError, ValueError):
            when = ""

    kind = event.get("kind") or "other"
    severity = (event.get("severity") or "info").upper()
    code = event.get("code")
    code_part = f" [{code}]" if code else ""
    message = event.get("message") or ""
    attrs = event.get("attrs") or {}
    return f"{when}{severity} {kind}{code_part}: {message}{_fmt_attrs(attrs)}".rstrip()


def build_ack_message(report, *, delivered: bool) -> str:
    if delivered:
        return f"✅ Отчёт {report.report_id} доставлен разработчику."
    return (
        f"⚠️ Отчёт {report.report_id} не удалось доставить автоматически.\n"
        "Используйте ручной экспорт в BeyGram (Настройки → Диагностика → Поделиться)."
    )
