"""Форматирование отчёта для доставки в служебный чат разработчика.

Текст собирается из уже отредактированных данных. Никакой Markdown-разметки
по умолчанию (чтобы данные не могли влиять на форматирование), только
экранирование — сообщение отправляется как обычный текст.

Гарантия размера: каждая часть строится так, чтобы уложиться в лимит Telegram
(4096), включая служебную подпись с номером части. Ничего не обрезается
молча — длинные блоки переносятся в следующую часть.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

MAX_MESSAGE_CHARS = 3960
# Резерв под подпись «[отчёт … · часть i/n]», добавляемую к каждой части.
# MAX_MESSAGE_CHARS + _PART_SUFFIX_RESERVE должно быть <= 4096 (лимит Telegram).
_PART_SUFFIX_RESERVE = 120


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
    """Собирает отчёт в список сообщений.

    Гарантии:
    * каждая часть ≤ MAX_MESSAGE_CHARS символов (с подписью части);
    * каждая часть содержит report_id и номер «часть i/n» — это и защита от
      потери контекста при дублях (at-least-once), и удобная дедупликация;
    * ни одна строка данных не обрезается молча: не влезло — переносится
      либо (одиночная сверхдлинная строка) режется с явным маркером «…».
    """
    meta = report.client_meta()

    lines: list[str] = []
    lines.append("🐞 Новый диагностический отчёт BeyGram")
    lines.append("")
    lines.append(f"report_id: {report.report_id}")
    lines.append(f"Пользователь: {report.telegram_user_id}")
    lines.append(f"Принят: {_fmt_time(report.created_at)}")
    if meta:
        meta_bits = [f"{k}={meta[k]}" for k in sorted(meta)]
        lines.append("Клиент: " + ", ".join(meta_bits))
    lines.append("")
    lines.append("— Описание —")
    _append_wrapped(lines, report.description or "(пусто)")
    if report.summary:
        lines.append("")
        lines.append("— Сводка —")
        _append_wrapped(lines, report.summary)
    lines.append("")
    lines.append(f"— События ({len(report.events())}) —")
    for event in report.events():
        _append_wrapped(lines, _format_event(event))

    return _pack_into_chunks(lines, report_id=report.report_id)


def _append_wrapped(lines: list[str], text: str) -> None:
    """Добавляет текст построчно; строки длиннее лимита режутся с «…»."""
    limit = MAX_MESSAGE_CHARS - _PART_SUFFIX_RESERVE
    for line in text.splitlines() or [""]:
        while len(line) > limit:
            lines.append(line[:limit] + " …(продолжение ниже)")
            line = line[limit:]
        lines.append(line)


def _pack_into_chunks(lines: list[str], *, report_id: str) -> list[str]:
    """Жадно упаковывает строки в части с подписью «часть i/n»."""
    capacity = MAX_MESSAGE_CHARS - _PART_SUFFIX_RESERVE
    chunks: list[str] = []
    current = ""
    for line in lines:
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > capacity and current:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current or not chunks:
        chunks.append(current)

    total = len(chunks)
    result: list[str] = []
    for index, body in enumerate(chunks, start=1):
        suffix = f"\n— часть {index}/{total} · {report_id}"
        result.append(body + suffix)
    return result


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
