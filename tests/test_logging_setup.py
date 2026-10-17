"""Тесты настройки логирования: редактирование без порчи ленивого форматирования."""

from __future__ import annotations

import logging

from app.logging_setup import RedactingFilter, redact


def _record(msg: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord(
        name="test", level=logging.WARNING, pathname="p", lineno=1,
        msg=msg, args=args, exc_info=None,
    )


def test_lazy_percent_formatting_survives_filter():
    """%d/%s-аргументы не превращаются в строки до форматирования (#регрессия)."""
    f = RedactingFilter()
    record = _record("reply failed after %d attempts: %s", 4, "TelegramTemporaryError")

    assert f.filter(record) is True
    assert record.getMessage() == "reply failed after 4 attempts: TelegramTemporaryError"


def test_filter_redacts_bearer_token_in_message():
    f = RedactingFilter()
    record = _record("connect bearer ABCDEFabcdef123456", )

    assert f.filter(record) is True
    assert "ABCDEFabcdef123456" not in record.getMessage()
    assert "[redacted]" in record.getMessage()


def test_filter_redacts_bot_token_in_formatted_args():
    f = RedactingFilter()
    record = _record("using %s for polling", "bot1234567890:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxx")

    assert f.filter(record) is True
    message = record.getMessage()
    assert "AAExxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in message
    assert record.args is None


def test_redact_helper_direct():
    assert redact("authorization: SomethingSecret123") == "authorization: [redacted]"
    assert redact("обычный текст без секретов") == "обычный текст без секретов"
