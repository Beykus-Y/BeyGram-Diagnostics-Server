"""Общие фикстуры тестов: изолированная БД, тестовое приложение, фейковый Bot API."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings, reset_settings_cache  # noqa: E402


@pytest.fixture()
def tmp_db_path(tmp_path) -> str:
    return str(tmp_path / "test_reports.db")


@pytest.fixture()
def settings(tmp_db_path) -> Settings:
    reset_settings_cache()
    return Settings(
        app_env="test",
        log_level="WARNING",
        log_format="text",
        database_path=tmp_db_path,
        nonce_pepper="test-pepper-that-is-long-enough-for-hmac-0123456789",
        report_bot_token="111:TESTTOKEN",
        delivery_bot_token="222:TESTTOKEN",
        delivery_chat_id=-100123,
        telegram_api_base="http://127.0.0.1:8081",
        require_https=False,
        enable_bot=False,
        enable_worker=False,
        enable_maintenance=False,
        bootstrap_allowlist="",
        nonce_ttl_seconds=300,
        rl_user_reports_per_day=5,
        rl_user_reports_per_window=2,
        rl_user_reports_window_seconds=600,
        rl_user_report_cmd_per_hour=10,
        rl_global_reports_per_day=500,
        rl_ip_reports_per_hour=20,
        rl_global_report_cmd_per_hour=500,
        retention_days=30,
    )


@pytest.fixture()
def db(settings) -> Iterator:
    from app.db import Database

    database = Database(settings.database_path)
    database.connect()
    try:
        yield database
    finally:
        database.close()


@pytest.fixture()
def temp_env(monkeypatch):
    """Позволяет задавать переменные окружения на время теста."""

    def _set(**values: str) -> None:
        for key, value in values.items():
            monkeypatch.setenv(key, value)

    return _set


@pytest.fixture()
def unused_tmp_dir() -> str:
    with tempfile.TemporaryDirectory() as d:
        yield d
