"""Тесты supervisor'а фоновых воркеров (AppContext)."""

from __future__ import annotations

import asyncio

import pytest

from app.context import _RESTART_BASE_SECONDS, AppContext


@pytest.fixture()
def fast_restart(monkeypatch):
    monkeypatch.setattr("app.context._RESTART_BASE_SECONDS", 0.01)


class _HealthOnlyContext(AppContext):
    """Минимальный контекст: только реестр здоровья и stopping-event."""

    def __init__(self) -> None:
        # Не вызываем super().__init__: данные не нужны, только поля.
        self.health = {}
        self.tasks = []
        self._stopping = asyncio.Event()


async def test_supervisor_restarts_crashed_worker(fast_restart):
    """Упавший воркер перезапускается новой корутиной, а не re-await'ом."""
    ctx = _HealthOnlyContext()
    calls = {"count": 0}

    async def worker() -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("boom")
        # Второй запуск живёт до остановки.
        await ctx.stopping.wait()

    supervisor = asyncio.create_task(ctx._supervise("test-worker", worker))
    # Даём первому запуску упасть и перезапуститься.
    await asyncio.sleep(0.1)

    entry = ctx.health["test-worker"]
    assert calls["count"] == 2, "воркер должен быть перезапущен новой корутиной"
    assert entry.running is True
    assert entry.restarts == 1
    assert entry.last_error == "RuntimeError"

    ctx.stopping.set()
    await asyncio.wait_for(supervisor, timeout=2)
    assert entry.running is False


async def test_supervisor_handles_repeated_crashes(fast_restart):
    """Каждый crash фиксируется, restarts растёт, процесс не падает."""
    ctx = _HealthOnlyContext()

    async def always_crash() -> None:
        raise ValueError("no luck")

    supervisor = asyncio.create_task(ctx._supervise("crasher", always_crash))
    await asyncio.sleep(0.15)

    entry = ctx.health["crasher"]
    assert entry.restarts >= 2
    assert entry.running is True

    ctx.stopping.set()
    await asyncio.wait_for(supervisor, timeout=2)


async def test_supervisor_marks_exited_worker(fast_restart):
    """Нормальный (вне остановки) выход воркера фиксируется как ошибка."""
    ctx = _HealthOnlyContext()

    async def exits_immediately() -> None:
        return None

    supervisor = asyncio.create_task(ctx._supervise("quitter", exits_immediately))
    await asyncio.sleep(0.05)
    ctx.stopping.set()
    await asyncio.wait_for(supervisor, timeout=2)

    entry = ctx.health["quitter"]
    assert entry.last_error == "worker exited unexpectedly"
    assert entry.running is False


def test_restart_base_is_configurable_constant():
    # Санкция на случай, если константу удалят при рефакторинге.
    assert _RESTART_BASE_SECONDS > 0
