"""Контекст приложения: настройки, БД, клиенты Telegram, фоновые задачи.

Один объект на процесс. Создаётся в lifespan FastAPI и передаётся в
зависимости через app.state. Здесь же живёт реестр здоровья фоновых
воркеров: /readyz показывает, работает ли bot/delivery/maintenance, когда
был последний успешный цикл и сколько раз воркер перезапускался.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

from .config import Settings
from .db import Database
from .telegram import DeliveryBotClient, ReportBotClient

log = logging.getLogger(__name__)

# Пауза перед перезапуском упавшего воркера (линейно растёт до потолка).
_RESTART_BASE_SECONDS = 2.0
_RESTART_MAX_SECONDS = 60.0


@dataclass
class WorkerHealth:
    """Наблюдаемое состояние одного фонового воркера."""

    name: str
    running: bool = False
    started_at: float | None = None
    last_success_at: float | None = None
    last_failure_at: float | None = None
    consecutive_failures: int = 0
    restarts: int = 0
    last_error: str | None = None

    def to_dict(self) -> dict:
        return {
            "running": self.running,
            "started_at": self.started_at,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "consecutive_failures": self.consecutive_failures,
            "restarts": self.restarts,
            "last_error": self.last_error,
        }


@dataclass
class AppContext:
    settings: Settings
    db: Database
    report_bot: ReportBotClient
    delivery_bot: DeliveryBotClient
    health: dict[str, WorkerHealth] = field(default_factory=dict)
    tasks: list[asyncio.Task] = field(default_factory=list)
    _stopping: asyncio.Event = field(default_factory=asyncio.Event)

    # --- Создание -----------------------------------------------------------

    @classmethod
    def build(cls, settings: Settings) -> AppContext:
        db = Database(settings.database_path)
        db.connect()
        return cls(
            settings=settings,
            db=db,
            report_bot=ReportBotClient(settings.report_bot_token, settings.telegram_api_base),
            delivery_bot=DeliveryBotClient(settings.delivery_bot_token, settings.telegram_api_base),
        )

    # --- Реестр здоровья воркеров -------------------------------------------

    def _health(self, name: str) -> WorkerHealth:
        return self.health.setdefault(name, WorkerHealth(name=name))

    def worker_success(self, name: str) -> None:
        """Воркер завершил успешную итерацию (poll/tick/доставка)."""
        entry = self._health(name)
        entry.last_success_at = time.time()
        entry.consecutive_failures = 0

    def worker_failure(self, name: str, error: str) -> None:
        """Воркер зафиксировал сбой итерации (временный или постоянный)."""
        entry = self._health(name)
        entry.last_failure_at = time.time()
        entry.consecutive_failures += 1
        entry.last_error = (error or "unknown")[:300]

    def worker_running(self, name: str) -> bool:
        entry = self.health.get(name)
        return bool(entry and entry.running)

    # --- Фоновые задачи -----------------------------------------------------

    def start_background_tasks(self) -> None:
        """Запускает бота, воркер доставки и обслуживание под supervisor.

        Supervisor следит за задачей: неожиданное завершение фиксируется в
        health-реестре, воркер перезапускается с растущей паузой, пока процесс
        не остановлен. Так «тихая смерть» фонового кода не оставляет сервер
        внешне живым, но без обработки отчётов.
        """
        from .services import bot_worker, delivery_worker, maintenance

        planned: list[tuple[str, object]] = []
        if self.settings.enable_bot:
            if self.report_bot.has_token:
                planned.append(("bot-worker", lambda: bot_worker.run(self)))
            else:
                log.warning("bot worker disabled: REPORT_BOT_TOKEN is empty")

        if self.settings.enable_worker:
            if self.delivery_bot.has_token and self.settings.delivery_chat_id:
                planned.append(("delivery-worker", lambda: delivery_worker.run(self)))
            else:
                log.warning(
                    "delivery worker disabled: token/chat are not configured",
                    extra={"has_token": self.delivery_bot.has_token},
                )

        if self.settings.enable_maintenance:
            planned.append(("maintenance", lambda: maintenance.run(self)))

        for name, factory in planned:
            self.tasks.append(asyncio.create_task(self._supervise(name, factory), name=name))

    async def _supervise(self, name: str, factory) -> None:
        """Перезапускает воркер до остановки процесса, пишет состояние в реестр.

        `factory` — функция, создающая НОВУЮ корутину при каждом запуске:
        корутину Python нельзя ожидать повторно, поэтому хранить и
        ре-await'ить готовую нельзя (RuntimeError: cannot reuse already
        awaited coroutine) — воркеры фактически не перезапускались бы.
        """
        entry = self._health(name)
        entry.running = True
        entry.started_at = time.time()
        try:
            delay = _RESTART_BASE_SECONDS
            while not self._stopping.is_set():
                try:
                    await factory()
                    # Нормальный выход возможен только при остановке.
                    if self._stopping.is_set():
                        break
                    entry.last_error = "worker exited unexpectedly"
                    log.error("worker exited unexpectedly", extra={"worker": name})
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    entry.last_error = f"{exc.__class__.__name__}"
                    log.exception("worker crashed; restarting", extra={"worker": name})
                entry.restarts += 1
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stopping.wait(), timeout=delay)
                delay = min(delay * 2, _RESTART_MAX_SECONDS)
        finally:
            entry.running = False

    async def stop_background_tasks(self) -> None:
        self._stopping.set()
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self.tasks.clear()

    @property
    def stopping(self) -> asyncio.Event:
        return self._stopping

    # --- Завершение ---------------------------------------------------------

    async def shutdown(self) -> None:
        await self.stop_background_tasks()
        await self.report_bot.aclose()
        await self.delivery_bot.aclose()
        await self.db.run(self.db.close)
