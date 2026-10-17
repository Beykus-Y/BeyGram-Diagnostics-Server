"""Контекст приложения: настройки, БД, клиенты Telegram, фоновые задачи.

Один объект на процесс. Создаётся в lifespan FastAPI и передаётся в
зависимости через app.state.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field

from .config import Settings
from .db import Database
from .telegram import DeliveryBotClient, ReportBotClient

log = logging.getLogger(__name__)


@dataclass
class AppContext:
    settings: Settings
    db: Database
    report_bot: ReportBotClient
    delivery_bot: DeliveryBotClient
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

    # --- Фоновые задачи -----------------------------------------------------

    def start_background_tasks(self) -> None:
        """Запускает бота, воркер доставки и обслуживание по флагам конфигурации."""
        from .services import bot_worker, delivery_worker, maintenance

        if self.settings.enable_bot:
            if self.report_bot.has_token:
                self.tasks.append(asyncio.create_task(bot_worker.run(self), name="bot-worker"))
            else:
                log.warning("bot worker disabled: REPORT_BOT_TOKEN is empty")

        if self.settings.enable_worker:
            if self.delivery_bot.has_token and self.settings.delivery_chat_id:
                self.tasks.append(
                    asyncio.create_task(delivery_worker.run(self), name="delivery-worker")
                )
            else:
                log.warning(
                    "delivery worker disabled: token/chat are not configured",
                    extra={"has_token": self.delivery_bot.has_token},
                )

        if self.settings.enable_maintenance:
            self.tasks.append(asyncio.create_task(maintenance.run(self), name="maintenance"))

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
