"""Репозитории: функции доступа к данным, работающие с соединением SQLite.

Функции принимают открытое соединение (`conn`), чтобы их можно было
компоновать внутри одной транзакции. Асинхронные сервисы вызывают их через
Database.run(), что сериализует доступ к единственному соединению.
"""

from __future__ import annotations

from . import allowlist, audit, kv, nonces, rate_limit, reports

__all__ = ["allowlist", "audit", "kv", "nonces", "rate_limit", "reports"]
