"""Фейковый Bot API для локальной отладки всего потока.

Реализует минимум методов, который использует сервер:
* getMe;
* getUpdates / sendMessage (long polling с очередью апдейтов);
* вспомогательный /_test/push — «пользователь пишет боту» для тестов и ручной
  проверки: PUT /_test/push с телом {"from_id": 1, "text": "/report <nonce>"}.

Этот модуль никогда не используется в production и включается только в
docker-compose профилем dev либо запуском вручную.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Fake Telegram Bot API (dev only)")

_state: dict[str, Any] = {
    "next_update_id": 1,
    "updates": [],
    "sent": [],
    "next_message_id": 1000,
    "bots": {},  # token -> username
    "lock": None,
}


def _lock() -> asyncio.Lock:
    if _state["lock"] is None:
        _state["lock"] = asyncio.Lock()
    return _state["lock"]


def _ok(result: Any) -> JSONResponse:
    return JSONResponse({"ok": True, "result": result})


def _fail(code: int, description: str) -> JSONResponse:
    return JSONResponse({"ok": False, "error_code": code, "description": description})


def _token(request: Request) -> str | None:
    # Путь имеет вид /bot<token>/<method>
    path = request.url.path
    if not path.startswith("/bot"):
        return None
    remainder = path[4:]
    return remainder.split("/", 1)[0] or None


@app.post("/bot{token}/{method}")
async def bot_method(token: str, method: str, request: Request) -> JSONResponse:
    token = token.lstrip("/")
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    if method == "getMe":
        return _ok({"id": 1, "is_bot": True, "first_name": "FakeReportBot", "username": "fake_report_bot"})

    if method == "getUpdates":
        offset = body.get("offset")
        timeout = float(body.get("timeout") or 0)
        deadline = asyncio.get_event_loop().time() + min(timeout, 5.0)

        while True:
            async with _lock():
                updates = _state["updates"]
                if offset is not None:
                    updates = [u for u in updates if u["update_id"] >= int(offset)]
                else:
                    updates = list(updates)
                _state["updates"] = [u for u in _state["updates"] if u["update_id"] >= (int(offset) if offset is not None else 0)]
                if updates:
                    return _ok(updates)
            if asyncio.get_event_loop().time() >= deadline:
                return _ok([])
            await asyncio.sleep(0.1)

    if method == "sendMessage":
        chat_id = body.get("chat_id")
        text = body.get("text") or ""
        if chat_id is None:
            return _fail(400, "chat_id is required")
        async with _lock():
            message_id = _state["next_message_id"]
            _state["next_message_id"] += 1
            _state["sent"].append({"chat_id": chat_id, "text": text, "message_id": message_id})
        return _ok(
            {
                "message_id": message_id,
                "date": 0,
                "chat": {"id": chat_id, "type": "private"},
                "text": text,
            }
        )

    return _fail(404, f"method {method} not implemented by fake API")


@app.put("/_test/push")
async def push_update(request: Request) -> JSONResponse:
    """Внедряет апдейт «пользователь написал боту» (только для тестов)."""
    try:
        body = await request.json()
    except ValueError:
        return _fail(400, "invalid json")
    from_id = body.get("from_id")
    text = body.get("text") or ""
    chat_type = body.get("chat_type", "private")
    is_bot = bool(body.get("is_bot", False))
    if from_id is None:
        return _fail(400, "from_id is required")

    async with _lock():
        update_id = _state["next_update_id"]
        _state["next_update_id"] += 1
        message_id = _state["next_message_id"]
        _state["next_message_id"] += 1
        _state["updates"].append(
            {
                "update_id": update_id,
                "message": {
                    "message_id": message_id,
                    "date": 0,
                    "chat": {"id": from_id, "type": chat_type},
                    "from": {"id": from_id, "is_bot": is_bot, "first_name": "Tester"},
                    "text": text,
                },
            }
        )
    return _ok({"update_id": update_id})


@app.get("/_test/sent")
async def sent_messages() -> JSONResponse:
    """Показывает всё, что сервер отправил (для проверки доставки)."""
    async with _lock():
        return _ok(list(_state["sent"]))


@app.post("/_test/reset")
async def reset() -> JSONResponse:
    async with _lock():
        _state["updates"] = []
        _state["sent"] = []
        _state["next_update_id"] = 1
        _state["next_message_id"] = 1000
    return _ok(True)
