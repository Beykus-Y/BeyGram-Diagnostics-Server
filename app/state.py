"""Состояния конечных автоматов nonce и отчёта.

Явные строковые константы (а не Enum) — чтобы значения попадали в SQLite
и в API-ответы без дополнительных преобразований.
"""

from __future__ import annotations

# --- Состояния nonce --------------------------------------------------------
# ISSUED      — бот подтвердил владение аккаунтом, токен ждёт загрузки отчёта
# PROCESSING  — nonce принят API, привязан к report_id (claim выполнен)
# ACCEPTED    — отчёт принят и поставлен в очередь на доставку
# DELIVERED   — отчёт доставлен разработчику; nonce окончательно погашен
# EXPIRED     — истёк TTL (подтверждение получено, но отчёт не загружен)
# REVOKED     — отозван (пользователь удалён из allowlist / выключатель приёма)

NONCE_ISSUED = "ISSUED"
NONCE_PROCESSING = "PROCESSING"
NONCE_ACCEPTED = "ACCEPTED"
NONCE_DELIVERED = "DELIVERED"
NONCE_EXPIRED = "EXPIRED"
NONCE_REVOKED = "REVOKED"

NONCE_TERMINAL_STATES = frozenset({NONCE_EXPIRED, NONCE_REVOKED})
# Состояния, при которых nonce уже связан с конкретным отчётом.
NONCE_BOUND_STATES = frozenset({NONCE_PROCESSING, NONCE_ACCEPTED, NONCE_DELIVERED})
NONCE_LIVE_STATES = frozenset({NONCE_ISSUED, NONCE_PROCESSING, NONCE_ACCEPTED})

# --- Состояния отчёта (очередь доставки) ------------------------------------
REPORT_QUEUED = "QUEUED"
REPORT_PROCESSING = "PROCESSING"
REPORT_DELIVERED = "DELIVERED"
REPORT_FAILED = "FAILED"  # исчерпаны попытки либо невосстановимая ошибка
REPORT_DROPPED = "DROPPED"  # снят с доставки (выключатель приёма/отзыв доступа)

REPORT_TERMINAL_STATES = frozenset({REPORT_DELIVERED, REPORT_FAILED, REPORT_DROPPED})
REPORT_CLAIMABLE_STATES = frozenset({REPORT_QUEUED})


def report_state_for_nonce(nonce_state: str) -> str:
    """Отображает состояние nonce в состояние отчёта для ответа клиенту."""
    return {
        NONCE_PROCESSING: REPORT_QUEUED,
        NONCE_ACCEPTED: REPORT_QUEUED,
        NONCE_DELIVERED: REPORT_DELIVERED,
    }.get(nonce_state, REPORT_QUEUED)


# --- Коды клиентских состояний (используются в API-ответах и в UI) ----------
CLIENT_STATUS_QUEUED = "queued"
CLIENT_STATUS_DELIVERED = "delivered"
CLIENT_STATUS_FAILED = "failed"
CLIENT_STATUS_CANCELLED = "cancelled"  # снят с доставки (отзыв доступа/kill switch)
