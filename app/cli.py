"""Административный CLI сервера отчётов.

Примеры:
    python -m app.cli gen-secrets
    python -m app.cli allowlist add 123456789 --label "beta tester"
    python -m app.cli allowlist remove 123456789 --reason "left beta"
    python -m app.cli allowlist list
    python -m app.cli intake off --note "maintenance"
    python -m app.cli status
    python -m app.cli audit --limit 20
    python -m app.cli doctor

CLI работает напрямую с той же БД, что и сервер (через DATABASE_PATH),
поэтому его можно запускать без остановки сервиса.
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import sys

from .config import Settings
from .db import Database
from .logging_setup import setup_logging
from .repository import allowlist, audit, nonces, reports
from .services.settings_service import intake_enabled, set_intake_enabled
from .util import now


def _open(settings: Settings) -> Database:
    db = Database(settings.database_path)
    db.connect()
    return db


def cmd_gen_secrets(_args: argparse.Namespace) -> int:
    """Печатает готовые секреты для .env."""
    print("# Скопируйте строки в .env")
    print(f"NONCE_PEPPER={secrets.token_urlsafe(48)}")
    print("# Токены ботов получите у @BotFather и впишите вручную:")
    print("REPORT_BOT_TOKEN=")
    print("DELIVERY_BOT_TOKEN=")
    print("# Telegram id разработчика/чата для доставки:")
    print("DELIVERY_CHAT_ID=")
    return 0


def cmd_allowlist(args: argparse.Namespace, settings: Settings) -> int:
    db = _open(settings)
    try:
        if args.action == "add":
            with db.transaction() as conn:
                entry = allowlist.add(conn, args.user_id, label=args.label or "")
                audit.write(
                    conn,
                    actor=f"cli:{args.actor}",
                    action="allowlist_add",
                    target=str(args.user_id),
                    detail={"label": args.label or ""},
                )
            print(f"Добавлен в allowlist: {entry.telegram_user_id} (active={entry.active})")

        elif args.action == "remove":
            with db.transaction() as conn:
                changed = allowlist.revoke(
                    conn, args.user_id, reason=args.reason or "revoked via CLI"
                )
                revoked_nonces = nonces.revoke_for_user(conn, args.user_id)
                dropped = reports.drop_pending_for_user(
                    conn, args.user_id, reason="allowlist revoked"
                )
                audit.write(
                    conn,
                    actor=f"cli:{args.actor}",
                    action="allowlist_remove",
                    target=str(args.user_id),
                    detail={
                        "reason": args.reason or "",
                        "was_active": changed,
                        "revoked_nonces": revoked_nonces,
                        "dropped_reports": dropped,
                    },
                )
            if changed:
                print(
                    f"Доступ отозван: {args.user_id}; "
                    f"погашено токенов: {revoked_nonces}; снято отчётов: {dropped}"
                )
            else:
                print(f"Пользователь {args.user_id} не был активен в allowlist.")

        elif args.action == "list":
            with db.transaction() as conn:
                entries = allowlist.list_all(conn, active_only=args.active_only)
            if not entries:
                print("Список пуст.")
            for entry in entries:
                state = "active" if entry.active else "revoked"
                label = f" [{entry.label}]" if entry.label else ""
                print(f"{entry.telegram_user_id}\t{state}{label}")
        return 0
    finally:
        db.close()


def cmd_intake(args: argparse.Namespace, settings: Settings) -> int:
    db = _open(settings)
    try:
        if args.action == "on":
            enabled = True
        elif args.action == "off":
            enabled = False
        else:  # status
            with db.transaction() as conn:
                state = intake_enabled(conn, settings)
            print(f"Приём отчётов: {'включён' if state else 'выключен'}")
            return 0

        with db.transaction() as conn:
            set_intake_enabled(conn, enabled, actor=f"cli:{args.actor}", note=args.note or "")
        print(f"Приём отчётов {'включён' if enabled else 'выключен'}.")
        return 0
    finally:
        db.close()


def cmd_status(_args: argparse.Namespace, settings: Settings) -> int:
    db = _open(settings)
    try:
        with db.transaction() as conn:
            payload = {
                "database": settings.database_path,
                "integrity": db.integrity_check(),
                "intake_enabled": intake_enabled(conn, settings),
                "allowlist": allowlist.count_entries(conn),
                "nonces": nonces.count_by_state(conn),
                "queue": reports.queue_stats(conn),
                "queue_depth": reports.queue_depth(conn),
                "time": now(),
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


def cmd_audit(args: argparse.Namespace, settings: Settings) -> int:
    db = _open(settings)
    try:
        with db.transaction() as conn:
            entries = audit.recent(conn, limit=args.limit)
        for entry in entries:
            detail = f" {json.dumps(entry.detail, ensure_ascii=False)}" if entry.detail else ""
            print(
                f"{entry.at:.0f}\t{entry.actor}\t{entry.action}\t{entry.target or '-'}{detail}"
            )
        return 0
    finally:
        db.close()


def cmd_doctor(_args: argparse.Namespace, settings: Settings) -> int:
    """Проверка конфигурации перед запуском в бой."""
    problems: list[str] = []
    warnings: list[str] = []

    if not settings.nonce_pepper:
        problems.append("NONCE_PEPPER не задан")
    elif len(settings.nonce_pepper) < 32:
        problems.append("NONCE_PEPPER короче 32 символов")
    if not settings.report_bot_token:
        problems.append("REPORT_BOT_TOKEN не задан")
    if not settings.delivery_chat_id:
        problems.append("DELIVERY_CHAT_ID не задан")
    if settings.is_production and settings.telegram_api_base.startswith("http://"):
        problems.append("TELEGRAM_API_BASE использует http в production")
    if not settings.require_https and settings.is_production:
        warnings.append("REQUIRE_HTTPS выключен в production")
    if not settings.bootstrap_allowlist_ids:
        warnings.append("BOOTSTRAP_ALLOWLIST пуст — тестировщиков нужно добавлять вручную")
    if settings.retention_days < 1:
        problems.append("RETENTION_DAYS должен быть >= 1")

    print(f"app_env: {settings.app_env}")
    print(f"database: {settings.database_path}")
    print(f"telegram_api_base: {settings.telegram_api_base}")
    print(f"nonce_ttl_seconds: {settings.nonce_ttl_seconds}")
    print(f"max_body_bytes: {settings.max_body_bytes}")
    print(f"trust_proxy_hops: {settings.trust_proxy_hops}")

    if warnings:
        print("\nПредупреждения:")
        for item in warnings:
            print(f"  - {item}")
    if problems:
        print("\nПроблемы:")
        for item in problems:
            print(f"  - {item}")
        return 1

    print("\nКонфигурация в порядке.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="beygram-report-server",
        description="Администрирование сервера отчётов BeyGram",
    )
    parser.add_argument("--actor", default="admin", help="Кто выполняет действие (для аудита)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("gen-secrets", help="Сгенерировать секреты для .env")
    sub.add_parser("status", help="Показать состояние сервера")
    sub.add_parser("doctor", help="Проверить конфигурацию")

    allow = sub.add_parser("allowlist", help="Управление списком доступа")
    allow.add_argument("action", choices=["add", "remove", "list"])
    allow.add_argument("user_id", nargs="?", type=int, help="Telegram user id")
    allow.add_argument("--label", default="", help="Метка (для add)")
    allow.add_argument("--reason", default="", help="Причина отзыва (для remove)")
    allow.add_argument("--active-only", action="store_true", help="Показывать только активных")

    intake = sub.add_parser("intake", help="Выключатель приёма отчётов")
    intake.add_argument("action", choices=["on", "off", "status"])
    intake.add_argument("--note", default="", help="Комментарий к изменению")

    audit_parser = sub.add_parser("audit", help="Последние записи аудита")
    audit_parser.add_argument("--limit", type=int, default=50)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings()
    setup_logging(settings.log_level, "text")
    logging.getLogger().setLevel(logging.WARNING)

    if args.command == "gen-secrets":
        return cmd_gen_secrets(args)
    if args.command == "allowlist":
        if args.action in {"add", "remove"} and args.user_id is None:
            parser.error("user_id обязателен для add/remove")
        return cmd_allowlist(args, settings)
    if args.command == "intake":
        return cmd_intake(args, settings)
    if args.command == "status":
        return cmd_status(args, settings)
    if args.command == "audit":
        return cmd_audit(args, settings)
    if args.command == "doctor":
        return cmd_doctor(args, settings)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
