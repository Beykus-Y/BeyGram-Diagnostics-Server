# BeyGram Report Server

Сервер приёма диагностических отчётов для BeyGram (закрытая бета).

Одна кнопка в приложении → отчёт попадает разработчику в Telegram. Без поиска
контакта, ручного ввода кода и постоянной телеметрии: отправка — только по
явному действию пользователя.

## Как это работает

```
BeyGram (TDLib)                Report Server                 Разработчик
────────────────               ─────────────                 ───────────
1. Пользователь пишет
   описание проблемы,
   видит состав данных
2. SecureRandom nonce
   (256 бит, Base64URL)
   + report_id (UUIDv4)
3. /report <nonce> ──────────► 4. Bot API: from.id ∈
   служебному боту                allowlist? лимиты?
                                  HMAC(nonce) → ISSUED, TTL 5–10 мин
5. ◄─── «Запрос подтверждён»
   + correlation_id
6. POST /api/v1/bug-reports ──► 7. Проверки: nonce жив,
   Authorization: Bearer          allowlist, лимиты,
   <nonce>                        схема, 256 КБ
                                  атомарный claim → очередь
                                  ◄── 202 + status_token
                               8. Воркер ────────────────────► отчёт в чат
                                  DELIVERED, nonce погашен     разработчику
9. Пользователь видит
   номер и статус отчёта
```

Ключевые свойства схемы:

* **Сервер доверяет только `message.from.id` от Bot API** — `telegram_user_id`
  из HTTP-тела не существует в схеме и будет отвергнут (`extra="forbid"`).
* **Сырой nonce не хранится** — только HMAC-SHA256 c серверным `NONCE_PEPPER`.
  Утечка БД не раскрывает действующие токены.
* **Никаких секретов в APK** — общий секрет не зашит; nonce генерируется на
  клиенте при каждом отчёте, бот-токен живёт только на сервере.
* **Атомарность** — выдача, claim и погашение nonce идут под `BEGIN IMMEDIATE`
  (SQLite WAL): повторное использование токена и дубли отчётов исключены.
* **Идемпотентность** — повтор того же `report_id` не создаёт дубль и не
  требует нового nonce (сетевой сбой → идемпотентный ретрай). TTL действует
  только на непривязанные ISSUED-токены; привязанный nonce остаётся пригодным
  для идемпотентного повтора, пока жив отчёт.
* **Fencing доставки** — claim несёт `claim_version`; все записи состояния
  (прогресс, DELIVERED, ретрай) принимаются только с актуальной версией, и
  отозванный (DROPPED) отчёт не может быть доставлен «выжившим» воркером.
* **Доставка at-least-once** — `sendMessage` Bot API не идемпотентен: при
  потере ответа или падении между отправкой и фиксацией часть может уйти
  дважды. Прогресс (число отправленных частей) сохраняется после каждого
  подтверждённого сообщения, ретрай продолжает со следующей части; каждая
  часть помечена `часть i/n · report_id` для дедупликации на стороне
  разработчика. Exactly-once через Bot API не гарантируется.
* **Анонимный злоумышленник**, знающий URL и чужой Telegram ID, ничего не
  может: подтверждение владения аккаунтом идёт через бота.

Это схема подтверждения владения аккаунтом, а не attestation приложения:
авторизованный Telegram-пользователь может написать боту из любого клиента.
Поэтому лимиты и валидация обязательны и настроены консервативно.

## Структура

| Путь | Назначение |
| --- | --- |
| `app/main.py` | Сборка FastAPI, middleware, lifespan |
| `app/config.py` | Все настройки из окружения / `.env` |
| `app/security.py` | Генерация/валидация nonce, HMAC-хэширование |
| `app/routers/bug_reports.py` | `POST /api/v1/bug-reports`, `GET` статуса |
| `app/services/bot_worker.py` | Long polling, `/report <nonce>` → ISSUED |
| `app/services/intake.py` | Проверки и атомарный приём отчёта |
| `app/services/delivery_worker.py` | Очередь → чат разработчика, ретраи |
| `app/services/maintenance.py` | Очистка просроченного, retention, WAL-checkpoint |
| `app/services/redaction.py` → `app/redaction.py` | Вторая линия защиты: вычищает секреты из текста |
| `app/repository/` | SQLite: nonces, reports, allowlist, rate_limit, audit, kv |
| `app/cli.py` | Админ-CLI (allowlist, kill switch, аудит, диагностика) |
| `devtools/fake_telegram.py` | Фейковый Bot API для локальной отладки |
| `tests/` | 81 тест: API, бот, воркер, безопасность, редакция |

## Быстрый старт (разработка)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env   # значения по умолчанию подходят для dev
```

Полный поток без реального Telegram — через фейковый Bot API:

```powershell
# 1. Фейковый Bot API
.venv\Scripts\uvicorn devtools.fake_telegram:app --port 8081

# 2. Сервер, указывающий на него (.env: TELEGRAM_API_BASE=http://127.0.0.1:8081,
#    DATABASE_PATH=data/dev_reports.db, REQUIRE_HTTPS=false)
.venv\Scripts\uvicorn app.main:app --port 8080
```

Сымитировать «пользователь написал боту»:

```powershell
# id 111 должен быть в BOOTSTRAP_ALLOWLIST
Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8081/_test/push `
  -ContentType application/json -Body '{"from_id": 111, "text": "/report AbCd1234"}'
# ответ бота: http://127.0.0.1:8081/_test/sent
```

Тесты и линтер:

```powershell
.venv\Scripts\python -m pytest tests
.venv\Scripts\python -m ruff check app tests
```

## Продакшен

### 1. Создать ботов у @BotFather

* **Report-бот** — его пишет пользователь из BeyGram. Команды не обязательны:
  сервер сам отвечает на `/start`, `/help` и `/report <nonce>`.
* **Delivery-бот** (необязательно — иначе используется report-бот) — добавляется
  в приватный чат/группу разработчика; `DELIVERY_CHAT_ID` — id этого чата.
  Узнать его можно, переслав сообщение из чата в `getUpdates`, или через
  `@userinfobot` для личного чата.

### 2. Заполнить `.env`

```powershell
.venv\Scripts\python -m app.cli gen-secrets   # NONCE_PEPPER и шаблон
```

Минимум для `APP_ENV=production`:

| Переменная | Значение |
| --- | --- |
| `NONCE_PEPPER` | 32+ случайных символа (утечка БД без него бесполезна) |
| `REPORT_BOT_TOKEN` | токен report-бота от @BotFather |
| `DELIVERY_CHAT_ID` | чат разработчика для готовых отчётов |
| `BOOTSTRAP_ALLOWLIST` | Telegram ID тестировщиков через запятую |
| `DATABASE_PATH` | путь к SQLite (в Docker — `/data/beygram_reports.db`) |

Остальные значения — см. `.env.example`, все лимиты конфигурируемы.

### 3. Запустить

```bash
docker compose up -d --build
docker compose run --rm report-server python -m app.cli doctor
```

Сервер слушает `127.0.0.1:8080`; **TLS терминирует reverse proxy** (Caddy,
nginx, Traefik) — `REQUIRE_HTTPS=true` проверяет `X-Forwarded-Proto` от
доверенного прокси (`TRUST_PROXY_HOPS`, `TRUSTED_PROXY_NETWORKS`).

> Проксировать нужно и вебсокеты/long polling не требуется: бот сам ходит
> наружу к Bot API, входящих вебхуков нет.

### 4. Проверить

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
```

## API

### POST /api/v1/bug-reports

`Authorization: Bearer <nonce>` (подтверждён ботом, не истёк, TTL 5–10 мин).
Тело — строгая схема, лимит 256 КБ:

```json
{
  "schema_version": 1,
  "report_id": "UUIDv4",
  "description": "≤ 2000 символов",
  "summary": "≤ 8000 символов, опционально",
  "client_meta": { "app_version": "...", "device_model": "...", "...": "только фиксированные поля" },
  "events": [ { "kind": "network", "severity": "error", "code": "...", "message": "≤500", "attrs": {"k": "≤200"} } ]
}
```

Ответ `202`:

```json
{
  "report_id": "...",
  "status": "queued",
  "status_token": "подписанный токен для GET статуса",
  "idempotent_replay": false,
  "redactions": {"ip_like": 3}
}
```

Ошибки: `401` (нет/плохой токен), `403` (allowlist/лимит/выключатель), `409`
(конфликт claim), `413` (размер), `422` (схема). Неавторизованные ответы не
раскрывают, есть ли пользователь в allowlist.

### GET /api/v1/bug-reports/{report_id}

`Authorization: Bearer <status_token>` из ответа приёма → состояние
`queued | delivered | failed`.

## Лимиты (стартовые, конфигурируемые)

| Ограничение | Значение |
| --- | --- |
| Отчёты на пользователя | ≤ 5/сутки и ≤ 2 за 10 минут |
| Запросы `/report` на пользователя | ≤ 10/час |
| Отчёты глобально / на IP | ≤ 500/сутки / ≤ 20/час |
| Тело запроса | ≤ 256 КБ |
| Событий в отчёте | ≤ 2000 |
| Описание | ≤ 2000 символов |

Лимиты применяются **до** регистрации nonce — спам через `/report` бесполезен.

## Эксплуатация (CLI)

```bash
python -m app.cli allowlist add 123456789 --label "beta tester"
python -m app.cli allowlist remove 123456789 --reason "left beta"   # + погашение nonce, снятие отчётов
python -m app.cli allowlist list
python -m app.cli intake off --note "maintenance"                   # общий выключатель приёма
python -m app.cli intake status
python -m app.cli status                                            # очередь, nonce, целостность БД
python -m app.cli audit --limit 50                                  # журнал действий
python -m app.cli doctor                                            # проверка конфигурации
```

Отзыв из allowlist действует сразу: бот больше не подтверждает токены,
а постановленные в очередь отчёты пользователя снимаются с доставки
(клиент увидит терминальный статус `cancelled`, а не «в очереди»).

## Админ-веб-панель

Небольшая встроенная панель на `/admin` для повседневных задач без SSH:
обзор очереди и здоровья воркеров, поиск и просмотр отчётов (уже
отредактированных), безопасный ручной retry только из FAILED, экспорт отчёта
в JSON, добавление/отзыв тестировщиков, выключатель приёма, журнал аудита.

Включается заданием `ADMIN_TOKEN` (пусто → панель полностью выключена, 404).
Безопасность: сессия — подписанная HttpOnly/SameSite=Strict/Secure-cookie,
CSRF обязателен для всех write-действий, rate limit на попытки входа,
ответы без кеширования, анти-XSS экранирование вывода, каждое действие
попадает в аудит. Сырые nonce, бот-токены и pepper не отображаются никогда.

> **Не открывайте панель в публичный интернет напрямую** — используйте
> приватную сеть или identity-aware reverse proxy; панель не заменяет их.

## Наблюдаемость

* `/healthz` — дешёвый liveness (без внешних вызовов).
* `/readyz` — readiness: целостность БД, состояние фоновых воркеров (жив,
  последний успешный цикл, сбои подряд, число рестартов), глубина и возраст
  старейшего недоставленного отчёта. Деградация видна полем `problems`.
* Воркеры под supervisor: неожиданное падение фиксируется в реестре, задача
  перезапускается с растущей паузой — «тихая смерть» фонового кода не остаётся
  незамеченной.
* CI (GitHub Actions): ruff + pytest на каждый push/PR, проверка Docker-сборки
  и smoke-запуск контейнера; Dependabot обновляет зависимости.

## Хранение данных

* Retention отчётов — 30 дней (`RETENTION_DAYS`), аудита — 60 (`AUDIT_RETENTION_DAYS`);
  `maintenance` чистит просроченное раз в 15 минут.
* В БД нет сырых nonce и нет текста сообщений пользователя Telegram — только
  диагностика, явно собранная приложением.
* `Authorization` никогда не попадает в логи; в логах — классы исключений и id.

## Замечания по безопасности

* HTTPS обязателен (`REQUIRE_HTTPS=true`); граница доверия одна — приложение.
  Uvicorn запускается **без** `--proxy-headers`: он не переписывает адрес
  клиента по чужим `X-Forwarded-*`. Заголовки принимаются только от
  доверенных прокси (`TRUST_PROXY_HOPS`, `TRUSTED_PROXY_NETWORKS`), определяемых
  по непосредственному сокет-пиру — иначе IP-лимит обходится подделкой.
* Редакция (`app/redaction.py`) — вторая линия: вычищает IP (включая IPv6),
  хосты, токены, ссылки подписок из **всех** строковых полей отчёта —
  description, summary, message, code, имена атрибутов и client_meta;
  первичная защита — клиент не кладёт их в события вообще.
* Status-токен принимается только в заголовке `Authorization` — query string
  попадает в логи прокси и историю браузера.
* Сервер не переходит по ссылкам из отчётов и не принимает произвольные архивы.
* При компрометации `NONCE_PEPPER` все выданные токены не аннулируются
  автоматически (они и так живут ≤ 10 минут), но ротация требует перезапуска.
