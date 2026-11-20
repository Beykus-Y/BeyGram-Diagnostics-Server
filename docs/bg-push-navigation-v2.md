# BG Push Navigation v2

## Общий контракт BG Push Navigation v2 (нормативный для обеих задач)

Версия продукта BG Push 2.1; версия протокола ссылки — 2. Схема регистрации, ключи, relay envelope и API v1 не меняются.

`beygram://push/open?v=2&account=123&kind=user&rawPeer=456&msg=789`

| Поле | Семантика |
|---|---|
| v | Ровно 2; не версия API/IPA |
| account | Обязательный для адресного перехода положительный Telegram user ID получателя (не ID регистрации, не ID отправителя) |
| kind | Обязательный enum: user (cloud user), chat (basic group), channel (channel/supergroup) |
| rawPeer | Обязательный положительный raw Telegram ID в namespace kind; НЕ упакованный iOS PeerId и НЕ Bot API signed ID |
| msg | Необязательный положительный cloud message ID внутри указанного peer, 1..2147483647 |

account/rawPeer: каноническая ASCII десятичная строка 1..9223372036854775807, без знака, пробелов, leading zero, экспоненты и округления JS Number. msg аналогично с Int32 max. Порядок генерации фиксирован как выше; получатель принимает перестановки уникальных ключей. Для v2 строго одна величина каждого обязательного ключа, только указанный allowlist, без fragment/userinfo/port, без percent-encoded alias, дополнительных path, дубликатов или произвольного URL. Длина <= 200 ASCII символов. Любая недействительная, неполная или неизвестная версия — безопасный переход к обычному открытию приложения без целевого чата, без частичного доверия к данным. Если msg отсутствует — открыть чат; если передан некорректный msg — отклонить v2 целиком. Для неизвестного/удалённого корректного msg — открыть доступный чат без прокрутки. Forum topic/thread и secret-chat routing не угадывать: v2 не содержит thread, native разрешает тему по реально найденному сообщению при возможности, иначе обычный чат; явный thread — будущая версия.

**Совместимость:** старый маршрут `beygram://push/open` и существующие legacy-ссылки без v (account/peer/msg) сохраняются; peer в legacy означает прежний упакованный iOS PeerId. НИКОГДА не передавать rawPeer в параметре peer, не смешивать v2 с legacy peer. Старый IPA распознаёт тот же route, но не видит peer и не пытается открыть неверный чат; фактически просто запускает BeyGram/оставляет текущий экран. Новый IPA сначала поддерживает оба формата; старый PWA продолжает открывать приложение как раньше. Новая PWA может быть выложена после native или до него с указанным безопасным fallback, но предпочтительно native-first. Старые уведомления не переписывать. Никакого обязательного re-pair/сброса подписки.

**Приватность:** ссылка формируется после локальной расшифровки и проверки полей, хранится в notification.data локально. Переход SW → same-origin `/push/open#<encodeURIComponent(canonicalLink)>` → валидированный native URL; fragment не отправлять на сервер. Не помещать в backend/query HTTP/аналитику/лог/телеметрию/clipboard plaintext, ключи или chat/account/message IDs. Не исполнять URL из payload. Deep link не авторизация: native проверяет доступ и аккаунт. Режим privacy=none, неизвестные/служебные события и недостоверная адресация — только bare open; privacy=name допускает navigation без текста. Старый generic fallback обязателен.

### Общие contract fixtures (синтетические, одинаковые в JS и Swift)
- user: `beygram://push/open?v=2&account=123&kind=user&rawPeer=456&msg=789`
- basic group: `beygram://push/open?v=2&account=123&kind=chat&rawPeer=42&msg=7`
- channel/supergroup: `beygram://push/open?v=2&account=123&kind=channel&rawPeer=42&msg=7` — другой namespace, не тот же peer.
- chat only: `beygram://push/open?v=2&account=123&kind=channel&rawPeer=42`
- точность: `beygram://push/open?v=2&account=9007199254740993&kind=user&rawPeer=9007199254740995&msg=2147483647` (wire parsing, native domain representability отдельно; не усекать).
- legacy: `beygram://push/open?account=123&peer=456&msg=789`; bare open.
- rejects: unknown v/kind, rawPeer=0/-1/01/9223372036854775808/1e3, msg=2147483648, отсутствующий account/kind/rawPeer, повторный account, v2+peer, unknown param, fragment, credentials, external URL, percent-encoded key/value, malformed query. Invalid v2 не трактовать как legacy.

Единый источник спецификации после реализации: `docs/bg-push-navigation-v2.md` в Diagnostics Server и машиночитаемый JSON fixture рядом (путь согласовать в PR); iOS ссылается на документ и хранит идентичную копию fixture с указанием версии/commit либо импортирует её в тесты без сетевой зависимости сборки. Любое изменение формата — согласование в обоих Issue/PR, несовместимое изменение — новая версия.

Парные задачи: [Diagnostics Server #37](https://github.com/Beykus-Y/BeyGram-Diagnostics-Server/issues/37) и [BeyGram-iOS #74](https://github.com/Beykus-Y/BeyGram-iOS/issues/74).

Машиночитаемые fixtures: [bg-push-navigation-v2.json](bg-push-navigation-v2.json). Поле `expectedLink` — каноническая ссылка либо bare open; `navigation` — null (нет адресной v2-навигации) либо объект wire-полей строками. Legacy не интерпретируется как v2. Native representability проверяется отдельно после wire validation.

PWA routing: CHAT_MESSAGE_* и CHAT_REACT_* допускают chat_id либо channel_id (supergroup); CHANNEL_MESSAGE_* требует channel_id; личные MESSAGE_* и REACT_* требуют from_id. Все три dialog fields взаимно исключаются для адресного перехода. chat_from_* — автор, не адрес. События альбомов/сборных уведомлений открывают чат без msg. Истории, звонки, секретные/служебные/неизвестные события, отсутствующая или конфликтующая адресация — bare open. Семантика msg_id для реакции описана в https://core.telegram.org/api/push-updates. Никаких новых API-запросов; payload остаётся на устройстве.
