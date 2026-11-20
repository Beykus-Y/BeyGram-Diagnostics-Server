/*
 * BG Push: криптография и разбор сообщений на устройстве.
 * Классический скрипт без модулей: подключается страницами и service worker (importScripts).
 * Внутренний слой расшифровывается только здесь, через Web Crypto: RFC 8188/8291 (aes128gcm) и конверт
 * aesgcm, который собирает сервер (см. decryptIngress).
 */
(function (root) {
  'use strict';

  var MAX_TEXT = 300;
  var OPEN_LINK = 'beygram://push/open';
  var ID_RE = /^-?\d{1,20}$/;
  var DEEP_LINK_RE = /^beygram:\/\/push\/open(\?(account|peer|msg)=-?\d{1,20}(&(account|peer|msg)=-?\d{1,20}){0,2})?$/;
  var textEncoder = new TextEncoder();
  var textDecoder = new TextDecoder('utf-8', { fatal: true });

  function b64urlEncode(input) {
    var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    var text = '';
    for (var i = 0; i < bytes.length; i++) {
      text += String.fromCharCode(bytes[i]);
    }
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
      throw new Error('bad base64url');
    }
    var pad = '==='.slice((text.length + 3) % 4);
    var binary = atob(text.replace(/-/g, '+').replace(/_/g, '/') + pad);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  function randomBytes(length) {
    var out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
  }

  function concat(parts) {
    var total = 0;
    for (var i = 0; i < parts.length; i++) {
      total += parts[i].length;
    }
    var out = new Uint8Array(total);
    var offset = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], offset);
      offset += parts[j].length;
    }
    return out;
  }

  async function hkdf(ikm, salt, info, length) {
    var key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: info }, key, length * 8);
    return new Uint8Array(bits);
  }

  // Расшифровка одной записи RFC 8188 (aes128gcm) для получателя с приватным ключом privateKey.
  async function decryptAes128gcm(body, privateKey, receiverPublicRaw, authSecret) {
    var record = new Uint8Array(body);
    if (record.length < 86) {
      throw new Error('short record');
    }
    var salt = record.slice(0, 16);
    var recordSize = new DataView(record.buffer, record.byteOffset + 16, 4).getUint32(0);
    if (record[20] !== 65) {
      throw new Error('unexpected key id length');
    }
    var senderPublic = record.slice(21, 86);
    var ciphertext = record.slice(86);
    if (recordSize < 18 || ciphertext.length > recordSize) {
      throw new Error('record size mismatch');
    }
    var senderKey = await crypto.subtle.importKey(
      'raw', senderPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    var shared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'ECDH', public: senderKey }, privateKey, 256)
    );
    var keyInfo = concat([textEncoder.encode('WebPush: info\u0000'), receiverPublicRaw, senderPublic]);
    var ikm = await hkdf(shared, authSecret, keyInfo, 32);
    var cek = await hkdf(ikm, salt, textEncoder.encode('Content-Encoding: aes128gcm\u0000'), 16);
    var nonce = await hkdf(ikm, salt, textEncoder.encode('Content-Encoding: nonce\u0000'), 12);
    var aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
    var padded = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext)
    );
    var end = padded.length - 1;
    while (end >= 0 && padded[end] === 0) {
      end--;
    }
    if (end < 0 || padded[end] !== 2) {
      throw new Error('invalid record padding');
    }
    return padded.slice(0, end);
  }

  // Конверт aesgcm от сервера: "BGA1" (4) || salt (16) || dh отправителя (65) || rs (4) || шифротекст.
  // Telegram шлёт aesgcm, где соль и ключ стоят в заголовках; сервер не расшифровывает запись и переносит их сюда.
  var AESGCM_MAGIC = [0x42, 0x47, 0x41, 0x31];
  var AESGCM_HEADER_LENGTH = 89;

  function lengthPrefixed(key) {
    return concat([new Uint8Array([0, key.length]), key]);
  }

  // draft-ietf-webpush-encryption-04 (aesgcm), одна запись. Совпадает с эталонной http_ece (tests/js).
  async function decryptAesgcmEnvelope(record, privateKey, receiverPublicRaw, authSecret) {
    var salt = record.slice(4, 20);
    var senderPublic = record.slice(20, 85);
    var ciphertext = record.slice(AESGCM_HEADER_LENGTH);
    var senderKey = await crypto.subtle.importKey(
      'raw', senderPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    var shared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'ECDH', public: senderKey }, privateKey, 256)
    );
    var ikm = await hkdf(shared, authSecret, textEncoder.encode('Content-Encoding: auth\u0000'), 32);
    var context = concat([
      textEncoder.encode('P-256\u0000'), lengthPrefixed(receiverPublicRaw), lengthPrefixed(senderPublic)
    ]);
    var cek = await hkdf(ikm, salt, concat([textEncoder.encode('Content-Encoding: aesgcm\u0000'), context]), 16);
    var nonce = await hkdf(ikm, salt, concat([textEncoder.encode('Content-Encoding: nonce\u0000'), context]), 12);
    var aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
    var padded = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext)
    );
    if (padded.length < 2) {
      throw new Error('invalid aesgcm padding');
    }
    var padLength = (padded[0] << 8) | padded[1];
    if (padded.length < 2 + padLength) {
      throw new Error('invalid aesgcm padding');
    }
    return padded.slice(2 + padLength);
  }

  // Вход service worker: конверт aesgcm от сервера или обычная запись aes128gcm (тестовое сообщение сервера).
  async function decryptIngress(body, privateKey, receiverPublicRaw, authSecret) {
    var record = new Uint8Array(body);
    var startsWithMagic = AESGCM_MAGIC.every(function (b, i) {
      return record[i] === b;
    });
    if (startsWithMagic && record.length >= AESGCM_HEADER_LENGTH + 18) {
      try {
        return await decryptAesgcmEnvelope(record, privateKey, receiverPublicRaw, authSecret);
      } catch (error) {
        // Соль aes128gcm могла случайно совпасть с магией (1 шанс из 2^32): тогда пробуем обычный формат.
      }
    }
    return decryptAes128gcm(body, privateKey, receiverPublicRaw, authSecret);
  }

  // Ключи приёма (ingress): приватный ключ остаётся на устройстве, сервер получает только публичную часть.
  async function generateReceiverKeys() {
    var pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    var publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    return { privateKey: pair.privateKey, publicRaw: publicRaw };
  }

  // Ссылка строится только из проверенных идентификаторов; URL из payload не исполняется.
  function buildLink(data) {
    var params = [];
    ['account', 'peer', 'msg'].forEach(function (name) {
      var value = data[name];
      if (typeof value === 'number' && Number.isSafeInteger(value)) {
        value = String(value);
      }
      if (typeof value === 'string' && ID_RE.test(value)) {
        params.push(name + '=' + value);
      }
    });
    return params.length ? OPEN_LINK + '?' + params.join('&') : OPEN_LINK;
  }

  // Wire v2 never reuses the legacy packed "peer" field.
  function messageId(value) {
    var id = positiveId(value);
    return id && (id.length < 10 || (id.length === 10 && id <= '2147483647')) ? id : '';
  }

  function buildNavigationLink(context) {
    var account = positiveId(context.account);
    var peer = positiveId(context.peerId);
    var kind = context.peerType;
    if (!account || !peer || ['user', 'chat', 'channel'].indexOf(kind) === -1) return OPEN_LINK;
    var msg = '';
    if (context.messageId !== undefined) {
      msg = messageId(context.messageId);
      if (!msg) return OPEN_LINK;
    }
    return OPEN_LINK + '?v=2&account=' + account + '&kind=' + kind + '&rawPeer=' + peer +
      (msg ? '&msg=' + msg : '');
  }

  function parseNavigationLink(value) {
    if (typeof value !== 'string' || value.length > 200 || /[^!-~]/.test(value)) return null;
    if (value.indexOf(OPEN_LINK + '?') !== 0) return null;
    var fields = Object.create(null);
    var parts = value.slice(OPEN_LINK.length + 1).split('&');
    for (var i = 0; i < parts.length; i++) {
      var pair = /^([A-Za-z]+)=([A-Za-z0-9]+)$/.exec(parts[i]);
      if (!pair || ['v', 'account', 'kind', 'rawPeer', 'msg'].indexOf(pair[1]) === -1 ||
          Object.prototype.hasOwnProperty.call(fields, pair[1])) return null;
      fields[pair[1]] = pair[2];
    }
    if (fields.v !== '2' || !positiveId(fields.account) || !positiveId(fields.rawPeer) ||
        ['user', 'chat', 'channel'].indexOf(fields.kind) === -1) return null;
    if (fields.msg !== undefined && !messageId(fields.msg)) return null;
    var result = { account: fields.account, peerType: fields.kind, peerId: fields.rawPeer };
    if (fields.msg !== undefined) result.messageId = fields.msg;
    return result;
  }

  function safeLink(value) {
    var navigation = parseNavigationLink(value);
    if (navigation) return buildNavigationLink(navigation);
    if (typeof value !== 'string' || value.length > 200 || /[^!-~]/.test(value) ||
        !DEEP_LINK_RE.test(value)) return OPEN_LINK;
    // Preserve legacy links, but reject duplicate keys rather than choosing one.
    var query = value.split('?')[1];
    if (query) {
      var keys = query.split('&').map(function (part) { return part.split('=')[0]; });
      if (new Set(keys).size !== keys.length) return OPEN_LINK;
    }
    return value;
  }

  function clip(value, limit) {
    return typeof value === 'string' ? value.slice(0, limit) : '';
  }

  // Telegram documents both the data wrapper and per-event argument schemas.
  // Never interpret arbitrary loc_args as preview text.
  var MEDIA = {
    ALBUM: ['Альбом', 'Album'],
    STORY: ['История', 'Story'],
    TODO: ['Список задач', 'Checklist'],
    AUDIO: ['🎤 Голосовое сообщение', '🎤 Voice message'],
    DOC: ['📎 Файл', '📎 File'],
    PHOTO: ['📷 Фото', '📷 Photo'],
    VIDEO: ['🎥 Видео', '🎥 Video'],
    ROUND: ['Видеосообщение', 'Video message'],
    GIF: ['GIF', 'GIF'],
    STICKER: ['Стикер', 'Sticker'],
    POLL: ['Опрос', 'Poll'],
    QUIZ: ['Викторина', 'Quiz'],
    CONTACT: ['Контакт', 'Contact'],
    GEO: ['Геопозиция', 'Location'],
    GEOLIVE: ['Геопозиция в реальном времени', 'Live location'],
    NOTEXT: ['Новое сообщение', 'New message'],
    PLAYLIST: ['🎵 Музыка', '🎵 Music'],
    DOCS: ['Файлы', 'Files'],
    PHOTOS: ['Фотографии', 'Photos'],
    VIDEOS: ['Видео', 'Videos'],
    FWDS: ['Пересланные сообщения', 'Forwarded messages']
  };
  var CONTROL = ['DC_UPDATE', 'MESSAGE_DELETED', 'READ_REACTION', 'READ_HISTORY',
    'READ_STORIES', 'STORY_DELETED', 'GEO_LIVE_PENDING', 'SESSION_REVOKE', 'MESSAGE_MUTED'];

  function langIndex(language) {
    return /^en(?:-|$)/i.test(language || '') ? 1 : 0;
  }

  function fallback(language, control) {
    var l = langIndex(language);
    return { k: control ? 'control' : 'unknown', t: 'BeyGram',
      b: control ? ['Откройте приложение для обновления', 'Open the app to refresh'][l] :
        ['Новое уведомление', 'New notification'][l], link: OPEN_LINK, tag: '' };
  }

  // Protect large integer and noncanonical numeric tokens before JSON.parse; quoted strings are untouched.
  // Decimal/exponent spellings cannot be silently rounded into valid routing IDs.
  // The parser only treats canonical positive decimal IDs as identifiers.
  function parseJsonLossless(text) {
    return JSON.parse(text.replace(/"(?:[^"\\]|\\[\s\S])*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g,
      function (token) {
        return token[0] !== '"' && (!/^-?\d+$/.test(token) || !Number.isSafeInteger(Number(token))) ?
          '"' + token + '"' : token;
      }));
  }

  function positiveId(value) {
    if (typeof value === 'number' && Number.isSafeInteger(value)) value = String(value);
    return typeof value === 'string' && /^[1-9]\d{0,18}$/.test(value) && !/[^0-9]/.test(value) &&
      (value.length < 19 || value <= '9223372036854775807') ? value : '';
  }

  function clean(value, length) {
    if (typeof value !== 'string') return '';
    return Array.from(value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ').trim())
      .slice(0, length).join('');
  }

  var COUNTS = {
    PHOTOS: [['фотография', 'фотографии', 'фотографий'], ['photo', 'photos']],
    VIDEOS: [['видео', 'видео', 'видео'], ['video', 'videos']],
    DOCS: [['файл', 'файла', 'файлов'], ['file', 'files']],
    PLAYLIST: [['аудиофайл', 'аудиофайла', 'аудиофайлов'], ['audio file', 'audio files']],
    FWDS: [['пересланное сообщение', 'пересланных сообщения', 'пересланных сообщений'], ['forwarded message', 'forwarded messages']]
  };
  function mediaBody(kind, arg, l) {
    if (Object.prototype.hasOwnProperty.call(COUNTS, kind)) {
      var count = typeof arg === 'number' ? String(arg) : arg;
      if (typeof count === 'string' && /^[1-9]\d{0,8}$/.test(count)) {
        var n = Number(count);
        var form = l ? (n === 1 ? 0 : 1) :
          (n % 100 >= 11 && n % 100 <= 14 ? 2 : n % 10 === 1 ? 0 : n % 10 >= 2 && n % 10 <= 4 ? 1 : 2);
        return count + ' ' + COUNTS[kind][l][form];
      }
    }
    var base = MEDIA[kind][l];
    if (['STICKER', 'POLL', 'QUIZ', 'TODO'].indexOf(kind) !== -1) {
      var detail = clean(arg, 120);
      if (detail) return base + ': ' + detail;
    }
    return base;
  }
  function telegramContext(data) {
    var c = data.custom && typeof data.custom === 'object' && !Array.isArray(data.custom) ? data.custom : {};
    var account = positiveId(data.user_id);
    var peers = [['channel', positiveId(c.channel_id)], ['chat', positiveId(c.chat_id)], ['user', positiveId(c.from_id)]]
      .filter(function (p) { return p[1]; });
    // A channel or chat has priority over the author, but ambiguous group namespaces are rejected.
    var peer = peers.length && !(positiveId(c.channel_id) && positiveId(c.chat_id)) ? peers[0] : ['', ''];
    return { account: account, peerType: peer[0], peerId: peer[1], messageId: positiveId(c.msg_id),
      silent: c.silent === true || c.silent === 1 || c.silent === '1',
      mention: c.mention === true || c.mention === 1 || c.mention === '1' };
  }

  // Addressing is distinct from the old display/dedup context: a group actor is
  // not the dialog. Only documented cloud message/reaction events may navigate.
  function telegramNavigation(data, match, reaction, kind) {
    if ((!match && !reaction) || kind === 'STORY') return OPEN_LINK;
    var custom = data.custom;
    if (!custom || typeof custom !== 'object' || Array.isArray(custom) ||
        Object.prototype.hasOwnProperty.call(custom, 'encryption_id')) return OPEN_LINK;
    var prefix = reaction ? (reaction[1] ? 'CHAT' : '') : (match[1] || '');
    var has = function (field) { return Object.prototype.hasOwnProperty.call(custom, field); };
    // CHAT covers basic groups and supergroups; CHANNEL requires channel_id.
    // Reject contradictory dialog fields, including malformed values; author fields
    // chat_from_id/chat_from_group_id/chat_from_broadcast_id are not dialog IDs.
    var targets = ['from_id', 'chat_id', 'channel_id'].filter(has);
    if (targets.length !== 1) return OPEN_LINK;
    var field = targets[0];
    if ((prefix === 'CHAT' && field === 'from_id') ||
        (prefix === 'CHANNEL' && field !== 'channel_id') ||
        (!prefix && field !== 'from_id')) return OPEN_LINK;
    var context = { account: data.user_id,
      peerType: field === 'from_id' ? 'user' : field === 'chat_id' ? 'chat' : 'channel',
      peerId: custom[field] };
    // Aggregated notifications have no single guaranteed message target.
    var aggregate = ['ALBUM', 'PHOTOS', 'VIDEOS', 'DOCS', 'PLAYLIST', 'FWDS'].indexOf(kind) !== -1;
    if (!aggregate && has('msg_id')) context.messageId = custom.msg_id;
    return buildNavigationLink(context);
  }

  function parseTelegram(data, language) {
    var key = data.loc_key;
    if (typeof key !== 'string' || !/^[A-Z_0-9]{1,80}$/.test(key)) return null;
    if (CONTROL.indexOf(key) !== -1) {
      var control = fallback(language, true);
      var controlContext = telegramContext(data);
      var custom = data.custom || {};
      control.event = key;
      control.context = controlContext;
      if (key === 'READ_HISTORY') control.maxId = positiveId(custom.max_id);
      if (key === 'MESSAGE_DELETED' || key === 'READ_REACTION') {
        control.ids = typeof custom.messages === 'string' && custom.messages.length <= 4096 ?
          custom.messages.split(',').map(positiveId).filter(Boolean) : [];
      }
      return control;
    }
    if (key === 'ENCRYPTED_MESSAGE' || key === 'STORY_HIDDEN_AUTHOR') return fallback(language, false);
    if (key === 'MESSAGE_ANNOUNCEMENT') {
      var announcement = clean(data.message, MAX_TEXT);
      return announcement ? { k: 'service', t: 'Telegram', b: announcement, link: OPEN_LINK, tag: '' } : fallback(language, false);
    }
    if (/^(CHAT_|CHANNEL_)?MESSAGES$/.test(key)) key = key.replace(/MESSAGES$/, 'MESSAGE_ALBUM');
    var m = /^(?:(CHAT|CHANNEL)_)?MESSAGE_([A-Z_]+)$/.exec(key);
    var missed = key === 'PHONE_CALL_MISSED' || key === 'CONF_CALL_MISSED';
    var reaction = /^(CHAT_)?REACT_(TEXT|AUDIO|DOC|PHOTO|VIDEO|ROUND|STICKER|POLL|QUIZ|TODO)$/.exec(key);
    if (data.custom && (data.custom.schedule === true || data.custom.schedule === 1 || data.custom.schedule === '1')) return fallback(language, true);
    if (!missed && !reaction && (!m || (m[2] !== 'TEXT' && !Object.prototype.hasOwnProperty.call(MEDIA, m[2])))) return null;
    var kind = missed ? 'MISSED_CALL' : reaction ? 'REACTION' : m[2];
    var group = !missed && (reaction ? !!reaction[1] : m[1] === 'CHAT');
    var args = Array.isArray(data.loc_args) ? data.loc_args : [];
    // CHAT_MESSAGE_STORY has only a group-name argument, unlike other CHAT_MESSAGE events.
    // Never invent an author or treat additional arguments as a title.
    var groupStory = key === 'CHAT_MESSAGE_STORY';
    var sender = groupStory ? '' : clean(args[0], 100);
    var title = groupStory ? clean(args[0], 100) : group ? clean(args[1], 100) : sender;
    if (!title || (group && !groupStory && !sender)) return fallback(language, false);
    var l = langIndex(language);
    var body;
    if (missed) body = ['Пропущенный звонок', 'Missed call'][l];
    else if (reaction) {
      var emoji = clean(args[group ? 2 : 1], 30);
      body = ['Реакция на сообщение', 'Reaction to a message'][l] + (emoji ? ' ' + emoji : '');
    } else if (kind === 'TEXT') body = clean(args[group ? 2 : 1], MAX_TEXT);
    else body = mediaBody(kind, args[group ? 2 : 1], l);
    if (!body) body = ['Новое сообщение', 'New message'][l];
    var ctx = telegramContext(data);
    var navigation = missed ? OPEN_LINK : telegramNavigation(data, m, reaction, kind);
    var tag = !missed && !reaction && ['ALBUM', 'PHOTOS', 'VIDEOS', 'DOCS', 'PLAYLIST', 'FWDS'].indexOf(kind) === -1 && ctx.account && ctx.peerType && ctx.peerId && ctx.messageId ?
      ['tg', ctx.account, ctx.peerType, ctx.peerId, ctx.messageId].join(':') : '';
    // Reactions may have multiple actors; no tag-based collapse without a verified event ID.
    return { k: missed ? 'call' : reaction ? 'reaction' : 'msg', t: title, b: clean(group && !groupStory ? sender + ': ' + body : body, MAX_TEXT),
      link: navigation, tag: tag, context: ctx, silent: ctx.silent, event: key };
  }

  function parseDetailed(bytes, language) {
    var data;
    try {
      data = parseJsonLossless(textDecoder.decode(bytes));
    } catch (error) {
      return { code: 'invalid-json-or-utf8', message: null };
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { code: 'invalid-format', message: null };
    if (data.v === 1 && (data.k === 'test' || data.k === 'msg')) {
      return { code: 'bg-v1', message: {
        k: data.k, id: clip(data.id, 64), t: clip(data.t, 100) || 'BeyGram',
        b: clip(data.b, MAX_TEXT) || fallback(language).b, link: data.k === 'test' ? OPEN_LINK : buildLink(data), tag: clip(data.tag, 64)
      }};
    }
    var inner = data.data && typeof data.data === 'object' && !Array.isArray(data.data) ? data.data : data;
    var message = parseTelegram(inner, language);
    return { code: !message ? (typeof inner.loc_key === 'string' ? 'unknown-event' : 'invalid-format') :
      message.k === 'control' ? 'control-event' : message.k === 'unknown' ? 'missing-preview' : 'telegram', message: message };
  }

  function parseMessage(bytes, language) {
    return parseDetailed(bytes, language).message;
  }

  function applyPrivacy(message, mode, language) {
    if (message.k === 'test' || message.k === 'control') return message;
    if (mode === 'full' || mode === undefined) return message;
    if (mode !== 'name') mode = 'none';
    return Object.assign({}, message, {
      t: mode === 'none' || message.k === 'service' ? 'BeyGram' : message.t,
      b: fallback(language).b,
      link: mode === 'none' ? OPEN_LINK : message.link
    });
  }

  // Only notifications tagged by our parser are eligible for read/delete closure.
  function shouldCloseNotification(control, tag) {
    if (!control || control.k !== 'control' || !control.context || typeof tag !== 'string') return false;
    var ctx = control.context;
    if (!ctx.account || !ctx.peerType || !ctx.peerId) return false;
    var prefix = ['tg', ctx.account, ctx.peerType, ctx.peerId, ''].join(':');
    if (tag.indexOf(prefix) !== 0) return false;
    var id = positiveId(tag.slice(prefix.length));
    if (!id) return false;
    if (control.event === 'MESSAGE_DELETED') return Array.isArray(control.ids) && control.ids.indexOf(id) !== -1;
    if (control.event === 'READ_HISTORY' && control.maxId) {
      return id.length < control.maxId.length || (id.length === control.maxId.length && id <= control.maxId);
    }
    return false;
  }

  root.BgCore = {
    b64urlEncode: b64urlEncode,
    b64urlDecode: b64urlDecode,
    randomBytes: randomBytes,
    concat: concat,
    decryptAes128gcm: decryptAes128gcm,
    decryptIngress: decryptIngress,
    generateReceiverKeys: generateReceiverKeys,
    parseMessage: parseMessage,
    parseDetailed: parseDetailed,
    fallback: fallback,
    applyPrivacy: applyPrivacy,
    shouldCloseNotification: shouldCloseNotification,
    safeLink: safeLink,
    buildNavigationLink: buildNavigationLink,
    parseNavigationLink: parseNavigationLink,
    DEEP_LINK_RE: DEEP_LINK_RE
  };
})(typeof self !== 'undefined' ? self : globalThis);
