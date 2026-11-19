/*
 * BG Push: криптография и разбор сообщений на устройстве.
 * Классический скрипт без модулей: подключается страницами и service worker (importScripts).
 * Внутренний слой RFC 8188/8291 (aes128gcm) расшифровывается только здесь, через Web Crypto.
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

  // Принимаем только beygram://push/open с необязательными account, peer и msg. Иное заменяется на OPEN_LINK.
  function safeLink(value) {
    if (typeof value === 'string' && value.length <= 200 && DEEP_LINK_RE.test(value)) {
      return value;
    }
    return OPEN_LINK;
  }

  function clip(value, limit) {
    return typeof value === 'string' ? value.slice(0, limit) : '';
  }

  // Формат BG Push v1 (внутренний слой). Непонятный payload не угадываем: вернём null,
  // и service worker покажет общее уведомление.
  function parseMessage(bytes) {
    var data;
    try {
      data = JSON.parse(textDecoder.decode(bytes));
    } catch (error) {
      return null;
    }
    if (!data || data.v !== 1 || (data.k !== 'test' && data.k !== 'msg')) {
      return null;
    }
    return {
      k: data.k,
      id: clip(data.id, 64),
      t: clip(data.t, 100) || 'BeyGram',
      b: clip(data.b, MAX_TEXT) || 'Новое уведомление',
      link: buildLink(data),
      tag: clip(data.tag, 64)
    };
  }

  root.BgCore = {
    b64urlEncode: b64urlEncode,
    b64urlDecode: b64urlDecode,
    randomBytes: randomBytes,
    concat: concat,
    decryptAes128gcm: decryptAes128gcm,
    generateReceiverKeys: generateReceiverKeys,
    parseMessage: parseMessage,
    safeLink: safeLink,
    DEEP_LINK_RE: DEEP_LINK_RE
  };
})(typeof self !== 'undefined' ? self : globalThis);
