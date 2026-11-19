/*
 * BG Push: экран установленного приложения — привязка, статус, тест и отключение.
 * Код привязки вводится вручную и используется один раз; после привязки он не хранится.
 */
(function () {
  'use strict';

  var API = '/api/v1/push';
  var STATE_KEY = 'reg';
  var busy = false;

  var el = {
    support: document.getElementById('support'),
    status: document.getElementById('status'),
    detail: document.getElementById('detail'),
    pair: document.getElementById('pair'),
    code: document.getElementById('code'),
    enable: document.getElementById('enable'),
    actions: document.getElementById('actions'),
    test: document.getElementById('test'),
    refresh: document.getElementById('refresh'),
    disable: document.getElementById('disable'),
    message: document.getElementById('message')
  };

  function say(text, kind) {
    el.message.textContent = text;
    el.message.className = 'message' + (kind ? ' ' + kind : '');
  }

  function isStandalone() {
    return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
      window.navigator.standalone === true;
  }

  function supported() {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }

  function parseCode(text) {
    var match = /^bgp1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec((text || '').trim());
    return match ? { registrationId: match[1], secret: match[2] } : null;
  }

  function authHeaders(token) {
    return { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
  }

  async function api(path, options) {
    var response = await fetch(API + path, Object.assign({ credentials: 'omit', cache: 'no-store' }, options || {}));
    var body = null;
    try {
      body = await response.json();
    } catch (error) {
      body = null;
    }
    if (!response.ok) {
      var failure = new Error((body && body.error && body.error.message) || ('Ошибка ' + response.status));
      failure.status = response.status;
      throw failure;
    }
    return body;
  }

  function showState(remote, note) {
    el.support.hidden = true;
    if (!remote) {
      el.status.textContent = 'Не подключено';
      el.detail.textContent = 'Создайте код в BeyGram: Настройки → Уведомления → Настроить на iPhone.';
      el.pair.hidden = false;
      el.actions.hidden = true;
    } else {
      var labels = {
        pending: 'Ожидает привязки',
        active: remote.telegram_confirmed_at ? 'Уведомления включены' : 'Ждём подтверждения в BeyGram',
        revoked: 'Отключено',
        expired: 'Код истёк'
      };
      el.status.textContent = labels[remote.state] || remote.state;
      var lastOk = remote.last_push_ok_at ? new Date(remote.last_push_ok_at * 1000).toLocaleString('ru-RU') : 'пока нет';
      el.detail.textContent = remote.state === 'active' ? 'Последняя отправка: ' + lastOk + '.' : '';
      el.pair.hidden = remote.state === 'active';
      el.actions.hidden = remote.state !== 'active';
    }
    if (note) {
      say(note, 'bad');
    }
  }

  async function refresh() {
    var state = await BgStore.get(STATE_KEY).catch(function () { return null; });
    if (!state) {
      showState(null);
      return;
    }
    try {
      var remote = await api('/registrations/' + encodeURIComponent(state.registrationId), {
        headers: authHeaders(state.token)
      });
      showState(remote);
    } catch (error) {
      if (error.status === 401) {
        await BgStore.remove(STATE_KEY);
        showState(null, 'Привязка больше не действует. Создайте новый код в BeyGram.');
        return;
      }
      showState(state, 'Не удалось получить статус: ' + error.message);
    }
  }

  async function enable() {
    var parsed = parseCode(el.code.value);
    if (!parsed) {
      say('Вставьте код привязки из BeyGram.', 'bad');
      return;
    }
    if (!supported()) {
      say('Уведомления доступны только из приложения на экране «Домой» (iOS 16.4 и новее).', 'bad');
      return;
    }
    // Разрешение запрашивается только по нажатию кнопки: иначе браузер его отклонит.
    var permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      say('Уведомления не разрешены. Включите их в Настройках iPhone для BG Push.', 'bad');
      return;
    }
    var config = await api('/config');
    if (!config.enabled) {
      say('Сервер временно не принимает новые привязки.', 'bad');
      return;
    }
    var registration = await navigator.serviceWorker.register('/push/sw.js', { scope: '/push/' });
    await navigator.serviceWorker.ready;
    var subscription = await registration.pushManager.getSubscription();
    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: BgCore.b64urlDecode(config.vapid_public_key)
      });
    }
    var receiver = await BgCore.generateReceiverKeys();
    var receiverAuth = BgCore.randomBytes(16);
    var payload = {
      endpoint: subscription.endpoint,
      keys: {
        p256dh: BgCore.b64urlEncode(subscription.getKey('p256dh')),
        auth: BgCore.b64urlEncode(subscription.getKey('auth'))
      },
      ingress: {
        p256dh: BgCore.b64urlEncode(receiver.publicRaw),
        auth: BgCore.b64urlEncode(receiverAuth)
      },
      platform: 'ios_pwa'
    };
    var done = await api('/registrations/' + parsed.registrationId + '/complete', {
      method: 'POST',
      headers: authHeaders(parsed.secret),
      body: JSON.stringify(payload)
    });
    await BgStore.set(STATE_KEY, {
      registrationId: done.registration_id,
      token: done.token,
      ingressPrivate: receiver.privateKey,
      ingressPublicRaw: receiver.publicRaw,
      ingressAuth: receiverAuth
    });
    el.code.value = '';
    say('Устройство привязано. Теперь откройте BeyGram и подтвердите привязку.', 'ok');
    await refresh();
  }

  async function sendTest() {
    var state = await BgStore.get(STATE_KEY);
    if (!state) {
      return;
    }
    await api('/registrations/' + encodeURIComponent(state.registrationId) + '/test', {
      method: 'POST',
      headers: authHeaders(state.token)
    });
    say('Тест отправлен. Уведомление придёт в течение нескольких секунд.', 'ok');
  }

  async function disable() {
    var state = await BgStore.get(STATE_KEY);
    if (state) {
      try {
        await api('/registrations/' + encodeURIComponent(state.registrationId), {
          method: 'DELETE',
          headers: authHeaders(state.token)
        });
      } catch (error) {
        // Сервер недоступен: локальное отключение всё равно выполняем.
      }
    }
    var registration = await navigator.serviceWorker.getRegistration('/push/');
    if (registration) {
      var subscription = await registration.pushManager.getSubscription();
      if (subscription) {
        await subscription.unsubscribe();
      }
    }
    await BgStore.remove(STATE_KEY);
    say('Уведомления отключены на этом устройстве.', 'ok');
    await refresh();
  }

  function guard(button, action) {
    button.addEventListener('click', async function () {
      if (busy) {
        return;
      }
      busy = true;
      button.disabled = true;
      try {
        await action();
      } catch (error) {
        say(error && error.message ? error.message : 'Не удалось выполнить действие.', 'bad');
      } finally {
        busy = false;
        button.disabled = false;
      }
    });
  }

  async function init() {
    if (!supported()) {
      el.support.textContent = 'Этот браузер не поддерживает уведомления. Откройте BG Push с экрана «Домой» в Safari на iOS 16.4 или новее.';
      el.support.hidden = false;
    } else if (!isStandalone()) {
      el.support.textContent = 'Добавьте эту страницу на экран «Домой» (Поделиться → На экран «Домой») и откройте её оттуда.';
      el.support.hidden = false;
    }
    if ('serviceWorker' in navigator) {
      try {
        await navigator.serviceWorker.register('/push/sw.js', { scope: '/push/' });
      } catch (error) {
        say('Не удалось зарегистрировать службу уведомлений.', 'bad');
      }
    }
    await refresh();
  }

  guard(el.enable, enable);
  guard(el.test, sendTest);
  guard(el.refresh, refresh);
  guard(el.disable, disable);
  init();
})();
