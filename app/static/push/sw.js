/*
 * BG Push: service worker, версия 5 (конверт aesgcm, см. bg-core.js). Обрабатывает только push и notificationclick.
 * Кэширования и перехвата запросов нет: привязка и токены не должны попадать в кэш.
 */
importScripts('/push/assets/js/bg-core.js?v=3', '/push/assets/js/bg-store.js');

var REGISTRATIONS_PATH = '/api/v1/push/registrations/';

self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', function (event) {
  event.waitUntil(handlePush(event));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var link = BgCore.safeLink(event.notification.data && event.notification.data.link);
  event.waitUntil(self.clients.openWindow('/push/open#' + encodeURIComponent(link)));
});

async function handlePush(event) {
  var state = null;
  try {
    state = await BgStore.get('reg');
  } catch (error) {
    state = null;
  }

  var message = null;
  var preferences = {};
  var code = 'missing-registration';
  try {
    preferences = (await BgStore.get('notification-preferences')) || {};
  } catch (error) {
    // Fail closed when local privacy preferences cannot be read.
    preferences = { privacy: 'none' };
  }
  var language = preferences.language === 'ru' || preferences.language === 'en' ?
    preferences.language : self.navigator.language;
  try {
    if (event.data && state && state.ingressPrivate) {
      code = 'inner-decrypt-failed';
      var cipher = await event.data.arrayBuffer();
      var plain = await BgCore.decryptIngress(
        cipher, state.ingressPrivate, state.ingressPublicRaw, state.ingressAuth
      );
      var parsed = BgCore.parseDetailed(plain, language);
      code = parsed.code;
      message = parsed.message;
    } else if (!event.data) {
      code = 'missing-push-data';
    }
  } catch (error) {
    message = null;
  }
  // Only a fixed diagnostic code is kept locally; never store raw payload or IDs.
  try {
    await BgStore.set('last-push-result', code);
  } catch (error) {
    // Diagnostics must not block notification delivery.
  }

  if (message && message.k === 'test') {
    await self.registration.showNotification(/^en(?:-|$)/i.test(language) ? 'BG Push is working' : 'BG Push работает', {
      body: /^en(?:-|$)/i.test(language) ? 'Test notification received.' : 'Тестовое уведомление получено.',
      tag: 'bg-push-test',
      data: { link: 'beygram://push/open' },
      icon: '/push/assets/icons/icon-192.png?v=2'
    });
    await acknowledge(state, message.id);
    return;
  }

  // Web Push requires a visible notification. Control events use a neutral
  // refresh hint instead of pretending a new Telegram message arrived.
  message = BgCore.applyPrivacy(message || BgCore.fallback(language), preferences.privacy, language);
  if (message.k === 'control') {
    try {
      var notifications = await self.registration.getNotifications();
      notifications.forEach(function (notification) {
        if (BgCore.shouldCloseNotification(message, notification.tag)) notification.close();
      });
    } catch (error) {
      // Best effort: browser may not expose all notifications.
    }
  }
  await self.registration.showNotification(message.t, {
    body: message.b,
    tag: message.k === 'control' ? 'bg-push-control' : message.tag || undefined,
    silent: message.silent === true || message.k === 'control',
    data: { link: BgCore.safeLink(message.link) },
    icon: '/push/assets/icons/icon-192.png?v=2'
  });
}

async function acknowledge(state, testId) {
  if (!state || !state.token || !state.registrationId || !testId) {
    return;
  }
  try {
    await fetch(REGISTRATIONS_PATH + encodeURIComponent(state.registrationId) + '/ack', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + state.token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ test_id: testId }),
      credentials: 'omit',
      cache: 'no-store'
    });
  } catch (error) {
    // Подтверждение не обязательно для доставки: ошибка сети здесь безвредна.
  }
}
