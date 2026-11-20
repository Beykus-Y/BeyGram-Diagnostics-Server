/*
 * BG Push: service worker, версия 2 (конверт aesgcm, см. bg-core.js). Обрабатывает только push и notificationclick.
 * Кэширования и перехвата запросов нет: привязка и токены не должны попадать в кэш.
 */
importScripts('/push/assets/js/bg-core.js', '/push/assets/js/bg-store.js');

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
  try {
    if (event.data && state && state.ingressPrivate) {
      var cipher = await event.data.arrayBuffer();
      var plain = await BgCore.decryptIngress(
        cipher, state.ingressPrivate, state.ingressPublicRaw, state.ingressAuth
      );
      message = BgCore.parseMessage(plain);
    }
  } catch (error) {
    message = null;
  }

  if (message && message.k === 'test') {
    await self.registration.showNotification('BG Push работает', {
      body: 'Тестовое уведомление получено.',
      tag: 'bg-push-test',
      data: { link: 'beygram://push/open' },
      icon: '/push/assets/icons/icon-192.png'
    });
    await acknowledge(state, message.id);
    return;
  }

  // Браузер требует видимого уведомления на каждый push, поэтому без расшифровки показываем общее.
  if (!message) {
    message = { t: 'BeyGram', b: 'Новое уведомление', link: 'beygram://push/open', tag: '' };
  }
  await self.registration.showNotification(message.t, {
    body: message.b,
    tag: message.tag || undefined,
    data: { link: message.link },
    icon: '/push/assets/icons/icon-192.png',
    badge: '/push/assets/icons/icon-192.png'
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
