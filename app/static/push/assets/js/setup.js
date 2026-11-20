/*
 * BG Push: страница установки в Safari. Код привязки берётся из фрагмента URL.
 * Фрагмент не уходит на сервер и не попадает в журналы; после чтения его убираем из адресной строки.
 */
(function () {
  'use strict';

  var raw = '';
  try {
    raw = decodeURIComponent((location.hash || '').replace(/^#/, ''));
  } catch (error) {
    raw = '';
  }
  var valid = /^bgp1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(raw);
  var codeEl = document.getElementById('code');
  var copyButton = document.getElementById('copy');
  var note = document.getElementById('note');

  if (valid) {
    codeEl.textContent = raw;
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', location.pathname);
    }
  } else {
    codeEl.textContent = '—';
    copyButton.disabled = true;
    note.textContent = 'Откройте эту страницу из приложения BeyGram, чтобы получить код привязки.';
  }

  copyButton.addEventListener('click', async function () {
    try {
      await navigator.clipboard.writeText(codeEl.textContent);
      note.textContent = 'Код скопирован. Откройте BG Push с экрана «Домой» и вставьте его.';
    } catch (error) {
      note.textContent = 'Не удалось скопировать автоматически. Выделите код и скопируйте вручную.';
    }
  });
})();
