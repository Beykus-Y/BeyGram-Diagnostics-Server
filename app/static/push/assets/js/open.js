/*
 * BG Push: переход из уведомления в BeyGram. Адрес приходит во фрагменте и проверяется по белому списку.
 * Автоматическая попытка best effort: WebKit может её ограничить, поэтому кнопка остаётся основным способом.
 */
(function () {
  'use strict';

  var requested = '';
  try {
    requested = decodeURIComponent((location.hash || '').replace(/^#/, ''));
  } catch (error) {
    requested = '';
  }
  var link = BgCore.safeLink(requested);
  var button = document.getElementById('open');
  var hint = document.getElementById('hint');

  button.setAttribute('href', link);
  hint.textContent = link.indexOf('?') === -1
    ? 'Откроется BeyGram.'
    : 'Откроется нужный чат. Если приложение не открылось, нажмите кнопку ещё раз.';

  setTimeout(function () {
    window.location.href = link;
  }, 300);
})();
