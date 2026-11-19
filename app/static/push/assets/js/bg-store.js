/*
 * BG Push: состояние устройства в IndexedDB (идентификаторы, токен, ключи приёма).
 * localStorage и sessionStorage не используются: Safari и установленное приложение имеют разные хранилища.
 */
(function (root) {
  'use strict';

  var DB_NAME = 'bg-push';
  var STORE = 'kv';

  function open() {
    return new Promise(function (resolve, reject) {
      var request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = function () {
        request.result.createObjectStore(STORE);
      };
      request.onsuccess = function () {
        resolve(request.result);
      };
      request.onerror = function () {
        reject(request.error);
      };
    });
  }

  function run(mode, action) {
    return open().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, mode);
        var request = action(tx.objectStore(STORE));
        tx.oncomplete = function () {
          db.close();
          resolve(request ? request.result : undefined);
        };
        tx.onerror = function () {
          db.close();
          reject(tx.error);
        };
        tx.onabort = function () {
          db.close();
          reject(tx.error || new Error('transaction aborted'));
        };
      });
    });
  }

  root.BgStore = {
    get: function (key) {
      return run('readonly', function (store) {
        return store.get(key);
      });
    },
    set: function (key, value) {
      return run('readwrite', function (store) {
        store.put(value, key);
        return null;
      });
    },
    remove: function (key) {
      return run('readwrite', function (store) {
        store.delete(key);
        return null;
      });
    }
  };
})(typeof self !== 'undefined' ? self : globalThis);
