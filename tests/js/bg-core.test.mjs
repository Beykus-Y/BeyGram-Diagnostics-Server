// Проверка bg-core.js: расшифровка записи, созданной серверной функцией, и разбор сообщения.
// Запуск из корня репозитория, python с пакетом cryptography (например, из venv):
//   BG_PYTHON=/путь/к/python node --test tests/js/bg-core.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const python = process.env.BG_PYTHON || 'python3';

// bg-core.js — классический скрипт браузера: выполняем его в глобальной области и берём BgCore.
vm.runInThisContext(readFileSync(join(root, 'app/static/push/assets/js/bg-core.js'), 'utf8'), {
  filename: 'bg-core.js',
});
const { BgCore } = globalThis;

const fixture = JSON.parse(
  execFileSync(python, [join(here, 'bg_core_fixture.py')], { cwd: root, encoding: 'utf8' }),
);

const encoder = new TextEncoder();
const body = () => new Uint8Array(Buffer.from(fixture.body, 'base64'));
const publicRaw = () => new Uint8Array(Buffer.from(fixture.publicRaw, 'base64'));
const auth = () => new Uint8Array(Buffer.from(fixture.auth, 'base64'));
const envelope = () => new Uint8Array(Buffer.from(fixture.aesgcmEnvelope, 'base64'));

async function receiverKey() {
  return crypto.subtle.importKey(
    'pkcs8',
    Buffer.from(fixture.privatePkcs8, 'base64'),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
}

test('расшифровывает запись, созданную серверной функцией', async () => {
  const plain = await BgCore.decryptAes128gcm(body(), await receiverKey(), publicRaw(), auth());
  assert.equal(new TextDecoder().decode(plain), fixture.plaintext);
});

test('разбор строит ссылку только из проверенных id и не берёт URL из payload', async () => {
  const plain = await BgCore.decryptAes128gcm(body(), await receiverKey(), publicRaw(), auth());
  const message = BgCore.parseMessage(plain);
  assert.equal(message.k, 'msg');
  assert.equal(message.t, 'Анна');
  assert.equal(message.link, 'beygram://push/open?account=1001&peer=-100200&msg=42');
});

test('некорректные id не попадают в ссылку', () => {
  const bytes = encoder.encode(JSON.stringify({ v: 1, k: 'msg', account: '1; x', peer: 'a', msg: '7' }));
  assert.equal(BgCore.parseMessage(bytes).link, 'beygram://push/open?msg=7');
});

test('непонятный payload возвращает null, а не угаданное уведомление', () => {
  assert.equal(BgCore.parseMessage(encoder.encode('{"hello":1}')), null);
  assert.equal(BgCore.parseMessage(encoder.encode('не json')), null);
});

test('safeLink пропускает только beygram://push/open с проверенными параметрами', () => {
  assert.equal(BgCore.safeLink('beygram://push/open'), 'beygram://push/open');
  assert.equal(
    BgCore.safeLink('beygram://push/open?account=1&peer=-2&msg=3'),
    'beygram://push/open?account=1&peer=-2&msg=3',
  );
  assert.equal(BgCore.safeLink('javascript:alert(1)'), 'beygram://push/open');
  assert.equal(BgCore.safeLink('https://evil.example/'), 'beygram://push/open');
  assert.equal(BgCore.safeLink('beygram://chat/1'), 'beygram://push/open');
});

test('подмена байта в записи приводит к ошибке', async () => {
  const tampered = body();
  tampered[tampered.length - 1] ^= 0x01;
  await assert.rejects(BgCore.decryptAes128gcm(tampered, await receiverKey(), publicRaw(), auth()));
});

test('неверный auth-секрет приводит к ошибке', async () => {
  const wrong = auth();
  wrong[0] ^= 0xff;
  await assert.rejects(BgCore.decryptAes128gcm(body(), await receiverKey(), publicRaw(), wrong));
});

test('decryptIngress открывает конверт aesgcm, записанный эталонной http_ece', async () => {
  const plain = await BgCore.decryptIngress(envelope(), await receiverKey(), publicRaw(), auth());
  assert.equal(new TextDecoder().decode(plain), fixture.plaintext);
});

test('decryptIngress по-прежнему открывает обычную запись aes128gcm', async () => {
  const plain = await BgCore.decryptIngress(body(), await receiverKey(), publicRaw(), auth());
  assert.equal(new TextDecoder().decode(plain), fixture.plaintext);
});

test('подмена байта в конверте aesgcm приводит к ошибке', async () => {
  const tampered = envelope();
  tampered[tampered.length - 1] ^= 0x01;
  await assert.rejects(BgCore.decryptIngress(tampered, await receiverKey(), publicRaw(), auth()));
});

test('конверт aesgcm не открывается с чужим auth-секретом', async () => {
  const wrong = auth();
  wrong[0] ^= 0xff;
  await assert.rejects(BgCore.decryptIngress(envelope(), await receiverKey(), publicRaw(), wrong));
});

// Include parser regressions in the existing CI Node entry point.
await import('./bg-push-notifications.test.cjs');

await import('./bg-push-navigation.test.cjs');
