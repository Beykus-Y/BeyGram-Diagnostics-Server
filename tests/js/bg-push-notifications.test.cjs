const assert = require('node:assert/strict');
const test = require('node:test');
require('../../app/static/push/assets/js/bg-core.js');
const core = globalThis.BgCore;
const encode = value => new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));
const parse = (data, language = 'ru') => core.parseMessage(encode(data), language);
const make = (key, args, custom = { from_id: '42', msg_id: '7' }, account = '123') =>
  ({ data: { loc_key: key, loc_args: args, custom, user_id: account } });

test('personal text, wrapped and flat payloads', () => {
  const input = make('MESSAGE_TEXT', ['Alice', 'Привет 😀']);
  for (const data of [input, input.data]) {
    const result = parse(data);
    assert.equal(result.t, 'Alice');
    assert.equal(result.b, 'Привет 😀');
    assert.equal(result.link, 'beygram://push/open');
    assert.equal(result.tag, 'tg:123:user:42:7');
  }
});
test('group uses actor and chat in correct order', () => {
  const result = parse(make('CHAT_MESSAGE_TEXT', ['Alice', 'Group', 'Hello'], { chat_id: 5, msg_id: 7 }));
  assert.equal(result.t, 'Group');
  assert.equal(result.b, 'Alice: Hello');
  assert.equal(result.context.peerType, 'chat');
});
test('channel, media, languages and hidden text', () => {
  assert.equal(parse(make('CHANNEL_MESSAGE_PHOTO', ['Channel'], { channel_id: 6 })).b, '📷 Фото');
  assert.equal(parse(make('MESSAGE_AUDIO', ['Alice']), 'en').b, '🎤 Voice message');
  assert.equal(parse(make('CHAT_MESSAGE_NOTEXT', ['Alice', 'Group'])).b, 'Alice: Новое сообщение');
  assert.equal(parse(make('MESSAGE_TEXT', ['Alice'])).b, 'Новое сообщение');
});
test('64-bit ids remain exact and accounts do not collapse', () => {
  const result = parse('{"data":{"loc_key":"MESSAGE_TEXT","loc_args":["Alice","text 9007199254740993"],"user_id":9007199254740993,"custom":{"from_id":9007199254740995,"msg_id":7}}}');
  assert.equal(result.context.account, '9007199254740993');
  assert.equal(result.context.peerId, '9007199254740995');
  assert.equal(result.b, 'text 9007199254740993');
  assert.notEqual(parse(make('MESSAGE_TEXT', ['A', 'B'])).tag, parse(make('MESSAGE_TEXT', ['A', 'B'], {from_id:42,msg_id:7}, '124')).tag);
});
test('control events and unknown events do not expose arguments', () => {
  assert.equal(parse(make('READ_HISTORY', ['private'])).k, 'control');
  assert.equal(parse(make('MESSAGE_MUTED', ['private'])).k, 'control');
  assert.equal(parse(make('UNRECOGNIZED', ['private'])), null);
  assert.equal(core.parseDetailed(encode('not json')).code, 'invalid-json-or-utf8');
});
test('reactions never replace original message notification', () => {
  const reaction = parse(make('CHAT_REACT_TEXT', ['Alice', 'Group', '👍', 'private text'], {chat_id:5,msg_id:7}));
  assert.equal(reaction.k, 'reaction');
  assert.equal(reaction.tag, '');
  assert.equal(reaction.b, 'Alice: Реакция на сообщение 👍');
});
test('privacy and arbitrary links', () => {
  const message = parse(make('MESSAGE_TEXT', ['Alice', 'private']));
  assert.equal(core.applyPrivacy(message, 'name', 'en').b, 'New notification');
  assert.equal(core.applyPrivacy(message, 'none', 'ru').t, 'BeyGram');
  assert.equal(core.safeLink('https://example.invalid'), 'beygram://push/open');
});
test('legacy BG Push payload remains compatible', () => {
  const message = parse({v:1,k:'test',id:'test-1',t:'BG',b:'Test'});
  assert.equal(message.k, 'test');
  assert.equal(message.id, 'test-1');
  assert.equal(parse({v:1,k:'msg',t:'A',b:'B',peer:42}).link, 'beygram://push/open?peer=42');
});
