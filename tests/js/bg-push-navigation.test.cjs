const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
require('../../app/static/push/assets/js/bg-core.js');
const core = globalThis.BgCore;
const fixture = require('../../docs/bg-push-navigation-v2.json');
const root = path.resolve(__dirname, '../..');
const open = 'beygram://push/open';
const url = (kind, peer, msg, account = '123') =>
  open + '?v=2&account=' + account + '&kind=' + kind + '&rawPeer=' + peer + (msg === undefined ? '' : '&msg=' + msg);
const enc = x => new TextEncoder().encode(typeof x === 'string' ? x : JSON.stringify(x));
const payload = (loc_key, custom, user_id = '123') => ({
  data: { loc_key, custom, user_id, loc_args: ['Alice', 'Group', 'Hello'] }
});
const parse = x => core.parseMessage(enc(x), 'en');

test('shared JS/Swift contract fixture: validation, canonical ordering and exact fields', () => {
  assert.equal(fixture.version, 2);
  for (const row of fixture.cases) {
    assert.equal(core.safeLink(row.input), row.expectedLink, row.name);
    const navigation = core.parseNavigationLink(row.input);
    if (!row.navigation) assert.equal(navigation, null, row.name);
    else {
      const n = row.navigation;
      assert.deepEqual(navigation, {account:n.account,peerType:n.kind,peerId:n.rawPeer,...(n.msg === undefined ? {} : {messageId:n.msg})}, row.name);
      assert.equal(core.buildNavigationLink(navigation),row.expectedLink,row.name);
    }
  }
});

test('documented dialog fields; basic group vs supergroup vs broadcast', () => {
  for (const [key, custom, expected] of [
    ['MESSAGE_TEXT', {from_id:42,msg_id:7}, url('user',42,7)],
    ['CHAT_MESSAGE_TEXT',{chat_id:42,chat_from_id:99,msg_id:7},url('chat',42,7)],
    ['CHAT_MESSAGE_TEXT',{channel_id:42,chat_from_broadcast_id:99,msg_id:7},url('channel',42,7)],
    ['CHANNEL_MESSAGE_PHOTO',{channel_id:42,msg_id:7},url('channel',42,7)],
    ['CHAT_MESSAGE_TEXT',{chat_id:42},url('chat',42)],
    ['CHAT_REACT_TEXT',{channel_id:42,msg_id:7,chat_from_id:99},url('channel',42,7)],
    ['REACT_TEXT',{from_id:42,msg_id:7},url('user',42,7)],
    ['CHANNEL_MESSAGES',{channel_id:42,msg_id:7},url('channel',42)],
    ['MESSAGE_PHOTOS',{from_id:42,msg_id:7},url('user',42)]
  ]) {
    const p = payload(key,custom);
    assert.equal(parse(p).link,expected,key);
    assert.equal(parse(p.data).link,expected,key+' flat');
  }
});

test('missing or contradictory context never guesses another chat', () => {
  for (const [key, custom, account] of [
    ['CHAT_MESSAGE_TEXT',{from_id:99,msg_id:7}],
    ['CHAT_MESSAGE_TEXT',{chat_id:42,channel_id:42,msg_id:7}],
    ['CHAT_MESSAGE_TEXT',{chat_id:42,channel_id:'x',msg_id:7}],
    ['CHAT_MESSAGE_TEXT',{chat_id:42,from_id:99,msg_id:7}],
    ['CHANNEL_MESSAGE_TEXT',{chat_id:42,msg_id:7}],
    ['MESSAGE_TEXT',{channel_id:42,msg_id:7}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:7,encryption_id:3}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:7},''],
    ['MESSAGE_TEXT',{from_id:'01',msg_id:7}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:2147483648}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:null}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:'7\n'}],
    ['MESSAGE_TEXT',{from_id:42,msg_id:7},'123\n'],
    ['MESSAGE_TEXT',{from_id:42,msg_id:7,schedule:true}]
  ]) assert.equal(parse(payload(key,custom,account)).link,open,JSON.stringify([key,custom,account]));
  for (const key of ['PHONE_CALL_MISSED','CHAT_MESSAGE_STORY','MESSAGE_STORY','ENCRYPTED_MESSAGE','READ_HISTORY','MESSAGE_DELETED'])
    assert.equal(parse(payload(key,{from_id:42,msg_id:7})).link,open,key);
  assert.equal(parse(payload('UNKNOWN',{from_id:42,msg_id:7})),null);
});

test('large numeric JSON IDs remain exact; decimal and exponent tokens are not normalized', () => {
  const raw = '{"data":{"loc_key":"MESSAGE_TEXT","loc_args":["A","B"],"user_id":9007199254740993,"custom":{"from_id":9007199254740995,"msg_id":2147483647}}}';
  assert.equal(parse(raw).link,url('user','9007199254740995','2147483647','9007199254740993'));
  for (const bad of ['1e3','42.0','42.000000000000001','9223372036854775808'])
    assert.equal(parse(raw.replace('9007199254740995',bad)).link,open,bad);
  assert.notEqual(parse(payload('MESSAGE_TEXT',{from_id:42,msg_id:7},'124')).link,url('user',42,7));
});

test('privacy and legacy/test push compatibility', () => {
  const p = parse(payload('MESSAGE_TEXT',{from_id:42,msg_id:7,url:'https://evil.invalid'}));
  assert.equal(core.applyPrivacy(p,'full','en').link,url('user',42,7));
  assert.equal(core.applyPrivacy(p,'name','en').link,url('user',42,7));
  assert.equal(core.applyPrivacy(p,'none','en').link,open);
  assert.equal(core.applyPrivacy(p,'corrupt','en').link,open);
  assert.equal(parse({v:1,k:'msg',account:123,peer:456,msg:7}).link,open+'?account=123&peer=456&msg=7');
  assert.equal(parse({v:1,k:'test',account:123,peer:456,msg:7}).link,open);
});

const swScript = fs.readFileSync(path.join(root,'app/static/push/sw.js'),'utf8');
const landingScript = fs.readFileSync(path.join(root,'app/static/push/assets/js/open.js'),'utf8');
function landing(fragment, safeLink = core.safeLink) {
  let href, auto, hint = {};
  const location = {hash:fragment};
  const ctx = {BgCore:{safeLink},location,window:{location:{set href(v){auto=v;}}},
    document:{getElementById:id=>id==='open'?{setAttribute:(attr,value)=>{assert.equal(attr,'href');href=value;}}:hint},
    setTimeout:fn=>fn()};
  vm.runInNewContext(landingScript,ctx);
  return {href,auto};
}
async function deliver(p, privacy) {
  const handlers = {};
  let notification, opened;
  const store = {reg:{ingressPrivate: true},'notification-preferences':{privacy,language:'en'}};
  const self = {navigator:{language:'en'},addEventListener:(name,fn)=>{handlers[name]=fn;},
    registration:{showNotification:async(t,options)=>{notification={title:t,...options,close(){}};}},
    clients:{openWindow:async href=>{opened=href;}}};
  vm.runInNewContext(swScript,{self,importScripts(){},
    BgCore:{...core,decryptIngress:async()=>enc(p)},
    BgStore:{get:async key=>store[key],set:async(key,value)=>{store[key]=value;}}});
  let work;
  handlers.push({data:{arrayBuffer:async()=>new ArrayBuffer(0)},waitUntil:p=>{work=p;}});
  await work;
  handlers.notificationclick({notification,waitUntil:p=>{work=p;}});
  await work;
  return {notification,opened,store};
}
test('SW push -> notification -> same-origin fragment -> landing -> native', async () => {
  const p = payload('MESSAGE_TEXT',{from_id:42,msg_id:7});
  for (const privacy of ['full','name','none']) {
    const result=await deliver(p,privacy);
    const expected=privacy==='none'?open:url('user',42,7);
    assert.equal(result.notification.data.link,expected);
    assert.equal(result.opened,'/push/open#'+encodeURIComponent(expected));
    assert.equal(result.store['last-push-result'],'telegram');
    const fragment=result.opened.slice('/push/open'.length);
    assert.deepEqual(landing(fragment),{href:expected,auto:expected});
    // The old landing validator accepts only old links, safely degrading v2.
    const oldSafeLink=value=>core.DEEP_LINK_RE.test(value)?value:open;
    assert.deepEqual(landing(fragment,oldSafeLink),{href:open,auto:open});
  }
});
test('landing rejects invalid fragments and does not execute external or malformed URLs', () => {
  for(const fragment of ['#%zz','#'+encodeURIComponent('https://evil.invalid'),'#'+encodeURIComponent(open+'?v=999&peer=42')])
    assert.deepEqual(landing(fragment),{href:open,auto:open});
  const legacy=open+'?account=123&peer=456&msg=7';
  assert.deepEqual(landing('#'+encodeURIComponent(legacy)),{href:legacy,auto:legacy});
});
