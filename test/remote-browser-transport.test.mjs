import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRemoteTransport, base64url, parseSetup, credentialJSON, postJSON } from '../public/remote-transport.mjs';

const key = Uint8Array.from({ length: 65 }, (_, i) => i ? 1 : 4);
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const epoch = '11111111-1111-4111-8111-111111111111';
function harness(options = {}) {
  const sockets = [], calls = [], peers = [], statuses = [];
  class Socket {
    readyState = 1; sent = [];
    constructor() { sockets.push(this); }
    send(bytes) { this.sent.push(bytes); }
    close() { this.readyState = 3; this.onclose?.(); }
    message(data) { this.onmessage?.({ data }); }
  }
  const transport = createRemoteTransport({
    origin: 'https://notify.example', macID: 'mac', deviceID: 'phone', pinnedMacKey: key,
    WebSocketImpl: Socket, onStatus: status => statuses.push(status), ...options,
    restorePeer: async () => {
      const peer = { freed: false, identity_key: () => key, key_package: () => new Uint8Array([1]),
        sign_authorization: () => new Uint8Array([2]), join_pinned: (welcome, tree, pinned) => assert.deepEqual(pinned, key),
        send: bytes => bytes, receive: bytes => ({ bytes: () => bytes, sender: () => new TextEncoder().encode('native'), free() {} }),
        free() { this.freed = true; } };
      peers.push(peer); return peer;
    },
    post: async (path, data) => {
      calls.push({ path, data });
      return path.endsWith('begin') ? { id: 'grant', challenge: 'challenge', expiresAt: Date.now() + 30000 }
        : { role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000 };
    }
  });
  async function connect() {
    await transport.connect();
    const socket = sockets.at(-1);
    socket.message('{"type":"ready","version":1}');
    socket.message(encode({ type: 'welcome', welcome: [1], tree: [2] }).buffer);
    socket.message(encode({ type: 'ready', epoch }).buffer);
    return socket;
  }
  return { transport, connect, sockets, peers, calls, statuses };
}

test('full QR key is mandatory and login never invents a user handle', () => {
  assert.deepEqual(parseSetup(`#setup=setup&mac=mac&key=${base64url(key)}`), { setupID: 'setup', macID: 'mac', macPublicKey: base64url(key) });
  assert.throws(() => parseSetup('#setup=setup&mac=mac&key=123456'));
  assert.throws(() => credentialJSON({ id: 'x', rawId: new Uint8Array([1]), type: 'public-key',
    response: { clientDataJSON: new Uint8Array([1]), authenticatorData: new Uint8Array([2]), signature: new Uint8Array([3]), userHandle: null } }, 'login'), /user handle/i);
});

test('account fetches use same-origin cookies and stop reading oversized responses', async t => {
  let cancelled = false, chunks = 0;
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    assert.equal(path, '/v1/account/session');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    return new Response(new ReadableStream({
      pull(controller) {
        chunks++;
        if (chunks > 1200) { controller.close(); return; }
        controller.enqueue(new Uint8Array(1024).fill(32));
      },
      cancel() { cancelled = true; }
    }));
  });
  await assert.rejects(postJSON('/v1/account/session', {}), /too large/);
  assert.equal(cancelled, true);
  assert.ok(chunks < 1100);
});

test('approval gates RPC; disconnect rejects uncertainty and reconnect restores fresh peer and grant', async () => {
  const h = harness();
  await assert.rejects(h.transport.api('state', {}), /approved|connected/i);
  const socket = await h.connect();
  const result = h.transport.api('state', {});
  const request = JSON.parse(new TextDecoder().decode(socket.sent.at(-1)));
  assert.equal(request.epoch, epoch);
  socket.message(encode({ id: request.id, status: 200, data: { connected: true } }).buffer);
  assert.deepEqual(await result, { connected: true });
  const action = h.transport.api('reply', { ticket: 'original' });
  socket.close();
  await assert.rejects(action, /uncertain/i);
  await h.connect();
  assert.equal(h.peers.length, 2);
  assert.equal(h.peers[0].freed, true);
  assert.equal(h.calls.filter(call => call.path.endsWith('begin')).length, 2);
  assert.equal(h.sockets[1].sent.length, 2);
  h.transport.close();
});

test('malformed relay greeting and non-binary post-greeting traffic fail closed', async () => {
  const h = harness();
  await h.transport.connect();
  h.sockets[0].message('{"version":1,"type":"ready"}');
  assert.equal(h.sockets[0].readyState, 3);
  await h.connect();
  h.sockets[1].message('{"type":"pending"}');
  assert.equal(h.sockets[1].readyState, 3);
  h.transport.close();
});

test('RPC limits and malformed responses close the channel without replay', async () => {
  const h = harness(), socket = await h.connect();
  const calls = Array.from({ length: 8 }, () => h.transport.api('state', {}));
  const rejected = calls.map(promise => assert.rejects(promise));
  await assert.rejects(h.transport.api('state', {}), /busy/i);
  const request = JSON.parse(new TextDecoder().decode(socket.sent.at(-1)));
  socket.message(encode({ id: request.id, status: '200', data: {} }).buffer);
  await Promise.all(rejected);
  assert.equal(socket.readyState, 3);
});

test('opted-in reconnect restores fresh identity and grant automatically without replaying actions', async () => {
  const h = harness({ autoReconnect: true }), socket = await h.connect();
  const action = assert.rejects(h.transport.api('control', { action: 'stop' }), /uncertain/i);
  socket.close(); await action;
  await new Promise(resolve => setTimeout(resolve, 1150));
  assert.equal(h.peers.length, 2);
  assert.equal(h.calls.filter(call => call.path.endsWith('begin')).length, 2);
  assert.equal(h.sockets[1].sent.length, 0);
  h.transport.close();
  await new Promise(resolve => setTimeout(resolve, 1100));
  assert.equal(h.peers.length, 2);
});

test('unexpected encrypted sender label fails closed even after pinned join', async () => {
  const h = harness(), socket = await h.connect();
  h.peers[0].receive = bytes => ({ bytes: () => bytes, sender: () => new TextEncoder().encode('phone'), free() {} });
  const pending = assert.rejects(h.transport.api('state', {}));
  const request = JSON.parse(new TextDecoder().decode(socket.sent.at(-1)));
  socket.message(encode({ id: request.id, status: 200, data: {} }).buffer);
  await pending;
  assert.equal(socket.readyState, 3);
});

test('actual WASM MLS establishes pinned channel and encrypts browser RPC (synthetic in-memory relay)', async () => {
  const { default: init, Peer } = await import('../public/remote-crypto/channel.js');
  await init({ module_or_path: await readFile(new URL('../public/remote-crypto/channel_bg.wasm', import.meta.url)) });
  const native = new Peer('native'), phone = new Peer('phone');
  const phoneKey = phone.identity_key(), secret = phone.export_identity(), macKey = native.identity_key();
  phone.free();
  let socket;
  class Socket {
    readyState = 1; sent = [];
    constructor() { socket = this; }
    send(bytes) { this.sent.push(bytes); }
    close() { this.readyState = 3; }
    message(bytes) { this.onmessage({ data: bytes }); }
  }
  const transport = createRemoteTransport({origin:'https://notify.example',macID:'mac',deviceID:'phone',pinnedMacKey:macKey,
    WebSocketImpl:Socket,restorePeer:async()=>Peer.restore_identity('phone',secret,phoneKey),
    post:async path=>path.endsWith('begin') ? {id:'test-grant',challenge:'synthetic challenge',expiresAt:Date.now()+30000}
      : {role:'phone',macID:'mac',deviceID:'phone',approved:true,expiresAt:Date.now()+30000} });
  try {
    await transport.connect(); socket.message('{"type":"ready","version":1}');
    const packageMessage = JSON.parse(new TextDecoder().decode(socket.sent[0]));
    native.create(crypto.randomUUID());
    const welcome = native.add_pinned(new Uint8Array(packageMessage.bytes),phoneKey);
    socket.message(encode({type:'welcome',welcome:[...welcome],tree:[...native.tree()]}).buffer);
    const hello = native.receive(socket.sent[1]);
    assert.deepEqual(JSON.parse(new TextDecoder().decode(hello.bytes())), {type:'hello'});
    assert.equal(new TextDecoder().decode(hello.sender()),'phone'); hello.free();
    socket.message(native.send(encode({type:'ready',epoch})).buffer);
    const response = transport.api('reply',{ticket:'synthetic-secret-ticket',decision:'deny'});
    const wire = socket.sent.at(-1);
    assert.equal(Buffer.from(wire).includes(Buffer.from('synthetic-secret-ticket')),false);
    const requestMessage = native.receive(wire), request = JSON.parse(new TextDecoder().decode(requestMessage.bytes()));
    requestMessage.free();
    assert.equal(request.payload.data.ticket,'synthetic-secret-ticket');
    socket.message(native.send(encode({id:request.id,status:200,data:{acknowledged:true}})).buffer);
    assert.deepEqual(await response,{acknowledged:true});
  } finally { transport.close(); native.free(); secret.fill(0); }
});
