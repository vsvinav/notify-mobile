import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRemoteTransport, base64url, parseSetup, credentialJSON, postJSON } from '../public/remote-transport.mjs';

const key = Uint8Array.from({ length: 65 }, (_, i) => i ? 1 : 4);
const encode = value => new TextEncoder().encode(JSON.stringify(value));
const epoch = '11111111-1111-4111-8111-111111111111';
const grantID = 'g'.repeat(43);
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
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
    post: async (path, data, timeout, signal) => {
      calls.push({ path, data });
      if (options.post) return options.post(path, data, timeout, signal);
      return path.endsWith('begin') ? { id: grantID, challenge: 'challenge', expiresAt: Date.now() + 30000 }
        : { role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
          renewal: { id: grantID, challenge: `renew-${calls.length}` } };
    }
  });
  async function connect() {
    await transport.connect();
    const socket = sockets.at(-1);
    socket.onopen?.();
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

test('renewal keeps the peer and pending mutation alive beyond the old lease and 12s ACK timeout', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  const h = harness(); t.after(() => h.transport.close());
  const socket = await h.connect(), statusCount = h.statuses.length;
  for (let i = 0; i < 2; i++) { t.mock.timers.tick(10000); await flush(); }
  let settled = false;
  const result = h.transport.api('control', { action: 'stop' }).finally(() => { settled = true; });
  void result.catch(() => {});
  const request = JSON.parse(new TextDecoder().decode(socket.sent.at(-1)));
  t.mock.timers.tick(10000); await flush();
  t.mock.timers.tick(3000); await flush();
  t.mock.timers.tick(9000); await flush();
  assert.equal(settled, false);
  assert.equal(socket.readyState, 1);
  assert.equal(h.peers.length, 1);
  assert.equal(h.statuses.length, statusCount);
  assert.equal(h.calls.filter(call => call.path.endsWith('/renew')).length, 4);
  socket.message(encode({ id: request.id, status: 200, data: { acknowledged: true } }).buffer);
  assert.deepEqual(await result, { acknowledged: true });
  const callCount = h.calls.length;
  h.transport.close(); t.mock.timers.tick(60000); await flush();
  assert.equal(h.calls.length, callCount);
});

test('pending approval renews without exposing RPC and retains the bounded handshake deadline', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  const h = harness(); t.after(() => h.transport.close());
  await h.transport.connect();
  const socket = h.sockets[0]; socket.onopen?.();
  socket.message('{"type":"ready","version":1}');
  socket.message(encode({ type: 'welcome', welcome: [1], tree: [2] }).buffer);
  for (let i = 0; i < 4; i++) { t.mock.timers.tick(10000); await flush(); }
  assert.equal(socket.readyState, 1);
  assert.equal(h.calls.filter(call => call.path.endsWith('/renew')).length, 4);
  await assert.rejects(h.transport.api('state'), /approved/);
  assert.equal(h.statuses.at(-1).state, 'pending');
  t.mock.timers.tick(80000); await flush();
  assert.equal(socket.readyState, 3);
});

test('renewal rejects changed binding and uncertain responses without retrying a consumed challenge', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  for (const change of [
    { role: 'mac' }, { macID: 'other' }, { deviceID: 'other' }, { approved: 'yes' }, { approved: false },
    { renewal: { id: 'x'.repeat(43), challenge: 'next' } },
    { renewal: { id: grantID, challenge: 'renew' } },
    { renewal: { id: grantID, challenge: 'x'.repeat(4097) } },
    { renewal: { id: grantID, challenge: 'é'.repeat(2049) } },
    { expiresAt: Date.now() + 1000000 }, { expiresAt: 0 }, null
  ]) {
    const h = harness({ post: async path => {
      if (path.endsWith('begin')) return { id: grantID, challenge: 'challenge' };
      if (path.endsWith('renew') && change === null) throw new Error('Response lost');
      return { role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
        renewal: { id: grantID, challenge: path.endsWith('renew') ? 'next' : 'renew' },
        ...(path.endsWith('renew') ? change : {}) };
    } });
    const socket = await h.connect();
    const pending = assert.rejects(h.transport.api('reply'), /uncertain/);
    t.mock.timers.tick(10000); await flush();
    assert.equal(socket.readyState, 3);
    await pending;
    t.mock.timers.tick(60000); await flush();
    assert.equal(h.calls.filter(call => call.path.endsWith('renew')).length, 1);
    h.transport.close();
  }
});

test('close aborts renewal HTTP and discards its late response without overlapping or resurrecting a socket', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  let release, signal;
  const h = harness({ post: async (path, _data, _timeout, requestSignal) => {
    if (path.endsWith('begin')) return { id: grantID, challenge: 'challenge' };
    if (path.endsWith('renew')) {
      signal = requestSignal;
      return new Promise(resolve => { release = resolve; });
    }
    return { role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
      renewal: { id: grantID, challenge: 'renew' } };
  } }); t.after(() => h.transport.close());
  await h.connect();
  t.mock.timers.tick(10000); await flush();
  t.mock.timers.tick(10000); await flush();
  assert.equal(h.calls.filter(call => call.path.endsWith('renew')).length, 1);
  assert.equal(signal.aborted, false);
  h.transport.close();
  assert.equal(signal.aborted, true);
  release({ role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
    renewal: { id: grantID, challenge: 'next' } });
  await flush(); t.mock.timers.tick(60000); await flush();
  assert.equal(h.sockets.length, 1);
  assert.equal(h.calls.filter(call => call.path.endsWith('renew')).length, 1);
});

test('read timeout stays short while a missing mutation ACK remains bounded at 25 seconds', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  const h = harness(); t.after(() => h.transport.close());
  await h.connect();
  let readDone = false, mutationDone = false;
  const read = assert.rejects(h.transport.api('state'), /uncertain/).then(() => { readDone = true; });
  const mutation = assert.rejects(h.transport.api('reply'), /uncertain/).then(() => { mutationDone = true; });
  t.mock.timers.tick(10000); await flush();
  t.mock.timers.tick(2000); await flush();
  assert.equal(readDone, true);
  assert.equal(mutationDone, false);
  t.mock.timers.tick(10000); await flush();
  assert.equal(mutationDone, false);
  t.mock.timers.tick(3000); await flush();
  assert.equal(mutationDone, true);
  await Promise.all([read, mutation]);
});

test('an unresolved renewal cannot revive the phone after the original expiry deadline', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  let release, signal;
  const h = harness({ post: async (path, _data, _timeout, requestSignal) => {
    if (path.endsWith('begin')) return { id: grantID, challenge: 'challenge' };
    if (path.endsWith('renew')) {
      signal = requestSignal;
      return new Promise(resolve => { release = resolve; });
    }
    return { role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
      renewal: { id: grantID, challenge: 'renew' } };
  } }); t.after(() => h.transport.close());
  const socket = await h.connect();
  t.mock.timers.tick(10000); await flush();
  t.mock.timers.tick(20000); await flush();
  assert.equal(signal.aborted, true);
  assert.equal(socket.readyState, 3);
  release({ role: 'phone', macID: 'mac', deviceID: 'phone', approved: true, expiresAt: Date.now() + 30000,
    renewal: { id: grantID, challenge: 'next' } });
  await flush(); t.mock.timers.tick(60000); await flush();
  assert.equal(h.calls.filter(call => call.path.endsWith('/renew')).length, 1);
  assert.equal(h.peers[0].freed, true);
});

test('slow renewal responses do not drift the 10-second cadence or overlap requests', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  let release, renewals = 0;
  const lease = () => ({ role: 'phone', macID: 'mac', deviceID: 'phone', approved: true,
    expiresAt: Date.now() + 30000, renewal: { id: grantID, challenge: `renew-${renewals}` } });
  const h = harness({ post: async path => {
    if (path.endsWith('begin')) return { id: grantID, challenge: 'challenge' };
    if (path.endsWith('renew') && ++renewals === 1) return new Promise(resolve => { release = () => resolve(lease()); });
    return lease();
  } }); t.after(() => h.transport.close());
  await h.connect();
  t.mock.timers.tick(10000); await flush();
  t.mock.timers.tick(5000); await flush();
  assert.equal(renewals, 1);
  release(); await flush();
  t.mock.timers.tick(5000); await flush();
  assert.equal(renewals, 2);
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

test('an enrollment 401 does not incorrectly tell the phone to sign in again', async t => {
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json({ error: 'Device enrollment required.' }, { status: 401 }));
  await assert.rejects(postJSON('/v1/remote/grant/begin', {}), error => {
    assert.equal(error.status, 401);
    assert.match(error.message, /Device enrollment required/);
    assert.doesNotMatch(error.message, /sign in again/i);
    return true;
  });
});

test('HTTP errors retain status with empty, non-JSON or invalid error bodies', async t => {
  for (const response of [
    new Response(null, { status: 401 }),
    new Response('<html>Unavailable</html>', { status: 503 }),
    Response.json({ error: 'x'.repeat(501) }, { status: 401 }),
    Response.json({ error: {} }, { status: 403 })
  ]) {
    const mock = t.mock.method(globalThis, 'fetch', async () => response);
    await assert.rejects(postJSON('/v1/remote/grant/begin', {}), error => {
      assert.equal(error.status, response.status);
      assert.equal(error.message, `Request failed (${response.status}).`);
      return true;
    });
    mock.mock.restore();
  }
});

test('rejected setup authorization stops before opening a socket or automatically retrying', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  for (const rejectedPhase of ['begin', 'finish']) {
    const h = harness({ autoReconnect: true, post: async path => {
      if (path.endsWith(rejectedPhase)) throw Object.assign(new Error('Device enrollment required.'), { status: 401 });
      return { id: grantID, challenge: 'challenge' };
    } });
    await assert.rejects(h.transport.connect(), { status: 401 });
    t.mock.timers.tick(120000); await flush();
    assert.equal(h.sockets.length, 0);
    assert.equal(h.calls.length, rejectedPhase === 'begin' ? 1 : 2);
    assert.equal(h.statuses.at(-1).state, 'disconnected');
    assert.equal(h.peers[0].freed, true);
    h.transport.close();
  }
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
    post:async path=>path.endsWith('begin') ? {id:grantID,challenge:'synthetic challenge',expiresAt:Date.now()+30000}
      : {role:'phone',macID:'mac',deviceID:'phone',approved:true,expiresAt:Date.now()+30000,
        renewal:{id:grantID,challenge:'renew'}} });
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
