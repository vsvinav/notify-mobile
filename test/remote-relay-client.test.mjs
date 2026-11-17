import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { once } from 'node:events';
import { randomUUID, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket, { WebSocketServer } from 'ws';
import { certificates } from '../src/certificates.mjs';
import { privateDirectory } from '../src/storage.mjs';
import { createRemoteRelay } from '../src/remote-relay.mjs';
import { connectRemoteRelay } from '../src/remote-relay-client.mjs';
import { RemoteAccess } from '../src/remote-access.mjs';

async function fixture(t, raw) {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await privateDirectory(directory);
  const tls = await certificates(directory, '127.0.0.1', true);
  const server = https.createServer(tls);
  // Discover a local port before constructing the relay's exact public origin.
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const origin = `https://127.0.0.1:${port}`, url = origin.replace('https:', 'wss:') + '/v1/relay';
  const credential = randomBytes(32).toString('base64url');
  const clients = new Set(), phones = new Set(), frames = [], requests = [], errors = [];
  const controller = new AbortController();
  let relay, wss;
  if (raw) {
    wss = new WebSocketServer({ server, perMessageDeflate: false });
    wss.on('connection', (ws, req) => {
      ws.on('error', error => errors.push(error));
      requests.push(req);
      raw(ws, req);
    });
  } else relay = createRemoteRelay({
    server, publicOrigin: origin, webOrigin: 'https://phone.notify.invalid',
    reportError: error => errors.push(error),
    authorize: req => {
      requests.push(req);
      const role = req.headers.authorization === `Bearer ${credential}` ? 'mac'
        : req.headers.authorization === 'Bearer synthetic-phone' ? 'phone' : null;
      return role ? { issuer: 'synthetic-issuer', subject: 'account', macID: 'mac', deviceID: 'phone',
        role, expiresAt: Date.now() + 10000, signal: new AbortController().signal } : null;
    }
  });
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    controller.abort();
    for (const phone of phones) phone.terminate();
    await Promise.all([...clients].map(client => client.close()));
    if (relay) await relay.close();
    if (wss) {
      for (const client of wss.clients) client.terminate();
      await new Promise(resolve => wss.close(resolve));
    }
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  async function mac(options = {}) {
    const client = await connectRemoteRelay({ url, credential, expiresAt: Date.now() + 10000,
      signal: controller.signal, receive: bytes => frames.push(bytes), ca: tls.ca, ...options });
    clients.add(client);
    return client;
  }
  async function phone() {
    const ws = new WebSocket(url, 'notify-relay-v1', { ca: tls.ca, rejectUnauthorized: true,
      headers: { origin: 'https://phone.notify.invalid', authorization: 'Bearer synthetic-phone' } });
    phones.add(ws);
    ws.on('error', error => errors.push(error));
    await once(ws, 'open');
    return ws;
  }
  return { mac, phone, url, credential, controller, frames, requests, server, tls };
}

test('Mac client waits for relay readiness and exchanges exact bytes without Origin or URL credentials', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  let connected = false;
  let delivered;
  const incoming = new Promise(resolve => { delivered = resolve; });
  const connecting = f.mac({ receive: delivered }).then(client => { connected = true; return client; });
  await delay(50);
  assert.equal(connected, false);
  const phone = await f.phone();
  const client = await connecting;
  const received = new Promise(resolve => phone.on('message', (bytes, binary) => { if (binary) resolve(bytes); }));
  const bytes = randomBytes(2048);
  const input = Buffer.from(bytes);
  const sending = client.send(input);
  input.fill(0);
  await sending;
  assert.deepEqual(await received, bytes);
  phone.send(Buffer.from('opaque synthetic receipt'));
  assert.equal((await incoming).toString(), 'opaque synthetic receipt');
  const request = f.requests.find(req => req.headers.authorization === `Bearer ${f.credential}`);
  assert.equal(request.headers.origin, undefined);
  assert.equal(request.url, '/v1/relay');
  assert.equal(request.headers['sec-websocket-extensions'], undefined);
  await assert.rejects(client.send('text instead of bytes'), /binary/i);
  await assert.rejects(client.send(Buffer.alloc(1_048_576 + 16_384 + 1)), /binary/i);
});

test('invalid endpoints, credentials and expired grants fail before opening a socket', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  for (const options of [
    { url: f.url.replace('wss:', 'ws:') },
    { url: f.url + '?token=secret' },
    { url: f.url.replace('/v1/relay', '/other') },
    { url: f.url.replace('wss://', 'wss://name:secret@') },
    { credential: 'secret\r\nInjected: true' },
    { credential: '' },
    { expiresAt: Date.now() - 1 },
    { expiresAt: Date.now() + 90000 },
    { signal: AbortSignal.abort() }
  ]) await assert.rejects(f.mac(options));
  assert.equal(f.requests.length, 0);
});

test('untrusted TLS certificates are rejected before sending credentials', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  await assert.rejects(f.mac({ ca: undefined }), /connection failed/i);
  assert.equal(f.requests.length, 0);
});

test('redirects never forward the credential to another path', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  f.server.removeAllListeners('upgrade');
  const paths = [];
  f.server.on('upgrade', (req, socket) => {
    paths.push(req.url);
    socket.on('error', () => socket.destroy());
    socket.end(`HTTP/1.1 302 Found\r\nLocation: ${f.url.replace('/v1/relay', '/stolen')}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  });
  await assert.rejects(f.mac(), /connection failed/i);
  assert.deepEqual(paths, ['/v1/relay']);
});

test('local revocation discards queued frames while cancelling the active callback', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  const owner = { issuer: 'synthetic-issuer', subject: 'account', macID: 'mac' };
  const device = { deviceID: 'phone', keyHash: 'a'.repeat(64) };
  const policy = await RemoteAccess.open({ owner, store: { read: async () => null, write: async () => {} } });
  t.after(() => policy.disable());
  await policy.approveDevice(device);
  policy.enable();
  const authorization = policy.connect({ ...owner, ...device }, 10000);
  let release, processingSignal, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const processed = [];
  const phone = await f.phone();
  const client = await f.mac({ signal: authorization.signal, receive: async (bytes, { signal }) => {
    processed.push(bytes.toString());
    processingSignal = signal;
    entered();
    await new Promise(resolve => { release = resolve; });
  } });
  phone.send(Buffer.from('first')); phone.send(Buffer.from('must not run'));
  await started;
  policy.disable();
  assert.equal(processingSignal.aborted, true);
  assert.match((await client.closed).message, /revoked/i);
  await assert.rejects(client.send(Buffer.from('late')), /closed|revoked/i);
  release();
  await delay(10);
  assert.deepEqual(processed, ['first']);
});

test('client expires independently of the relay and never reconnects automatically', { timeout: 10000 }, async t => {
  const f = await fixture(t), phone = await f.phone();
  const client = await f.mac({ expiresAt: Date.now() + 200 });
  assert.match((await client.closed).message, /expired/i);
  await assert.rejects(client.send(Buffer.from('late')), /closed|expired/i);
  assert.equal(f.requests.filter(req => req.headers.origin === undefined).length, 1);
  assert.equal(client.signal.aborted, true);
  phone.terminate();
});

test('callback errors close the connection without exposing private error details', { timeout: 10000 }, async t => {
  const f = await fixture(t), phone = await f.phone();
  const client = await f.mac({ receive: () => { throw new Error('private decrypted request'); } });
  phone.send(Buffer.from('opaque'));
  const error = await client.closed;
  assert.match(error.message, /processing failed/i);
  assert.doesNotMatch(error.message, /private|decrypted/);
});

test('a stalled consumer cannot accumulate an unbounded queue', { timeout: 10000 }, async t => {
  for (const [payload, count] of [[Buffer.from([0]), 12], [Buffer.alloc(1_048_576 + 16_384), 3]]) {
    let sender;
    const f = await fixture(t, ws => { sender = ws; ws.send('{"type":"ready","version":1}'); });
    let release, entered;
    const started = new Promise(resolve => { entered = resolve; });
    let calls = 0;
    const client = await f.mac({ receive: () => {
      calls++; entered();
      return new Promise(resolve => { release = resolve; });
    } });
    sender.send(payload);
    await started;
    for (let i = 1; i < count; i++) sender.send(payload);
    assert.match((await client.closed).message, /buffer limit/i);
    release();
    await delay(10);
    assert.equal(calls, 1);
  }
});

test('unexpected pre-ready and post-ready relay frames fail closed', { timeout: 10000 }, async t => {
  for (const frame of [Buffer.from('early bytes'), '{"type":"ready","version":2}', '{"type":"ready","version":1,"extra":true}']) {
    const f = await fixture(t, ws => ws.send(frame));
    await assert.rejects(f.mac(), /ready/i);
    assert.deepEqual(f.frames, []);
  }
  const f = await fixture(t, ws => {
    ws.send('{"type":"ready","version":1}');
    ws.send('{"type":"ready","version":1}');
  });
  const client = await f.mac();
  assert.match((await client.closed).message, /binary/i);
  assert.deepEqual(f.frames, []);
});

test('relay control-frame floods and oversized data frames close the client', { timeout: 10000 }, async t => {
  for (const kind of ['ping', 'oversized']) {
    const f = await fixture(t, ws => {
      ws.send('{"type":"ready","version":1}');
      if (kind === 'ping') for (let i = 0; i < 100; i++) ws.ping();
      else ws.send(Buffer.alloc(1_048_576 + 16_384 + 1));
    });
    const client = await f.mac();
    assert.match((await client.closed).message, kind === 'ping' ? /rate limit/i : /connection failed/i);
    assert.deepEqual(f.frames, []);
  }
});

test('peer disconnect is explicit and a replacement connection never receives old frames', { timeout: 10000 }, async t => {
  const f = await fixture(t), phone = await f.phone(), client = await f.mac();
  phone.terminate();
  assert.match((await client.closed).message, /disconnected|connection failed/i);
  await assert.rejects(client.send(Buffer.from('must not be retained')), /closed|disconnected|connection failed/i);
  const nextPhone = await f.phone();
  const frames = [];
  nextPhone.on('message', (data, binary) => { if (binary) frames.push(data); });
  const nextClient = await f.mac();
  const received = new Promise(resolve => nextPhone.on('message', (data, binary) => { if (binary) resolve(data); }));
  await nextClient.send(Buffer.from('new frame'));
  assert.equal((await received).toString(), 'new frame');
  assert.deepEqual(frames.map(data => data.toString()), ['new frame']);
  assert.equal(await nextClient.close(), null);
});
