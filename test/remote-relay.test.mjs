import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import { once } from 'node:events';
import { randomUUID, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { certificates } from '../src/certificates.mjs';
import { privateDirectory } from '../src/storage.mjs';
import { RemoteAccess } from '../src/remote-access.mjs';
import { createRemoteRelay } from '../src/remote-relay.mjs';

const publicOrigin = 'https://relay.notify.invalid';
const webOrigin = 'https://app.notify.invalid';
const protocol = 'notify-relay-v1';
const owner = { issuer: 'https://accounts.notify.invalid', subject: 'account-a', macID: 'mac-a' };
const identity = { ...owner, deviceID: 'phone-a', keyHash: 'a'.repeat(64) };

async function fixture(t, authorizer) {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await privateDirectory(directory);
  const tls = await certificates(directory, '127.0.0.1', true);
  const server = https.createServer(tls, (_req, res) => { res.writeHead(404); res.end(); });
  const tokens = new Map(), clients = new Set(), errors = [];
  const relay = createRemoteRelay({
    server, publicOrigin, webOrigin, reportError: error => errors.push(error),
    authorize: authorizer ?? (async req => tokens.get(req.headers.authorization)?.() ?? null)
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `wss://127.0.0.1:${server.address().port}/v1/relay`;
  t.after(async () => {
    for (const client of clients) client.terminate();
    await relay.close();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  function credential(role, extra = {}, signal = new AbortController().signal) {
    const token = `Bearer ${randomBytes(32).toString('base64url')}`;
    tokens.set(token, () => ({ ...owner, deviceID: 'phone-a', role, expiresAt: Date.now() + 10000, signal, ...extra }));
    return token;
  }
  function connect(token, { origin, host = 'relay.notify.invalid', path, protocols = protocol } = {}) {
    const client = new WebSocket(path ? new URL(path, url) : url, protocols, {
      ca: tls.ca, rejectUnauthorized: true, handshakeTimeout: 4000,
      headers: { host, ...(token ? { authorization: token } : {}), ...(origin ? { origin } : {}) }
    });
    clients.add(client);
    client.on('error', () => {});
    const messages = [];
    client.on('message', (data, binary) => messages.push({ data: Buffer.from(data), binary }));
    const opened = new Promise((resolve, reject) => {
      client.once('open', resolve);
      client.once('error', reject);
      client.once('unexpected-response', (_request, response) => {
        const status = response.statusCode;
        response.resume(); client.terminate();
        reject(Object.assign(new Error('Upgrade rejected'), { status }));
      });
    });
    return { client, messages, opened };
  }
  async function pair(macToken = credential('mac'), phoneToken = credential('phone')) {
    const mac = connect(macToken); await mac.opened;
    const ready = once(mac.client, 'message');
    const phone = connect(phoneToken, { origin: webOrigin }); await phone.opened;
    const [data, binary] = await ready;
    assert.equal(binary, false);
    assert.deepEqual(JSON.parse(data), { type: 'ready', version: 1 });
    return { mac, phone };
  }
  return { credential, connect, pair, tokens, errors, relay, server };
}

test('relay requires TLS, credentials, exact host/path/protocol and phone Origin', { timeout: 15000 }, async t => {
  assert.throws(() => createRemoteRelay({ server: http.createServer(), publicOrigin, webOrigin,
    authorize: async () => null, reportError() {} }), /HTTPS/);
  const f = await fixture(t);
  const phone = f.credential('phone'), mac = f.credential('mac');
  for (const [token, opts, status] of [
    [null, {}, 401],
    [phone, {}, 403],
    [phone, { origin: 'https://evil.invalid' }, 403],
    [mac, { origin: webOrigin }, 403],
    [mac, { host: 'other.invalid' }, 403],
    [mac, { path: '/v1/relay?token=not-a-real-secret' }, 404],
    [mac, { protocols: 'unrecognized-protocol' }, 400]
  ]) await assert.rejects(f.connect(token, opts).opened, { status });
});

test('relay forwards exact binary bytes in both directions without compression', { timeout: 10000 }, async t => {
  const f = await fixture(t), { mac, phone } = await f.pair();
  assert.equal(mac.client.extensions, '');
  assert.equal(phone.client.extensions, '');
  const bytes = randomBytes(2048);
  const toMac = once(mac.client, 'message');
  phone.client.send(bytes);
  const [received, binary] = await toMac;
  assert.equal(binary, true); assert.deepEqual(received, bytes);
  const toPhone = once(phone.client, 'message');
  mac.client.send(Buffer.from('synthetic opaque receipt'));
  const [receipt] = await toPhone;
  assert.equal(receipt.toString(), 'synthetic opaque receipt');
});

test('different account, issuer, Mac and phone remain separate even with matching other IDs', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  for (const changed of [
    { subject: 'account-b' }, { issuer: 'https://other-issuer.invalid' }, { macID: 'mac-b' }, { deviceID: 'phone-b' }
  ]) {
    const { mac, phone } = await f.pair();
    const outsider = f.connect(f.credential('phone', changed), { origin: webOrigin });
    await outsider.opened;
    const closed = once(outsider.client, 'close');
    outsider.client.send(Buffer.from('not for the other account'));
    await closed;
    assert.equal(mac.messages.filter(message => message.binary).length, 0);
    assert.equal(phone.messages.filter(message => message.binary).length, 0);
    const bothClosed = Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
    mac.client.close(); await bothClosed;
  }
});

test('duplicate side is rejected and reconnect never receives an offline queue', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  const macToken = f.credential('mac'), phoneToken = f.credential('phone');
  const alone = f.connect(macToken); await alone.opened;
  await assert.rejects(f.connect(macToken).opened, { status: 409 });
  const closed = once(alone.client, 'close');
  alone.client.send(Buffer.from('must never be queued')); await closed;
  const { mac, phone } = await f.pair(macToken, phoneToken);
  assert.equal(phone.messages.filter(message => message.binary).length, 0);
  const peerClosed = once(mac.client, 'close');
  phone.client.close(); await peerClosed;
});

test('local policy revocation closes both live relay sockets before its disk write finishes', { timeout: 10000 }, async t => {
  let saved = null, hold = false, release;
  const policy = await RemoteAccess.open({ owner, store: {
    read: async () => saved,
    write: async state => {
      if (hold) await new Promise(resolve => { release = resolve; });
      saved = structuredClone(state);
    }
  } });
  t.after(() => policy.disable());
  await policy.approveDevice({ deviceID: identity.deviceID, keyHash: identity.keyHash });
  policy.enable();
  const f = await fixture(t);
  const authorization = policy.connect(identity, 10000);
  const { mac, phone } = await f.pair(f.credential('mac', {}, authorization.signal),
    f.credential('phone', {}, authorization.signal));
  const closed = Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
  hold = true;
  const revoked = policy.revokeDevice(identity.deviceID);
  await closed;
  assert.equal(authorization.signal.aborted, true);
  release(); await revoked;
  await assert.rejects(f.connect(f.credential('mac', {}, authorization.signal)).opened, { status: 401 });
});

test('expired grants reject upgrades and live authorization expires without another message', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  for (const expiresAt of [Date.now() - 1, Date.now() + 90000, NaN])
    await assert.rejects(f.connect(f.credential('mac', { expiresAt })).opened, { status: 401 });
  const macToken = f.credential('mac', { expiresAt: Date.now() + 500 });
  const { mac, phone } = await f.pair(macToken);
  await Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
});

test('authorization failures are generic and timeouts abort the authorizer without upgrading', { timeout: 10000 }, async t => {
  let aborted = false;
  const f = await fixture(t, async (req, { signal }) => {
    if (req.headers.authorization === 'throw') throw new Error('secret-provider-detail');
    return new Promise(resolve => {
      signal.addEventListener('abort', () => { aborted = true; resolve(null); }, { once: true });
    });
  });
  await assert.rejects(f.connect('throw').opened, { status: 503 });
  assert.equal(f.errors.length, 1);
  assert.doesNotMatch(f.errors[0].message, /secret-provider-detail|throw/);
  await assert.rejects(f.connect('stall').opened, { status: 504 });
  assert.equal(aborted, true);
});

test('text and oversized frames close the pair instead of forwarding unsupported data', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  for (const payload of ['not an encrypted binary frame', Buffer.alloc(1_048_576 + 16_384 + 1)]) {
    const { mac, phone } = await f.pair();
    const closed = Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
    phone.client.send(payload); await closed;
    assert.equal(mac.messages.filter(message => message.binary).length, 0);
  }
});

test('message floods are bounded rather than indefinitely buffered', { timeout: 10000 }, async t => {
  const f = await fixture(t), { mac, phone } = await f.pair();
  const closed = Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
  for (let i = 0; i < 100; i++) phone.client.send(Buffer.from([i]));
  await closed;
  assert.ok(mac.messages.filter(message => message.binary).length <= 64);
});

test('timed-out authorizers retain their capacity until they actually settle', { timeout: 10000 }, async t => {
  const waiting = [];
  let calls = 0;
  const f = await fixture(t, (req, { signal }) => {
    calls++;
    if (req.headers.authorization === 'next') return null;
    return new Promise(resolve => waiting.push({ resolve, signal }));
  });
  t.after(() => { for (const entry of waiting) entry.resolve(null); });
  await Promise.all(Array.from({ length: 16 }, () =>
    assert.rejects(f.connect('stall').opened, { status: 504 })));
  assert.equal(waiting.length, 16);
  assert.ok(waiting.every(entry => entry.signal.aborted));
  await assert.rejects(f.connect('next').opened, { status: 503 });
  assert.equal(calls, 16);
  waiting[0].resolve(null);
  await assert.rejects(f.connect('next').opened, { status: 401 });
  assert.equal(calls, 17);
});

test('room limits isolate owners and still allow an existing room to pair at capacity', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  for (let account = 0; account < 8; account++) {
    for (let device = 0; device < 8; device++)
      await f.connect(f.credential('mac', { subject: `account-${account}`, deviceID: `phone-${device}` })).opened;
    await assert.rejects(f.connect(f.credential('mac', {
      subject: `account-${account}`, deviceID: 'phone-over-limit'
    })).opened, { status: 429 });
  }
  await assert.rejects(f.connect(f.credential('mac', { subject: 'account-over-limit' })).opened, { status: 429 });
  const phone = f.connect(f.credential('phone', { subject: 'account-0', deviceID: 'phone-0' }), { origin: webOrigin });
  await phone.opened;
});

test('shutdown closes active peers and prevents a late authorizer from upgrading', { timeout: 10000 }, async t => {
  let release, entered, pendingSignal;
  const started = new Promise(resolve => { entered = resolve; });
  const grant = role => ({ ...owner, deviceID: 'phone-a', role,
    expiresAt: Date.now() + 10000, signal: new AbortController().signal });
  const f = await fixture(t, (req, { signal }) => {
    if (req.headers.authorization !== 'late') return grant(req.headers.authorization);
    pendingSignal = signal;
    return new Promise(resolve => { release = resolve; entered(); });
  });
  const { mac, phone } = await f.pair('mac', 'phone');
  const closed = Promise.all([once(mac.client, 'close'), once(phone.client, 'close')]);
  const late = f.connect('late');
  const rejected = assert.rejects(late.opened);
  await started;
  const closing = f.relay.close();
  assert.equal(f.relay.close(), closing);
  await closing;
  assert.equal(pendingSignal.aborted, true);
  release(grant('mac'));
  await rejected;
  await closed;
  assert.notEqual(late.client.readyState, WebSocket.OPEN);
});

test('routing retains the verified role even if the authorizer later changes its record', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  const grant = { ...owner, deviceID: 'phone-a', role: 'mac',
    expiresAt: Date.now() + 10000, signal: new AbortController().signal };
  f.tokens.set('mutable', () => grant);
  const { mac, phone } = await f.pair('mutable');
  const delivered = new Promise(resolve => {
    for (const [role, peer] of [['mac', mac], ['phone', phone]])
      peer.client.on('message', (_data, binary) => { if (binary) resolve(role); });
  });
  grant.role = 'phone';
  mac.client.send(Buffer.from('must reach the original opposite role'));
  assert.equal(await delivered, 'phone');
});

test('a paused receiving peer hits the backpressure bound without relying on the rate limit', { timeout: 15000 }, async t => {
  const f = await fixture(t), { mac, phone } = await f.pair();
  phone.client.pause();
  const closed = once(mac.client, 'close');
  const payload = Buffer.alloc(1_048_576);
  for (let i = 0; i < 20 && mac.client.readyState === WebSocket.OPEN; i++) {
    mac.client.send(payload);
    await Promise.race([closed, delay(300)]);
  }
  const [code, reason] = await closed;
  phone.client.resume();
  assert.equal(code, 1008);
  assert.equal(reason.toString(), 'Relay backpressure limit reached.');
});
