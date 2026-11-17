import test from 'node:test';
import assert from 'node:assert/strict';
import { createRemoteCompanion } from '../src/remote-companion.mjs';
import { createECDH, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { permission } from './fixtures.mjs';
import https from 'node:https';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { certificates } from '../src/certificates.mjs';
import { createRemoteAuthority } from '../src/remote-authority.mjs';

const key = () => { const ecdh = createECDH('prime256v1'); ecdh.generateKeys(); return ecdh.getPublicKey().toString('base64url'); };
async function until(predicate) {
  const end = Date.now() + 3000;
  while (!predicate()) {
    if (Date.now() > end) throw new Error('Fixture condition timed out');
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

test('internet helper rejects insecure or non-origin service URLs before creating identity', async () => {
  for (const origin of ['http://example.com', 'https://example.com/path', 'https://a@example.com', 'https://example.com#key']) {
    await assert.rejects(createRemoteCompanion({ directory: '.', origin, emit() {} }), /origin/i);
  }
});

test('real native HTTP client verifies TLS without browser-only request headers', async () => {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'remote-http-'));
  const tls = await certificates(directory, '127.0.0.1', true);
  const macID = randomUUID(), publicKey = key();
  let headers;
  const server = https.createServer(tls, (req, res) => {
    headers = req.headers;
    req.resume();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ macID, pending: null, devices: [] }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const origin = `https://127.0.0.1:${server.address().port}`;
    await writeFile(join(directory, 'identity.json'), JSON.stringify({
      version: 1, origin, macID, publicKey, owner: null, devices: [],
      credential: 'c'.repeat(43), setupID: 'setup'
    }), { mode: 0o600 });
    const ca = join(directory, 'test-ca.pem');
    await writeFile(ca, tls.ca);
    await promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
      import fs from 'node:fs/promises';
      import { createRemoteCompanion } from './src/remote-companion.mjs';
      const directory = process.argv[1];
      const state = JSON.parse(await fs.readFile(directory + '/identity.json', 'utf8'));
      let count = 0, finish;
      const done = new Promise(resolve => { finish = resolve; });
      const helper = await createRemoteCompanion({
        directory, origin: state.origin,
        emit(event) { if (event.type === 'status' && ++count === 2) finish(); },
        cryptoProcess: () => ({
          async call() { return [...Buffer.from(state.publicKey, 'base64url')]; },
          async close() {}
        })
      });
      await done; await helper.close();
    `, directory], {
      timeout: 10000,
      env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1', NODE_EXTRA_CA_CERTS: ca }
    });
    assert.ok(headers, 'The verified HTTPS request must reach the server');
    assert.deepEqual(Object.keys(headers).filter(name => name.startsWith('sec-fetch-')), []);
    assert.equal(headers.origin, undefined);
    assert.equal(headers.cookie, undefined);
    assert.equal(headers.authorization, `Bearer ${'c'.repeat(43)}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true });
  }
});

test('closing the helper cancels an outstanding service poll', async () => {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'remote-close-'));
  const publicKey = key(), origin = 'https://notify.example';
  await writeFile(join(directory, 'identity.json'), JSON.stringify({
    version: 1, origin, macID: randomUUID(), publicKey, owner: null, devices: [],
    credential: 'c'.repeat(43), setupID: 'setup'
  }), { mode: 0o600 });
  let signal;
  const helper = await createRemoteCompanion({
    directory, origin, emit() {},
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(publicKey, 'base64url')]; },
      async close() {}
    }),
    fetchRequest: async (_url, options) => {
      signal = options.signal;
      await new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    }
  });
  try {
    await until(() => signal);
    await helper.close();
    assert.equal(signal.aborted, true);
  } finally {
    await helper.close();
    await rm(directory, { recursive: true });
  }
});

test('expired Mac registration is visible and cannot keep advertising a stale pairing QR', async t => {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'remote-recovery-'));
  const publicKey = key(), origin = 'https://notify.example', events = [];
  const saved = { version: 1, origin, macID: randomUUID(), publicKey,
    owner: { issuer: origin, subject: 'original-owner' }, devices: [],
    credential: 'c'.repeat(43), setupID: 'expired-setup' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  const helper = await createRemoteCompanion({
    directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(publicKey, 'base64url')]; },
      async close() {}
    }),
    fetchRequest: async () => Response.json({ error: 'Mac authorization required.' }, { status: 401 })
  });
  t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
  await until(() => events.filter(event => event.type === 'status').length >= 2);
  const status = events.findLast(event => event.type === 'status').status;
  assert.equal(status.state, 'error', 'An expired Mac registration must not look like an ongoing connection');
  assert.equal(status.setupURL, undefined, 'Do not offer a QR code the service has already rejected');
  assert.match(status.message, /Mac.*pair/i);
});

for (const subject of ['original-owner', 'different-owner']) {
  test(`restart recovery with real authority and ${subject} preserves the local trust boundary`, async t => {
    const root = join(process.cwd(), '.test-data');
    await mkdir(root, { recursive: true });
    const directory = await mkdtemp(join(root, 'remote-restart-'));
    const origin = 'https://notify.example', macID = randomUUID(), deviceID = randomUUID(), events = [];
    const { publicKey: publicObject, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicObject.export({ format: 'jwk' });
    const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64url');
    const owner = { issuer: origin, subject: 'original-owner' };
    const saved = { version: 1, origin, macID, publicKey, owner, devices: [],
      credential: 'c'.repeat(43), setupID: 'expired-setup' };
    await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
    const authority = createRemoteAuthority({ origin, accounts: { authorize: async () =>
      ({ issuer: origin, subject, signal: new AbortController().signal }) } });
    let receiver, closeRelay, polls = 0;
    const helper = await createRemoteCompanion({
      directory, origin, emit: event => events.push(event),
      cryptoProcess: () => ({
        async call(op, args = {}) {
          if (op === 'identity') return [...Buffer.from(publicKey, 'base64url')];
          if (op === 'sign') return [...sign('sha256', Buffer.concat([
            Buffer.from('Notify remote authorization v1\0'), Buffer.from(args.bytes)
          ]), privateKey)];
          // MLS is a fixture here; registration and grant signatures use the real authority.
          if (op === 'create') return null;
          if (op === 'add' || op === 'tree') return [1];
          if (op === 'receive') return { bytes: args.bytes, sender: [] };
          if (op === 'send') return args.bytes;
          throw new Error(`Unexpected crypto operation ${op}`);
        }, async close() {}
      }),
      fetchRequest: async (url, options) => {
        const path = new URL(url).pathname, input = JSON.parse(options.body);
        const credential = options.headers.Authorization?.slice(7);
        try {
          let result;
          if (path.endsWith('/mac/status')) { polls++; result = authority.macStatus(credential); }
          else if (path.endsWith('/mac/begin')) result = authority.beginMac(input);
          else if (path.endsWith('/mac/register')) result = authority.registerMac(input);
          else if (path.endsWith('/grant/begin')) result = await authority.beginGrant({}, { ...input, credential });
          else if (path.endsWith('/grant/finish')) result = authority.finishGrant(input);
          else if (path.endsWith('/mac/decision')) result = authority.decidePair(credential, input);
          else throw new Error(`Unexpected route ${path}`);
          return Response.json(result);
        } catch (error) {
          if (!error.status) throw error;
          return Response.json({ error: error.message }, { status: error.status });
        }
      },
      connectRelay: async ({ receive, signal }) => {
        receiver = receive;
        const closed = new Promise(resolve => { closeRelay = resolve; });
        signal.addEventListener('abort', () => closeRelay(), { once: true });
        return { closed, close() { closeRelay(); }, async send() {} };
      }
    });
    t.after(async () => { await helper.close(); authority.close(); await rm(directory, { recursive: true }); });
    await until(() => events.filter(event => event.type === 'status').length >= 2);
    for (let attempt = 0; attempt < 3; attempt++) await helper.command({ type: 'heartbeat' });
    await settle();
    assert.equal(polls, 1, 'Do not repeatedly poll with a credential the service rejected');
    await helper.command({ type: 'invite' });
    const registered = JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8'));
    assert.equal(registered.macID, macID);
    assert.equal(registered.publicKey, publicKey);
    assert.deepEqual(registered.owner, owner);
    assert.notEqual(registered.credential, saved.credential);
    assert.ok(events.findLast(event => event.type === 'status').status.setupURL);
    const phoneKey = key();
    const pairing = await authority.requestPair({ headers: { origin } }, {
      setupID: registered.setupID, deviceID, publicKey: phoneKey, name: 'Fixture phone'
    });
    await helper.command({ type: 'heartbeat' });
    await settle();
    if (subject !== owner.subject) {
      assert.equal(receiver, undefined);
      const status = events.findLast(event => event.type === 'status').status;
      assert.equal(status.state, 'error');
      assert.match(status.message, /locally approved owner/i);
      assert.equal(events.some(event => event.type === 'pairing'), false);
    } else {
      await until(() => receiver);
      await receiver(Buffer.from(JSON.stringify({ type: 'key_package', bytes: [1] })));
      await receiver(Buffer.from(JSON.stringify({ type: 'hello' })));
      const approval = events.findLast(event => event.type === 'pairing');
      assert.equal(approval.id, pairing.id);
      assert.deepEqual(authority.macStatus(registered.credential).devices, []);
      await helper.command({ type: 'pair', id: approval.id, allow: true, verificationData: approval.verificationData });
      assert.equal(events.findLast(event => event.type === 'status').status.state, 'connected');
    }
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8')).owner, owner);
  });
}

test('helper requires full-key local approval and native ACK (injected crypto fixture)', async () => {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'remote-runtime-'));
  const macID = randomUUID(), deviceID = randomUUID(), macKey = key(), phoneKey = key();
  const origin = 'https://notify.example', events = [], frames = [];
  const pending = { id: 'pending-phone', deviceID, publicKey: phoneKey, name: 'Phone',
    account: { issuer: origin, subject: 'owner' }, expiresAt: Date.now() + 120000 };
  await writeFile(join(directory, 'identity.json'), JSON.stringify({
    version: 1, origin, macID, publicKey: macKey, owner: null, devices: [],
    credential: 'c'.repeat(43), setupID: 'setup'
  }), { mode: 0o600 });
  let receiver, closeRelay, relaySignal;
  // This fixture isolates authorization/ACK ordering, not cryptographic correctness.
  const cryptoProcess = () => ({
    async call(op, args = {}) {
      if (op === 'identity') return [...Buffer.from(macKey, 'base64url')];
      if (op === 'sign') return [1, 2];
      if (op === 'create') return null;
      if (op === 'add' || op === 'tree') return [1];
      if (op === 'receive') return { bytes: args.bytes, sender: [] };
      if (op === 'send') return args.bytes;
      throw new Error(`Unexpected crypto operation ${op}`);
    },
    async close() {}
  });
  let decisions = 0;
  const fetchRequest = async (url, options) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/mac/status')) return Response.json({
      macID, pending: decisions ? null : pending,
      devices: decisions ? [{ deviceID, publicKey: phoneKey, name: 'Phone' }] : []
    });
    if (path.endsWith('/grant/begin')) return Response.json({ id: 'g'.repeat(43), challenge: 'fixture challenge' });
    if (path.endsWith('/grant/finish')) return Response.json({
      role: 'mac', macID, deviceID, approved: !!decisions, expiresAt: Date.now() + 29000, credential: 'g'.repeat(43),
      renewal: { id: 'g'.repeat(43), challenge: 'fixture renewal' }
    });

    if (path.endsWith('/mac/decision')) {
      assert.equal(JSON.parse(options.body).allow, true); decisions++;
      return Response.json({ approved: true });
    }
    throw new Error(`Unexpected fixture request ${path}`);
  };
  const connectRelay = async ({ receive, signal }) => {
    receiver = receive; relaySignal = signal;
    const closed = new Promise(resolve => { closeRelay = resolve; });
    signal.addEventListener('abort', () => closeRelay(), { once: true });
    return { send: async frame => frames.push(JSON.parse(frame.toString())), closed, async close() { closeRelay(); } };
  };
  const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
    cryptoProcess, fetchRequest, connectRelay });
  try {
    await until(() => receiver);
    await receiver(Buffer.from(JSON.stringify({ type: 'key_package', bytes: [1] })));
    await receiver(Buffer.from(JSON.stringify({ type: 'hello' })));
    assert.equal(events.findLast(e => e.type === 'status').status.state, 'pairing');
    const pairing = events.findLast(e => e.type === 'pairing');
    assert.equal(pairing.verificationData, Buffer.from(phoneKey, 'base64url').toString('base64'));
    await assert.rejects(helper.command({ type: 'pair', id: pending.id, allow: true, verificationData: 'wrong' }), /complete phone public key/i);
    assert.equal(decisions, 0);
    await helper.command({ type: 'pair', id: pending.id, allow: true, verificationData: pairing.verificationData });
    const ready = frames.findLast(f => f.type === 'ready');
    assert.ok(ready.epoch);
    assert.equal(events.findLast(e => e.type === 'status').status.state, 'connected');
    await helper.command({ type: 'snapshot', total: 1, requests: [permission()] });
    const id = randomUUID();
    await receiver(Buffer.from(JSON.stringify({ id, epoch: ready.epoch, payload: { path: 'reply', data: {
      sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {}
    } } })));
    await until(() => events.some(e => e.type === 'reply'));
    assert.equal(frames.some(f => f.id === id), false, 'No success before native runtime ACK');
    await helper.command({ type: 'result', id: events.findLast(e => e.type === 'reply').id, ok: true });
    await until(() => frames.some(f => f.id === id));
    assert.equal(frames.find(f => f.id === id).status, 200);
    for (let index = 0; index < 260; index++) {
      const readID = randomUUID();
      await receiver(Buffer.from(JSON.stringify({
        id: readID, epoch: ready.epoch, payload: { path: 'state', data: {} }
      })));
      await until(() => frames.some(f => f.id === readID));
      assert.equal(frames.find(f => f.id === readID).status, 200, 'Read polling must not exhaust action history');
    }
    const previousReceiver = receiver;
    closeRelay();
    await until(() => events.findLast(e => e.type === 'status').status.state !== 'connected');
    await helper.command({ type: 'heartbeat' });
    await until(() => receiver !== previousReceiver);
    await receiver(Buffer.from(JSON.stringify({ type: 'key_package', bytes: [1] })));
    await receiver(Buffer.from(JSON.stringify({ type: 'hello' })));
    const reconnected = frames.findLast(f => f.type === 'ready');
    assert.notEqual(reconnected.epoch, ready.epoch, 'Reconnect must invalidate the old action epoch');
    await helper.command({ type: 'offline' });
    assert.equal(relaySignal.aborted, true);
  } finally {
    await helper.close();
    await rm(directory, { recursive: true });
  }
});

const settle = async () => { for (let i = 0; i < 25; i++) await new Promise(resolve => setImmediate(resolve)); };
async function renewalFixture(t, { pendingApproval = false, renew } = {}) {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'remote-renew-'));
  const macID = randomUUID(), deviceID = randomUUID(), macKey = key(), phoneKey = key(), id = 'g'.repeat(43);
  const origin = 'https://notify.example', events = [], frames = [], requests = [], renewals = [], signed = [];
  const pending = { id: 'pending-phone', deviceID, publicKey: phoneKey, name: 'Phone',
    account: { issuer: origin, subject: 'owner' }, expiresAt: Date.now() + 120000 };
  await writeFile(join(directory, 'identity.json'), JSON.stringify({
    version: 1, origin, macID, publicKey: macKey,
    owner: pendingApproval ? null : pending.account,
    devices: pendingApproval ? [] : [{ id: deviceID, name: 'Phone', publicKey: phoneKey }],
    credential: 'c'.repeat(43), setupID: 'setup'
  }), { mode: 0o600 });
  let receiver, relaySignal, closeRelay, approved = !pendingApproval;
  const grant = () => ({ role: 'mac', macID, deviceID, approved, expiresAt: Date.now() + 30000,
    credential: 'r'.repeat(43), renewal: { id, challenge: `renew-${requests.length}` } });
  const helper = await createRemoteCompanion({
    directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call(op, args = {}) {
        if (op === 'identity') return [...Buffer.from(macKey, 'base64url')];
        if (op === 'sign') { signed.push(Buffer.from(args.bytes).toString()); return [1, 2]; }
        if (op === 'create') return null;
        if (op === 'add' || op === 'tree') return [1];
        if (op === 'receive') return { bytes: args.bytes, sender: [] };
        if (op === 'send') return args.bytes;
        throw new Error(`Unexpected crypto operation ${op}`);
      }, async close() {}
    }),
    fetchRequest: async (url, options) => {
      const path = new URL(url).pathname;
      requests.push({ path, options });
      if (path.endsWith('/mac/status')) return Response.json({
        macID, pending: approved ? null : pending,
        devices: approved ? [{ deviceID, publicKey: phoneKey, name: 'Phone' }] : []
      });
      if (path.endsWith('/grant/begin')) return Response.json({ id, challenge: 'initial' });
      if (path.endsWith('/grant/finish')) return Response.json(grant());
      if (path.endsWith('/grant/renew')) {
        assert.equal(options.headers.Authorization, `Bearer ${'c'.repeat(43)}`);
        assert.deepEqual(JSON.parse(options.body), { id, signature: 'AQI' });
        return renew ? await renew(grant(), options) : Response.json(grant());
      }
      if (path.endsWith('/mac/decision')) { approved = true; return Response.json({ approved }); }
      throw new Error(`Unexpected request ${path}`);
    },
    connectRelay: async ({ receive, signal, expiresAt, onOpen }) => {
      receiver = receive; relaySignal = signal;
      let resolve;
      const closed = new Promise(done => { resolve = done; });
      let timer = setTimeout(() => resolve(new Error('expired')), expiresAt - Date.now());
      closeRelay = () => { clearTimeout(timer); resolve(); };
      signal.addEventListener('abort', closeRelay, { once: true });
      const connection = { signal, closed, close: async () => closeRelay(),
        send: async bytes => frames.push(JSON.parse(bytes.toString())),
        renew(next) {
          signal.throwIfAborted();
          renewals.push(next); clearTimeout(timer);
          timer = setTimeout(() => resolve(new Error('expired')), next - Date.now());
        }
      };
      onOpen?.(connection);
      return connection;
    }
  });
  t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
  await settle();
  assert.ok(receiver);
  await receiver(Buffer.from(JSON.stringify({ type: 'key_package', bytes: [1] })));
  await receiver(Buffer.from(JSON.stringify({ type: 'hello' })));
  return { helper, events, frames, requests, renewals, signed, pending,
    receive: value => receiver(Buffer.from(JSON.stringify(value))), signal: relaySignal, disconnect: () => closeRelay() };
}

test('companion renews pending approval without data exposure, then retains live mutation and native ACK', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  const f = await renewalFixture(t, { pendingApproval: true });
  for (let i = 0; i < 4; i++) { t.mock.timers.tick(10000); await settle(); }
  assert.equal(f.renewals.length, 4);
  assert.equal(f.signal.aborted, false);
  assert.equal(f.frames.some(frame => frame.type === 'ready'), false);
  assert.equal(f.events.findLast(e => e.type === 'status').status.state, 'pairing');
  const pairing = f.events.findLast(e => e.type === 'pairing');
  await f.helper.command({ type: 'pair', id: pairing.id, allow: true, verificationData: pairing.verificationData });
  const ready = f.frames.findLast(frame => frame.type === 'ready');
  for (let i = 0; i < 2; i++) { t.mock.timers.tick(10000); await settle(); }
  await f.helper.command({ type: 'snapshot', total: 1, requests: [permission()] });
  const input = { id: randomUUID(), epoch: ready.epoch, payload: { path: 'reply', data: {
    sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {}
  } } };
  await f.receive(input); await settle();
  t.mock.timers.tick(10000); await settle();
  t.mock.timers.tick(3000); await settle();
  assert.equal(f.signal.aborted, false, 'The original approved handle deadline must have been renewed');
  assert.equal(f.frames.some(frame => frame.id === input.id), false, 'Renewal is not native ACK');
  await f.helper.command({ type: 'result', id: f.events.findLast(e => e.type === 'reply').id, ok: true });
  await settle();
  assert.equal(f.frames.find(frame => frame.id === input.id).status, 200);
  await f.receive(input); await settle();
  assert.equal(f.frames.filter(frame => frame.id === input.id).at(-1).status, 409);
  assert.equal(f.events.filter(e => e.type === 'reply').length, 1);
  assert.equal(f.frames.filter(frame => frame.type === 'ready').length, 1);
  assert.equal(new Set(f.signed).size, f.signed.length, 'A consumed challenge must never be signed twice');
  await f.helper.close();
  const count = f.requests.length;
  t.mock.timers.tick(60000); await settle();
  assert.equal(f.requests.length, count);
});

test('companion rejects invalid renewal bindings, lifetimes and uncertain responses without retry', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  for (const change of [
    { role: 'phone' }, { macID: 'other' }, { deviceID: 'other' }, { approved: false },
    { renewal: { id: 'x'.repeat(43), challenge: 'next' } }, { renewal: { id: 'g'.repeat(43), challenge: '' } },
    { expiresAt: 0 }, null
  ]) {
    const f = await renewalFixture(t, { renew: async grant => {
      if (change === null) throw new Error('Response lost');
      return Response.json({ ...grant, ...change });
    } });
    t.mock.timers.tick(10000); await settle();
    assert.equal(f.signal.aborted, true);
    assert.equal(f.renewals.length, 0);
    assert.equal(f.requests.filter(r => r.path.endsWith('/renew')).length, 1);
    await f.helper.close();
  }
});

test('companion renewal keeps its 10-second cadence after a slow HTTPS roundtrip', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  let release, renewals = 0;
  const f = await renewalFixture(t, { renew: async grant => {
    if (++renewals === 1) await new Promise(resolve => { release = resolve; });
    return Response.json(grant);
  } });
  t.mock.timers.tick(10000); await settle();
  t.mock.timers.tick(5000); await settle();
  assert.equal(renewals, 1);
  release(); await settle();
  t.mock.timers.tick(5000); await settle();
  assert.equal(renewals, 2);
  assert.equal(f.signal.aborted, false);
});

test('peer disconnect revokes the local handle before outstanding renewal HTTP drains', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  let release;
  const f = await renewalFixture(t, { renew: async grant => {
    await new Promise(resolve => { release = resolve; });
    return Response.json(grant);
  } });
  const ready = f.frames.find(frame => frame.type === 'ready');
  t.mock.timers.tick(10000); await settle();
  try {
    f.disconnect(); await settle();
    assert.equal(f.signal.aborted, true);
    await assert.rejects(f.receive({ id: randomUUID(), epoch: ready.epoch, payload: { path: 'state', data: {} } }),
      /closed|unknown|expired/i);
  } finally { release(); await settle(); }
  assert.equal(f.renewals.length, 0);
});

test('companion close aborts and drains outstanding renewal HTTP without late lease updates', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  let signal, release;
  const f = await renewalFixture(t, { renew: async (grant, options) => {
    signal = options.signal;
    await new Promise(resolve => { release = resolve; });
    return Response.json(grant);
  } });
  t.mock.timers.tick(10000); await settle();
  assert.ok(signal);
  t.mock.timers.tick(5000); await settle();
  let closed = false;
  const closing = f.helper.close().then(() => { closed = true; });
  await settle();
  assert.equal(signal.aborted, true);
  assert.equal(closed, false, 'close must drain renewal work');
  release(); await closing;
  assert.equal(f.renewals.length, 0);
  const count = f.requests.length;
  t.mock.timers.tick(60000); await settle();
  assert.equal(f.requests.length, count);
});
