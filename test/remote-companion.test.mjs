import test from 'node:test';
import assert from 'node:assert/strict';
import { createRemoteCompanion } from '../src/remote-companion.mjs';
import { createECDH, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { permission } from './fixtures.mjs';
import https from 'node:https';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { certificates } from '../src/certificates.mjs';

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
    if (path.endsWith('/grant/begin')) return Response.json({ id: 'challenge', challenge: 'fixture challenge' });
    if (path.endsWith('/grant/finish')) return Response.json({
      role: 'mac', macID, deviceID, expiresAt: Date.now() + 29000, credential: 'g'.repeat(43)
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
