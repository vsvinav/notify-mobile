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

test('native startup prepares one QR without blocking heartbeats behind the invitation', async () => {
  const source = await readFile(new URL('../src/remote-main.mjs', import.meta.url), 'utf8');
  const dependency = "import { createRemoteCompanion } from './remote-companion.mjs';";
  assert.equal(source.split(dependency).length, 2);
  const fixture = source.replace(dependency, `
    const createRemoteCompanion = async ({ emit }) => {
      let prepared = 0, release;
      return {
        prepareInvitation() {
          prepared++;
          return new Promise(resolve => { release = resolve; });
        },
        async command(value) {
          if (value.type !== 'heartbeat') throw Error('Unexpected fixture command');
          emit({ type: 'fixture', prepared, heartbeat: true });
          release?.();
        },
        async close() { release?.(); }
      };
    };
  `);
  const { stdout } = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', fixture + `
    process.stdin.emit('data', Buffer.from(
      JSON.stringify({ type: 'start', directory: 'fixture', origin: 'https://notify.example' }) + '\\n' +
      JSON.stringify({ type: 'heartbeat' }) + '\\n'));
    setImmediate(() => process.stdin.emit('end'));
  `], { timeout: 5000 });
  const events = stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(events, [{ type: 'fixture', prepared: 1, heartbeat: true }]);
});

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
  assert.match(status.message, /pairing registration expired/i);
});

for (const path of ['mac/begin', 'mac/invite']) {
  test(`pairing conflict at ${path} explains recovery without replacing saved trust`, async t => {
    const directory = join(process.cwd(), '.test-data', randomUUID());
    await mkdir(directory, { recursive: true });
    const origin = 'https://notify.example', events = [];
    const saved = { version: 1, origin, macID: randomUUID(), publicKey: key(), owner: null, devices: [],
      credential: path === 'mac/begin' ? null : 'c'.repeat(43), setupID: null };
    const file = join(directory, 'identity.json');
    await writeFile(file, JSON.stringify(saved), { mode: 0o600 });
    const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
      cryptoProcess: () => ({
        async call() { return [...Buffer.from(saved.publicKey, 'base64url')]; }, async close() {}
      }),
      fetchRequest: async url => new URL(url).pathname.endsWith(path)
        ? Response.json({ error: 'Conflict' }, { status: 409 })
        : Response.json({ macID: saved.macID, pending: null, devices: [] })
    });
    t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
    await until(() => events.filter(event => event.type === 'status').length >= 2);
    if (path === 'mac/invite') {
      await assert.rejects(helper.command({ type: 'invite' }), /Finish or reject.*pending phone/i);
    } else {
      assert.match(events.findLast(event => event.type === 'status').status.message, /Start fresh internet setup/);
    }
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), saved);
  });
}

for (const outcome of ['registered', 'retry', 'cancelled']) {
  test(`startup and immediate pairing share one enrollment: ${outcome}`, async t => {
    const directory = join(process.cwd(), '.test-data', randomUUID());
    await mkdir(directory, { recursive: true });
    const origin = 'https://notify.example', events = [];
    const { publicKey: publicObject, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicObject.export({ format: 'jwk' });
    const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64url');
    const saved = { version: 1, origin, macID: randomUUID(), publicKey, owner: null, devices: [],
      credential: null, setupID: null };
    const file = join(directory, 'identity.json');
    await writeFile(file, JSON.stringify(saved), { mode: 0o600 });
    const authority = createRemoteAuthority({ origin, accounts: { authorize: async () => {
      throw new Error('Enrollment must not authorize a phone');
    } } });
    const gate = Promise.withResolvers();
    let begins = 0, registrations = 0;
    const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
      cryptoProcess: () => ({
        async call(op, args) {
          if (op === 'identity') return [...Buffer.from(publicKey, 'base64url')];
          assert.equal(op, 'sign');
          return [...sign('sha256', Buffer.concat([
            Buffer.from('Notify remote authorization v1\0'), Buffer.from(args.bytes)
          ]), privateKey)];
        }, async close() {}
      }),
      fetchRequest: async (url, options) => {
        const path = new URL(url).pathname, input = JSON.parse(options.body);
        try {
          let result;
          if (path.endsWith('/mac/begin')) {
            const first = ++begins === 1;
            if (!first || outcome !== 'retry') result = authority.beginMac(input);
            if (first) {
              await gate.promise;
              options.signal.throwIfAborted();
              if (outcome === 'retry') return Response.json({ error: 'Temporarily unavailable' }, { status: 503 });
            }
          } else if (path.endsWith('/mac/register')) {
            registrations++;
            result = authority.registerMac(input);
          } else {
            assert.ok(path.endsWith('/mac/status'));
            result = authority.macStatus(options.headers.Authorization?.slice(7));
          }
          return Response.json(result);
        } catch (error) {
          if (!error.status) throw error;
          return Response.json({ error: error.message }, { status: error.status });
        }
      }
    });
    t.after(async () => { gate.resolve(); await helper.close(); authority.close(); await rm(directory, { recursive: true }); });
    await until(() => begins === 1);
    const invitation = helper.command({ type: 'invite' }).then(() => null, error => error);
    await settle();
    const closing = outcome === 'cancelled' ? helper.close() : undefined;
    gate.resolve();
    await closing;
    const error = await invitation;
    if (outcome === 'registered') assert.equal(error, null, 'Immediate pairing must not conflict with startup enrollment');
    else {
      assert.ok(error, 'Failure or shutdown must reject the pending invitation');
      assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), saved);
    }
    assert.equal(begins, 1, 'Only one bootstrap may run while the startup enrollment is pending');
    if (outcome === 'cancelled') return;
    if (outcome === 'retry') await helper.command({ type: 'invite' });
    const registered = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(registrations, 1);
    assert.deepEqual(registered, { ...saved, credential: registered.credential, setupID: registered.setupID });
    assert.equal(authority.macStatus(registered.credential).macID, saved.macID);
    assert.ok(events.findLast(event => event.type === 'status').status.setupURL);
  });
}

test('preparing the startup QR and an immediate manual request share one fresh invitation', async t => {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  const origin = 'https://notify.example', events = [], calls = [];
  const state = { version: 1, origin, macID: randomUUID(), publicKey: key(),
    owner: { issuer: origin, subject: 'owner' }, devices: [], credential: 'c'.repeat(43), setupID: 'old-setup' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(state), { mode: 0o600 });
  const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(state.publicKey, 'base64url')]; }, async close() {}
    }),
    fetchRequest: async (url, options) => {
      const path = new URL(url).pathname;
      calls.push(path);
      assert.equal(options.headers.Authorization, `Bearer ${state.credential}`);
      if (path.endsWith('/mac/invite'))
        return Response.json({ setupID: 'n'.repeat(43), expiresAt: Date.now() + 180000 });
      return Response.json({ macID: state.macID, account: state.owner, pending: null, devices: [] });
    }
  });
  t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
  await until(() => events.filter(event => event.type === 'status').length >= 2);
  await Promise.all([helper.prepareInvitation(), helper.command({ type: 'invite' })]);
  assert.equal(calls.filter(path => path === '/v1/remote/mac/invite').length, 1);
  const updated = JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8'));
  assert.deepEqual(updated, { ...state, setupID: 'n'.repeat(43) });
  assert.match(events.findLast(event => event.type === 'status').status.setupURL, new RegExp('n'.repeat(43)));
});

test('startup QR failure is visible without stopping the saved connection or advertising an old QR', async t => {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  const origin = 'https://notify.example', events = [];
  const saved = { version: 1, origin, macID: randomUUID(), publicKey: key(),
    owner: { issuer: origin, subject: 'owner' }, devices: [], credential: 'c'.repeat(43), setupID: 'old-setup' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  let deny = true;
  const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(saved.publicKey, 'base64url')]; }, async close() {}
    }),
    fetchRequest: async url => new URL(url).pathname.endsWith('/mac/invite')
      ? deny ? Response.json({ error: 'Unavailable' }, { status: 503 })
        : Response.json({ setupID: 'n'.repeat(43), expiresAt: Date.now() + 180000 })
      : Response.json({ macID: saved.macID, pending: null, devices: [] })
  });
  t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
  await helper.prepareInvitation();
  await helper.command({ type: 'heartbeat' });
  await settle();
  const status = events.findLast(event => event.type === 'status').status;
  assert.equal(status.setupURL, undefined);
  assert.match(status.message, /Pair an internet device/);
  assert.notEqual(status.state, 'error');
  assert.equal(events.some(event => event.type === 'error'), false);
  assert.deepEqual(JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8')), saved);
  deny = false;
  await helper.command({ type: 'invite' });
  assert.match(events.findLast(event => event.type === 'status').status.setupURL, /n{43}/);
});

test('a late expired-registration poll cannot invalidate the fresh startup QR', async t => {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  const origin = 'https://notify.example', events = [], gate = Promise.withResolvers();
  const saved = { version: 1, origin, macID: randomUUID(), publicKey: key(),
    owner: null, devices: [], credential: 'c'.repeat(43), setupID: 'expired-setup' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  let polls = 0;
  const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(saved.publicKey, 'base64url')]; }, async close() {}
    }),
    fetchRequest: async (url, options) => {
      const path = new URL(url).pathname;
      if (path.endsWith('/mac/begin')) return Response.json({ id: 'begin', challenge: 'challenge' });
      if (path.endsWith('/mac/register'))
        return Response.json({ macID: saved.macID, credential: 'd'.repeat(43), setupID: 'n'.repeat(43) });
      assert.ok(path.endsWith('/mac/status'));
      if (++polls === 1) await gate.promise;
      return options.headers.Authorization === `Bearer ${saved.credential}`
        ? Response.json({ error: 'Expired' }, { status: 401 })
        : Response.json({ macID: saved.macID, pending: null, devices: [] });
    }
  });
  t.after(async () => { gate.resolve(); await helper.close(); await rm(directory, { recursive: true }); });
  await until(() => polls === 1);
  await helper.prepareInvitation();
  assert.match(events.findLast(event => event.type === 'status').status.setupURL, /n{43}/);
  gate.resolve();
  await settle();
  const status = events.findLast(event => event.type === 'status').status;
  assert.notEqual(status.state, 'error');
  assert.match(status.setupURL, /n{43}/);
});

test('closing during startup QR preparation cannot save or advertise a late invitation', async t => {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  const origin = 'https://notify.example', events = [], gate = Promise.withResolvers();
  const saved = { version: 1, origin, macID: randomUUID(), publicKey: key(),
    owner: null, devices: [], credential: 'c'.repeat(43), setupID: 'previous-setup' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  let invitationSignal;
  const helper = await createRemoteCompanion({ directory, origin, emit: event => events.push(event),
    cryptoProcess: () => ({
      async call() { return [...Buffer.from(saved.publicKey, 'base64url')]; }, async close() {}
    }),
    fetchRequest: async (url, options) => {
      if (new URL(url).pathname.endsWith('/mac/invite')) {
        invitationSignal = options.signal;
        await gate.promise;
        return Response.json({ setupID: 'n'.repeat(43), expiresAt: Date.now() + 180000 });
      }
      return Response.json({ macID: saved.macID, pending: null, devices: [] });
    }
  });
  t.after(async () => { gate.resolve(); await helper.close(); await rm(directory, { recursive: true }); });
  const preparation = helper.prepareInvitation();
  await until(() => invitationSignal);
  const closing = helper.close(), eventCount = events.length;
  assert.equal(invitationSignal.aborted, true);
  gate.resolve();
  await Promise.all([preparation, closing]);
  assert.equal(events.length, eventCount);
  assert.deepEqual(JSON.parse(await readFile(join(directory, 'identity.json'), 'utf8')), saved);
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
      assert.match(status.message, /original Notify passkey/);
      assert.match(status.message, /Start fresh internet setup/);
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
  const attention = [];
  const fetchRequest = async (url, options) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/mac/attention')) {
      assert.equal(options.headers.Authorization, `Bearer ${'c'.repeat(43)}`);
      attention.push(JSON.parse(options.body));
      return Response.json({ accepted: true });
    }
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
    await helper.command({ type: 'snapshot', total: 1, requests: [permission()] });
    assert.equal(attention.length, 1);
    assert.deepEqual(Object.keys(attention[0]).sort(), ['eventID', 'issuedAt']);
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
    assert.equal(attention.length, 1, 'Polling and reply acknowledgment never generate further provider events');
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
async function renewalFixture(t, { pendingApproval = false, renew, status, finish, wrapCrypto = value => value } = {}) {
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
  let receiver, relaySignal, closeRelay, approved = !pendingApproval, revoked = false;
  const grant = () => ({ role: 'mac', macID, deviceID, approved, expiresAt: Date.now() + 30000,
    credential: 'r'.repeat(43), renewal: { id, challenge: `renew-${requests.length}` } });
  const helper = await createRemoteCompanion({
    directory, origin, emit: event => events.push(event),
    cryptoProcess: () => wrapCrypto({
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
      if (path.endsWith('/mac/status')) {
        const value = { macID, pending: approved || revoked ? null : pending,
          devices: approved ? [{ deviceID, publicKey: phoneKey, name: 'Phone' }] : [] };
        return status ? status(value, options) : Response.json(value);
      }
      if (path.endsWith('/grant/begin')) return Response.json({ id, challenge: 'initial' });
      if (path.endsWith('/grant/finish')) return finish ? await finish(grant(), options) : Response.json(grant());
      if (path.endsWith('/grant/renew')) {
        assert.equal(options.headers.Authorization, `Bearer ${'c'.repeat(43)}`);
        assert.deepEqual(JSON.parse(options.body), { id, signature: 'AQI' });
        return renew ? await renew(grant(), options) : Response.json(grant());
      }
      if (path.endsWith('/mac/decision')) { approved = true; return Response.json({ approved }); }
      if (path.endsWith('/mac/revoke')) { approved = false; revoked = true; return Response.json({ revoked }); }
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
    receive: value => receiver(Buffer.from(JSON.stringify(value))), signal: relaySignal, disconnect: () => closeRelay(),
    saved: () => readFile(join(directory, 'identity.json'), 'utf8') };
}

test('approved companion admits one urgent Off beyond eight inflight requests, not a tenth request', async t => {
  const f = await renewalFixture(t);
  const epoch = f.frames.find(frame => frame.type === 'ready').epoch;
  const offTicket = '00000000-0000-8000-8000-000000000001';
  await f.helper.command({ type: 'workspace', total: 1, truncated: false, sessions: [{
    id: 's', ticket: 't', name: 'Synthetic', project: '', agent: 'copilot', color: '#123456',
    state: 'working', connected: true, runningCount: 0, idleCount: 0,
    capabilities: { steering: true, subagentChat: false, subagentStop: false, dangerousAutoYes: true },
    dangerousAutoYes: { ticket: 'p', offTicket, revision: 1, enabled: true, normalEnabled: false }
  }] });
  const rpc = data => ({ id: data.id, epoch, payload: { path: 'control', data } });
  const queue = () => ({ id: randomUUID(), sessionID: 's', ticket: 't', action: 'queue', text: 'Synthetic' });
  for (let i = 0; i < 8; i++) await f.receive(rpc(queue()));
  const off = rpc({ id: offTicket, sessionID: 's', ticket: 't', action: 'dangerous_auto_yes',
    enabled: false, text: '', policyTicket: 'p', offTicket });
  await f.receive(off);
  assert.equal(f.events.filter(event => event.type === 'control').length, 9);
  await assert.rejects(f.receive(rpc(queue())), /busy/);
  await assert.rejects(f.receive(off), /duplicated/);
  assert.equal(f.events.filter(event => event.type === 'control').length, 9);
  await f.helper.command({ type: 'control_result', id: offTicket, ok: true, commandID: offTicket,
    status: 'applied', detail: '', dangerousAutoYes: {
      ticket: 'p2', offTicket: '00000000-0000-8000-8000-000000000002', revision: 2, enabled: false, normalEnabled: false
    } });
  await settle();
  assert.equal(f.frames.findLast(frame => frame.id === offTicket).data.dangerousAutoYes.enabled, false);
});

test('approved companion stale Off can be explicitly retried after refresh and 300 Off epochs survive full history', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = await renewalFixture(t);
  const epoch = f.frames.find(frame => frame.type === 'ready').epoch;
  const token = () => randomUUID().replace(/^(.{14})./, '$18');
  let policy = { ticket: randomUUID(), offTicket: token(), revision: 1, enabled: false, normalEnabled: false };
  const publish = () => f.helper.command({ type: 'workspace', total: 1, truncated: false, sessions: [{
    id: 's', ticket: 't', name: 'Synthetic', project: '', agent: 'copilot', color: '#123456',
    state: 'working', connected: true, runningCount: 0, idleCount: 0,
    capabilities: { steering: true, subagentChat: false, subagentStop: false, dangerousAutoYes: true },
    dangerousAutoYes: { ...policy }
  }] });
  const command = enabled => ({ id: enabled ? randomUUID() : policy.offTicket, sessionID: 's', ticket: 't',
    action: 'dangerous_auto_yes', enabled, text: '', policyTicket: policy.ticket, offTicket: policy.offTicket });
  const send = async data => {
    await f.receive({ id: data.id, epoch, payload: { path: 'control', data } });
    await settle();
  };
  const ack = async () => {
    const event = f.events.findLast(e => e.type === 'control');
    if (event.action === 'dangerous_auto_yes')
      policy = { ...policy, ticket: randomUUID(), revision: policy.revision + 1, enabled: event.enabled,
        offTicket: event.enabled ? policy.offTicket : token() };
    await f.helper.command({ type: 'control_result', id: event.id, ok: true, commandID: randomUUID(),
      status: event.action === 'dangerous_auto_yes' ? 'applied' : 'queued', detail: '',
      ...(event.action === 'dangerous_auto_yes' ? { dangerousAutoYes: { ...policy } } : {}) });
    await settle();
  };
  await publish();
  const declined = command(false);
  t.mock.timers.tick(12001);
  await send(declined);
  assert.equal(f.frames.findLast(frame => frame.id === declined.id).status, 503);
  assert.equal(f.frames.findLast(frame => frame.id === declined.id).data.notDispatched, true);
  assert.equal(f.events.filter(e => e.type === 'control').length, 0);
  await publish();
  await send(declined); await ack();
  assert.equal(f.frames.findLast(frame => frame.id === declined.id).status, 200);
  const first = { id: randomUUID(), sessionID: 's', ticket: 't', action: 'queue', text: 'Synthetic' };
  for (let i = 0; i < 255; i++) { await send(i === 0 ? first : { ...first, id: randomUUID() }); await ack(); }
  await send(command(true)); await ack();
  for (let i = 0; i < 300; i++) {
    const off = command(false);
    const count = f.events.filter(e => e.type === 'control').length;
    await send(off);
    assert.equal(f.events.filter(e => e.type === 'control').length, count + 1);
    await ack();
    assert.equal(f.frames.findLast(frame => frame.id === off.id).data.dangerousAutoYes.enabled, false);
    policy = { ...policy, enabled: true, ticket: randomUUID(), revision: policy.revision + 1 };
    await publish();
  }
  const count = f.events.filter(e => e.type === 'control').length;
  await send(first);
  assert.equal(f.frames.findLast(frame => frame.id === first.id).status, 409);
  const excess = { ...first, id: randomUUID() };
  await send(excess);
  assert.equal(f.frames.findLast(frame => frame.id === excess.id).status, 429);
  await send(declined);
  assert.equal(f.frames.findLast(frame => frame.id === declined.id).status, 409);
  assert.equal(f.events.filter(e => e.type === 'control').length, count);
});

for (const changedIdentity of [false, true]) {
  test(`retired native signer ${changedIdentity ? 'rejects a changed identity' : 'recovers with the pinned identity without replay'}`, async t => {
    const processes = [], otherKey = key();
    const f = await renewalFixture(t, { wrapCrypto: base => {
      const replacement = processes.length >= 2;
      const process = {
        failed: false,
        async call(op, args) {
          if (this.failed) throw new Error('Native encrypted channel closed.');
          if (changedIdentity && replacement && op === 'identity')
            return [...Buffer.from(otherKey, 'base64url')];
          return base.call(op, args);
        },
        async close() { this.failed = true; }
      };
      processes.push(process);
      return process;
    } });
    const saved = await f.saved(), oldEpoch = f.frames.find(frame => frame.type === 'ready').epoch;
    await f.helper.command({ type: 'snapshot', total: 1, requests: [permission()] });
    await f.receive({ id: randomUUID(), epoch: oldEpoch, payload: { path: 'reply', data: {
      sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {}
    } } });
    await settle();
    assert.equal(f.events.filter(event => event.type === 'reply').length, 1);
    processes[0].failed = true;
    await f.helper.command({ type: 'offline' }); await settle();
    await f.helper.command({ type: 'heartbeat' }); await settle();
    if (changedIdentity) {
      assert.equal(f.events.findLast(e => e.type === 'status').status.state, 'error');
      assert.match(f.events.findLast(e => e.type === 'error').message, /identity changed/i);
      assert.equal(f.requests.filter(r => r.path.endsWith('/grant/finish')).length, 1);
    } else {
      assert.equal(f.requests.filter(r => r.path.endsWith('/grant/finish')).length, 2,
        'A dead signer must not leave the Mac stuck Connecting forever');
      await f.receive({ type: 'key_package', bytes: [1] });
      await f.receive({ type: 'hello' }); await settle();
      assert.equal(f.events.findLast(e => e.type === 'status').status.state, 'connected');
      assert.notEqual(f.frames.findLast(frame => frame.type === 'ready').epoch, oldEpoch);
      await assert.rejects(f.receive({ id: randomUUID(), epoch: oldEpoch,
        payload: { path: 'state', data: {} } }), /expired connection/);
    }
    assert.equal(f.events.filter(event => event.type === 'reply').length, 1);
    assert.equal(await f.saved(), saved, 'Recovery must retain the existing identity, owner and approved phones');
  });
}

test('a status poll completing during revocation does not permanently fault the helper', async t => {
  let hold = false, release;
  const f = await renewalFixture(t, { status: value => {
    if (!hold) return Response.json(value);
    return new Promise(resolve => { release = () => resolve(Response.json(value)); });
  } });
  hold = true;
  await f.helper.command({ type: 'heartbeat' });
  await until(() => release);
  const revocation = f.helper.command({ type: 'revoke', id: f.pending.deviceID });
  hold = false; release();
  await revocation;
  await settle();
  assert.equal(f.events.some(event => event.type === 'error'), false);
  await f.helper.command({ type: 'heartbeat' });
  assert.deepEqual(JSON.parse(await f.saved()).devices, []);
});

test('companion accepts +19ms clock skew and passes only local deadlines to relay and authorization', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  const skew = grant => Response.json({ ...grant, expiresAt: Date.now() + 30019, validForMs: 30000 });
  const f = await renewalFixture(t, { finish: skew, renew: skew });
  assert.equal(f.events.findLast(e => e.type === 'status').status.state, 'connected');
  t.mock.timers.tick(10000); await settle();
  assert.equal(f.signal.aborted, false);
  assert.equal(f.renewals.length, 1);
  assert.ok(f.renewals[0] <= Date.now() + 30000);
  const ready = f.frames.find(frame => frame.type === 'ready');
  await f.receive({ id: randomUUID(), epoch: ready.epoch, payload: { path: 'state', data: {} } });
  await settle();
  assert.equal(f.frames.at(-1).status, 200);
});

test('companion renewal subtracts response latency before handing off local expiry', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  let requestStart;
  const f = await renewalFixture(t, { renew: async grant => {
    requestStart = Date.now();
    t.mock.timers.setTime(requestStart + 4000);
    return Response.json({ ...grant, expiresAt: Date.now() + 5019, validForMs: 5000 });
  } });
  t.mock.timers.tick(10000); await settle();
  assert.equal(f.renewals[0], requestStart + 5000);
  const ready = f.frames.find(frame => frame.type === 'ready');
  t.mock.timers.setTime(requestStart + 5000);
  await assert.rejects(f.receive({ id: randomUUID(), epoch: ready.epoch, payload: { path: 'state', data: {} } }),
    /expired|closed/i);
  assert.equal(f.requests.filter(r => r.path.endsWith('/renew')).length, 1);
});

for (const failure of ['network', 'timeout', 'service', 'service-html']) {
  test(`wake after five minutes recovers from ${failure} failure without replacing trust or replaying actions`, async t => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
    let unavailable = false;
    const f = await renewalFixture(t, { status: value => {
      if (unavailable && failure === 'network') throw Object.assign(new Error('Network unavailable'), { code: 'ENETUNREACH' });
      if (unavailable && failure === 'timeout') throw new DOMException('Request aborted by timeout', 'AbortError');
      if (unavailable && failure === 'service-html') return new Response('<html>Service waking up</html>', { status: 503 });
      return unavailable ? Response.json({ error: 'Service unavailable' }, { status: 503 }) : Response.json(value);
    } });
    const saved = await f.saved(), oldEpoch = f.frames.find(frame => frame.type === 'ready').epoch;
    await f.helper.command({ type: 'snapshot', total: 1, requests: [permission()] });
    await f.receive({ id: randomUUID(), epoch: oldEpoch, payload: { path: 'reply', data: {
      sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {}
    } } });
    await settle();
    assert.equal(f.events.filter(event => event.type === 'reply').length, 1);
    await f.helper.command({ type: 'offline' });
    t.mock.timers.tick(300000); await settle();
    assert.equal(f.signal.aborted, true);
    unavailable = true;
    await f.helper.command({ type: 'heartbeat' }); await settle();
    assert.equal(f.events.some(event => event.type === 'error'), false, 'A wake-time network failure must not kill the native helper');
    unavailable = false;
    await f.helper.command({ type: 'heartbeat' }); await settle();
    await f.receive({ type: 'key_package', bytes: [1] });
    await f.receive({ type: 'hello' }); await settle();
    const ready = f.frames.findLast(frame => frame.type === 'ready');
    assert.notEqual(ready.epoch, oldEpoch);
    assert.equal(f.events.findLast(event => event.type === 'status').status.state, 'connected');
    assert.equal(f.events.filter(event => event.type === 'reply').length, 1, 'Unacknowledged action is never dispatched again');
    await assert.rejects(f.receive({ id: randomUUID(), epoch: oldEpoch, payload: { path: 'state', data: {} } }), /expired connection/);
    assert.equal(await f.saved(), saved, 'Wake must not re-register, change the owner, keys or trusted phones');
  });
}

test('sleep cancels the old status poll and ignores its late authorization failure after wake', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  let hold = false, release, signal;
  const f = await renewalFixture(t, { status: (value, options) => {
    if (!hold) return Response.json(value);
    signal = options.signal;
    return new Promise(resolve => { release = resolve; });
  } });
  hold = true;
  await f.helper.command({ type: 'heartbeat' }); await settle();
  await f.helper.command({ type: 'offline' });
  try {
    assert.equal(signal.aborted, true, 'Sleep must cancel pre-sleep network work');
  } finally {
    hold = false;
    await f.helper.command({ type: 'heartbeat' });
    release(Response.json({ error: 'Expired old poll' }, { status: 401 }));
    await settle();
  }
  t.mock.timers.tick(3000); await settle();
  assert.equal(f.events.findLast(event => event.type === 'status').status.state, 'connecting');
  await f.receive({ type: 'key_package', bytes: [1] });
  await f.receive({ type: 'hello' });
  assert.equal(f.events.findLast(event => event.type === 'status').status.state, 'connected');
});

test('elapsed wall-clock lease rejects a queued action before wake timers run', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: Date.now() });
  const f = await renewalFixture(t);
  const epoch = f.frames.find(frame => frame.type === 'ready').epoch;
  t.mock.timers.setTime(Date.now() + 300001);
  await assert.rejects(f.receive({ id: randomUUID(), epoch, payload: { path: 'state', data: {} } }), /expired|closed/i);
  assert.equal(f.events.some(event => event.type === 'watch'), false);
});

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
    { expiresAt: 0 }, ...[null, 0, -1, 30001, 1.5, '30000'].map(validForMs => ({ validForMs })), null
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
