import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createRemoteAuthority } from '../src/remote-authority.mjs';
import { createRemoteCompanion } from '../src/remote-companion.mjs';

const origin = 'https://notify.example';
const nativeProposal = p => ({ ...p, publicKey: Buffer.from(p.publicKey, 'base64url').toString('base64'),
  macPublicKey: Buffer.from(p.macPublicKey, 'base64url').toString('base64') });
function identity() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    publicKey: Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64url'),
    sign: challenge => sign('sha256', Buffer.from('Notify remote authorization v1\0' + challenge), privateKey).toString('base64url')
  };
}
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };

async function fixture(t, { signed = true, remembered = false, mutate = (_path, value) => value,
  hold = async () => {}, skew = 0 } = {}) {
  const directory = join(process.cwd(), '.test-data', 'remember-' + randomUUID());
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const mac = identity(), phone = identity(), macID = randomUUID(), deviceID = randomUUID();
  const account = { issuer: origin, subject: 'synthetic-owner' }, controller = new AbortController();
  const req = { headers: { origin } };
  const authority = createRemoteAuthority({ origin, wallNow: () => Date.now() + skew, accounts: { authorize: async () => {
    if (controller.signal.aborted) throw Object.assign(Error('Account expired'), { status: 401 });
    return { ...account, signal: controller.signal };
  } } });
  const begin = authority.beginMac({ macID, publicKey: mac.publicKey });
  const registration = authority.registerMac({ id: begin.id, signature: mac.sign(begin.challenge) });
  const pair = await authority.requestPair(req, { setupID: registration.setupID, deviceID, publicKey: phone.publicKey, name: 'Fictional phone' });
  await authority.decidePair(registration.credential, { id: pair.id, allow: true });
  async function propose() {
    const flow = await authority.beginRemember(req, { macID, deviceID, optIn: true });
    return authority.finishRemember(req, { id: flow.id, signature: phone.sign(flow.challenge) });
  }
  let proposal;
  if (signed) proposal = await propose();
  if (remembered) {
    await authority.decideRemember(registration.credential, { id: proposal.id, allow: true });
    controller.abort();
  }
  const saved = { version: 1, origin, macID, publicKey: mac.publicKey, owner: account,
    devices: [{ id: deviceID, name: 'Fictional phone', publicKey: phone.publicKey }],
    credential: registration.credential, setupID: registration.setupID };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  const events = [], calls = [], signedProofs = [], relays = [];
  let loseDecision = false, helper;
  const options = {
    directory, origin, emit: e => events.push(e),
    cryptoProcess: () => ({
      async call(op, args) {
        if (op === 'identity') return [...Buffer.from(mac.publicKey, 'base64url')];
        if (op === 'sign') {
          const raw = Buffer.from(args.bytes).toString();
          signedProofs.push(raw);
          return [...Buffer.from(mac.sign(raw), 'base64url')];
        }
        throw Error(`Unexpected crypto operation ${op}`);
      }, async close() {}
    }),
    fetchRequest: async (url, options) => {
      const path = url.split('/v1/remote/')[1], input = JSON.parse(options.body);
      const credential = options.headers.Authorization?.slice(7);
      calls.push({ path, input });
      try {
        let result;
        if (path === 'mac/status') result = authority.macStatus(credential);
        else if (path === 'mac/remember/decision') {
          result = await authority.decideRemember(credential, input);
          if (loseDecision) throw Object.assign(Error('Lost acknowledgement'), { code: 'ECONNRESET' });
        } else if (path === 'grant/begin') result = await authority.beginGrant({}, { ...input, credential });
        else if (path === 'grant/finish') result = authority.finishGrant(input);
        else if (path === 'grant/renew') result = await authority.renewGrant({}, input, credential);
        else if (path === 'mac/revoke') result = authority.revokeDevice(credential, input);
        else throw Error(`Unexpected route ${path}`);
        await hold(path, input, result);
        return Response.json(mutate(path, structuredClone(result)));
      } catch (error) {
        if (!error.status) throw error;
        return Response.json({ error: error.message }, { status: error.status });
      }
    },
    connectRelay: async ({ credential, signal, onOpen }) => {
      const handle = authority.authorizeRelay({ headers: { authorization: `Bearer ${credential}` } });
      let finish;
      const closed = new Promise(resolve => { finish = resolve; });
      signal.addEventListener('abort', finish, { once: true });
      handle.signal.addEventListener('abort', finish, { once: true });
      const relay = { signal: handle.signal, closed, close: finish, send: async () => {}, renew() {} };
      relays.push({ signal, relay }); onOpen(relay); return relay;
    }
  };
  helper = await createRemoteCompanion(options);
  t.after(async () => { await helper.close(); authority.close(); await rm(directory, { recursive: true }); });
  await settle();
  return { authority, events, calls, saved, proposal, propose, signedProofs, relays, directory,
    get helper() { return helper; },
    status: () => events.findLast(e => e.type === 'status').status,
    poll: async () => { await helper.command({ type: 'heartbeat' }); await settle(); },
    lose: () => { loseDecision = true; },
    restart: async () => { await helper.close(); helper = await createRemoteCompanion(options); await settle(); },
    decision: (allow, p = nativeProposal(proposal), requestID = randomUUID()) =>
      helper.command({ type: 'remember-decision', requestID, proposal: p, allow })
  };
}

test('signed remembered consent is separate from pairing, attention and local trusted keys', async t => {
  const f = await fixture(t);
  assert.deepEqual(f.status().rememberPending, nativeProposal(f.proposal));
  assert.deepEqual(f.status().pendingPairingIDs, []);
  assert.equal(f.events.some(e => e.type === 'pairing'), false);
  assert.equal(f.calls.some(c => c.path === 'mac/attention'), false);
  assert.equal(f.status().devices[0].remembered, undefined);
  await f.decision(true);
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'approved');
  assert.deepEqual(f.calls.find(c => c.path === 'mac/remember/decision').input, { id: f.proposal.id, allow: true });
  await f.poll();
  assert.equal(f.status().devices[0].remembered.generation, f.proposal.generation);
  assert.deepEqual(JSON.parse(await readFile(join(f.directory, 'identity.json'))), f.saved);
});

test('denying a new proposal preserves an older committed authorization', async t => {
  const f = await fixture(t);
  await f.decision(true); await f.poll();
  const next = await f.propose(); await f.poll();
  await f.decision(false, nativeProposal(next)); await f.poll();
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'denied');
  assert.equal(f.status().devices[0].remembered.generation, f.proposal.generation);
  assert.equal(f.status().rememberPending, null);
});

test('changed displayed proposal context is rejected before HTTP mutation', async t => {
  const f = await fixture(t);
  for (const change of [
    { id: 'A'.repeat(43) }, { generation: 'A'.repeat(43) }, { deviceID: randomUUID() },
    { publicKey: nativeProposal({ ...f.proposal, publicKey: identity().publicKey }).publicKey },
    { macPublicKey: nativeProposal({ ...f.proposal, macPublicKey: identity().publicKey }).macPublicKey },
    { expiresAt: f.proposal.expiresAt + 1 }, { authorizationExpiresAt: f.proposal.authorizationExpiresAt + 1 },
    { account: { issuer: origin, subject: 'other' } }, { name: 'Other phone' }
  ]) {
    await f.decision(true, { ...nativeProposal(f.proposal), ...change });
    assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'error');
  }
  assert.equal(f.calls.filter(c => c.path === 'mac/remember/decision').length, 0);
});

test('lost remember ACK reconciles exact committed generation without mutation replay, including helper restart', async t => {
  const f = await fixture(t); f.lose();
  await f.decision(true);
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'unknown');
  await f.poll();
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'approved');
  await f.restart();
  assert.equal(f.status().devices[0].remembered.generation, f.proposal.generation);
  assert.equal(f.calls.filter(c => c.path === 'mac/remember/decision').length, 1);
});

test('remembered Mac proof is signed exactly and pins both identities and committed generation', async t => {
  const f = await fixture(t, { remembered: true });
  assert.equal(f.relays.length, 1);
  const proof = JSON.parse(f.signedProofs[0]);
  assert.equal(proof.purpose, 'remember-mac-grant');
  assert.equal(proof.generation, f.proposal.generation);
  assert.equal(proof.publicKey, f.saved.devices[0].publicKey);
  assert.equal(proof.macPublicKey, f.saved.publicKey);
});

for (const [name, change] of Object.entries({
  generation: { generation: 'A'.repeat(43) }, authorization: { authorizationExpiresAt: 9999999999999 },
  role: { role: 'phone' }, purpose: { purpose: 'remember-enable' }, operation: { operation: 'enable' },
  version: { version: 2 }, scope: { scope: 'account' }, origin: { origin: 'https://wrong.example' },
  owner: { account: { issuer: origin, subject: 'wrong' } }, phoneID: { deviceID: randomUUID() },
  macID: { macID: randomUUID() }, nonce: { challenge: 'wrong' }, unknown: { unexpected: true },
  phoneKey: { publicKey: identity().publicKey }, macKey: { macPublicKey: identity().publicKey },
  expires: { challengeExpiresAt: 1 }
})) {
  test(`remembered grant ${name} tampering fails before signer invocation`, async t => {
    const f = await fixture(t, { remembered: true, mutate: (path, value) => path === 'grant/begin'
      ? { ...value, challenge: JSON.stringify({ ...JSON.parse(value.challenge), ...change }) } : value });
    assert.equal(f.signedProofs.length, 0);
    assert.equal(f.relays.length, 0);
  });
}

test('unsigned proposals and old-server absent metadata never become remembered consent', async t => {
  const f = await fixture(t, { signed: false, mutate: (path, value) => {
    if (path === 'mac/status') delete value.rememberPending;
    return value;
  } });
  assert.equal(f.status().rememberPending, null);
  assert.equal(f.status().devices[0].remembered, undefined);
  assert.equal(f.events.some(e => e.type === 'remember-result'), false);
});

test('a signed proposal tolerates small server clock skew', async t => {
  const f = await fixture(t, { skew: 19 });
  assert.deepEqual(f.status().rememberPending, nativeProposal(f.proposal));
  await f.decision(false);
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'denied');
});

test('repeated or stale status cannot extend a remembered proposal past the local three-minute bound', async t => {
  let mono = 0, snapshot;
  t.mock.method(performance, 'now', () => mono);
  const f = await fixture(t, { skew: 60000, mutate: (path, value) => {
    if (path !== 'mac/status') return value;
    snapshot ??= structuredClone(value);
    return structuredClone(snapshot);
  } });
  mono = 179000; await f.poll();
  assert.equal(f.status().rememberPending.id, f.proposal.id);
  mono = 180001; await f.poll();
  assert.equal(f.status().rememberPending, null);
  await f.decision(true);
  assert.equal(f.calls.filter(c => c.path === 'mac/remember/decision').length, 0);
});

for (const change of [
  p => { p.account.subject = 'other'; }, p => { p.macID = randomUUID(); },
  p => { p.macPublicKey = identity().publicKey; }, p => { p.publicKey = identity().publicKey; },
  p => { p.generation = 'bad'; }, p => { p.extra = true; }, p => { p.expiresAt = 'soon'; }
]) {
  test('malformed remembered status is never projected as a valid prompt', async t => {
    const f = await fixture(t, { mutate: (path, value) => {
      if (path === 'mac/status') change(value.rememberPending);
      return value;
    } });
    assert.equal(f.status().state, 'error');
    assert.equal(f.events.some(e => e.status?.rememberPending != null), false);
  });
}

test('a cancelled or expired proposal rejects the old displayed decision without a mutation', async t => {
  const f = await fixture(t);
  await f.authority.decideRemember(f.saved.credential, { id: f.proposal.id, allow: false });
  await f.decision(true);
  assert.equal(f.events.findLast(e => e.type === 'remember-result')?.outcome, 'error');
  assert.equal(f.calls.filter(c => c.path === 'mac/remember/decision').length, 0);
});

test('a status poll started before a decision cannot restore its old proposal after ACK', async t => {
  let release, armed = false, held = false;
  const f = await fixture(t, { hold: async path => {
    if (armed && !held && path === 'mac/status') {
      held = true;
      await new Promise(resolve => { release = resolve; });
    }
  } });
  armed = true;
  await f.helper.command({ type: 'heartbeat' }); await settle();
  assert.ok(release);
  await f.decision(true);
  release(); await settle();
  assert.equal(f.status().rememberPending, null);
});

test('a remembered status response racing local device revoke is discarded, not adopted or fatal', async t => {
  let release, armed = false;
  const f = await fixture(t, { remembered: true, hold: async path => {
    if (armed && path === 'mac/status') await new Promise(resolve => { release = resolve; });
  } });
  armed = true;
  await f.helper.command({ type: 'heartbeat' }); await settle();
  assert.ok(release);
  await f.helper.command({ type: 'revoke', id: f.saved.devices[0].id });
  release(); await settle();
  assert.notEqual(f.status().state, 'error');
  assert.deepEqual(f.status().devices, []);
});

test('a generation cannot slide its committed authorization expiry on a later status', async t => {
  let change = false;
  const f = await fixture(t, { remembered: true, mutate: (path, value) => {
    if (change && path === 'mac/status') value.devices[0].remembered.authorizationExpiresAt++;
    return value;
  } });
  change = true; await f.poll();
  assert.equal(f.status().state, 'error');
  assert.equal(f.relays[0].signal.aborted, true);
});

test('remembered Mac renews through actual authority with a +19ms server clock and keeps exact G/E', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = await fixture(t, { remembered: true, skew: 19 });
  assert.equal(f.relays.length, 1);
  t.mock.timers.tick(10000); await settle();
  assert.equal(f.calls.filter(c => c.path === 'grant/renew').length, 1);
  assert.equal(f.relays[0].signal.aborted, false);
  assert.equal(JSON.parse(f.signedProofs[1]).purpose, 'remember-renew');
  assert.equal(JSON.parse(f.signedProofs[1]).generation, f.proposal.generation);
});

for (const change of [
  { scope: 'account' }, { generation: 'A'.repeat(43) }, { authorizationExpiresAt: 1 },
  { connectionID: 'A'.repeat(43) }, { challengeExpiresAt: 1 }, { role: 'phone' },
  { publicKey: identity().publicKey }, { macPublicKey: identity().publicKey },
  { account: { issuer: origin, subject: 'wrong' } }, { purpose: 'remember-mac-grant' },
  { operation: 'grant' }, { version: 2 }, { origin: 'https://wrong.example' }, { challenge: 'bad' }
]) {
  test('tampered remembered renewal is rejected before that proof reaches the signer', async t => {
    t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const f = await fixture(t, { remembered: true, mutate: (path, value) => {
      if (path === 'grant/finish') value.renewal.challenge = JSON.stringify({ ...JSON.parse(value.renewal.challenge), ...change });
      return value;
    } });
    t.mock.timers.tick(10000); await settle();
    assert.equal(f.signedProofs.length, 1, 'Only the initial valid grant proof may be signed');
    assert.equal(f.calls.filter(c => c.path === 'grant/renew').length, 0);
    assert.equal(f.relays.length, 0);
  });
}

for (const change of [{ scope: 'account' }, { generation: 'A'.repeat(43) }, { validForMs: 30001 },
  { authorizationExpiresAt: 9999999999999 }]) {
  test('remembered lease response cannot change scope, generation or lifetime on renewal', async t => {
    t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const f = await fixture(t, { remembered: true, mutate: (path, value) =>
      path === 'grant/renew' ? { ...value, ...change } : value });
    t.mock.timers.tick(10000); await settle();
    assert.equal(f.calls.filter(c => c.path === 'grant/renew').length, 1);
    assert.equal(f.relays[0].signal.aborted, true);
    assert.match(f.status().message, /Remembered connection stopped/);
    t.mock.timers.tick(10000); await settle();
    assert.equal(f.calls.filter(c => c.path === 'grant/renew').length, 1, 'No consumed renewal nonce replay');
  });
}

test('server revocation aborts remembered Mac channels without changing local paired keys', async t => {
  const f = await fixture(t, { remembered: true });
  await f.authority.revokeDevice(f.saved.credential, { deviceID: f.saved.devices[0].id });
  await f.poll();
  assert.equal(f.relays[0].signal.aborted, true);
  assert.equal(f.status().devices[0].remembered, undefined);
  assert.deepEqual(JSON.parse(await readFile(join(f.directory, 'identity.json'))), f.saved);
});

test('absolute remembered expiry closes the channel and projects Expired without sliding consent', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = await fixture(t, { remembered: true });
  t.mock.timers.tick(30 * 86400000 + 1); await settle(); await f.poll();
  assert.equal(f.relays[0].signal.aborted, true);
  assert.equal(f.status().devices[0].remembered.state, 'expired');
  assert.equal(f.status().devices[0].remembered.authorizationExpiresAt, f.proposal.authorizationExpiresAt);
  assert.equal(f.signedProofs.length, 1);
});

test('elapsed remembered grant flow is rejected before signing even when both raw expiry fields match', async t => {
  const f = await fixture(t, { remembered: true, mutate: (path, value) => {
    if (path === 'grant/begin') {
      value.expiresAt = Date.now() - 1;
      value.challenge = JSON.stringify({ ...JSON.parse(value.challenge), challengeExpiresAt: value.expiresAt });
    }
    return value;
  } });
  assert.equal(f.signedProofs.length, 0);
});

for (const raw of ['{broken remembered JSON', 'null', '[]', '{"purpose":"grant","challenge":"A"}']) {
  test('known remembered device cannot turn malformed JSON into an opaque account signing request', async t => {
    const f = await fixture(t, { remembered: true, mutate: (path, value) =>
      path === 'grant/begin' ? { ...value, challenge: raw } : value });
    assert.equal(f.signedProofs.length, 0);
  });
}

test('malformed real remembered producer proof is never signed when cached metadata is absent', async t => {
  const producer = JSON.parse(await readFile(new URL('./fixtures/remembered-mac-producer.json', import.meta.url)));
  const f = await fixture(t, { remembered: true, mutate: (path, value) => {
    if (path === 'mac/status') delete value.devices[0].remembered;
    if (path === 'grant/begin') value.challenge = producer.macGrantBegin.response.challenge.slice(0, -1);
    return value;
  } });
  assert.equal(f.status().devices[0].remembered, undefined);
  assert.equal(f.signedProofs.length, 0, 'Malformed JSON must not fall through to an opaque account signer');
});

for (const raw of ['opaque legacy-looking challenge', 'null', '[]', '{"purpose":"grant","challenge":"A"}']) {
  test('unsupported account proof format is rejected independently of remembered metadata', async t => {
    const f = await fixture(t, { signed: false, mutate: (path, value) =>
      path === 'grant/begin' ? { ...value, challenge: raw } : value });
    assert.equal(f.signedProofs.length, 0);
  });
}

test('an existing account lease stays account-scoped when new remembered consent commits', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = await fixture(t);
  assert.equal(f.relays.length, 1);
  await f.decision(true); await f.poll();
  t.mock.timers.tick(10000); await settle();
  assert.equal(f.calls.filter(c => c.path === 'grant/renew').length, 1);
  assert.equal(JSON.parse(f.signedProofs[1]).purpose, 'renew');
  assert.equal(f.relays[0].signal.aborted, false);
});

test('stop drains an uncertain remember decision and never emits a late result or replays it', async t => {
  let release;
  const f = await fixture(t, { hold: async path => {
    if (path === 'mac/remember/decision') await new Promise(resolve => { release = resolve; });
  } });
  const decision = f.decision(true);
  await settle(); assert.ok(release);
  let closed = false;
  const closing = f.helper.close().then(() => { closed = true; });
  await settle();
  assert.equal(closed, false, 'Close must drain in-flight remembered mutation work');
  const count = f.events.length;
  release(); await decision; await closing;
  assert.equal(f.events.length, count);
  await f.restart();
  assert.equal(f.status().devices[0].remembered.generation, f.proposal.generation);
  assert.equal(f.calls.filter(c => c.path === 'mac/remember/decision').length, 1);
});

test('frozen producer challenge bytes pass unchanged through the native signing boundary', async t => {
  const producer = JSON.parse(await readFile(new URL('./fixtures/remembered-mac-producer.json', import.meta.url)));
  t.mock.timers.enable({ apis: ['Date'], now: producer.now });
  const directory = join(process.cwd(), '.test-data', 'remember-producer-' + randomUUID());
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const p = producer.macPendingStatus.rememberPending;
  const saved = { version: 1, origin, macID: p.macID, publicKey: p.macPublicKey, owner: p.account,
    devices: [{ id: p.deviceID, publicKey: p.publicKey, name: p.name }], credential: 'A'.repeat(43), setupID: 'fixture' };
  await writeFile(join(directory, 'identity.json'), JSON.stringify(saved), { mode: 0o600 });
  const raw = [], status = structuredClone(producer.macPendingStatus);
  status.rememberPending = null;
  status.devices[0].remembered = { generation: p.generation, authorizationExpiresAt: p.authorizationExpiresAt, state: 'active' };
  const helper = await createRemoteCompanion({
    directory, origin, emit() {},
    cryptoProcess: () => ({
      async call(op, args) {
        if (op === 'identity') return [...Buffer.from(saved.publicKey, 'base64url')];
        assert.equal(op, 'sign'); raw.push(Buffer.from(args.bytes).toString()); return [1];
      }, async close() {}
    }),
    fetchRequest: async url => {
      if (url.endsWith('/mac/status')) return Response.json(status);
      if (url.endsWith('/grant/begin')) return Response.json(producer.macGrantBegin.response);
      return Response.json({ error: 'No synthetic private producer key retained' }, { status: 401 });
    }
  });
  t.after(async () => { await helper.close(); await rm(directory, { recursive: true }); });
  await settle();
  assert.deepEqual(raw, [producer.macGrantBegin.response.challenge]);
});
