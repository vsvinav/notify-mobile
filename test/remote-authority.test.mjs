import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import { createRemoteAuthority } from '../src/remote-authority.mjs';

const origin = 'https://notify.example';
const prefix = 'Notify remote authorization v1\0';
function identity() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    publicKey: Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url')]).toString('base64url'),
    sign: challenge => sign('sha256', Buffer.from(prefix + challenge), privateKey).toString('base64url'),
    rawSign: challenge => sign('sha256', Buffer.from(challenge), privateKey).toString('base64url')
  };
}
const status = code => error => error.status === code;
function fixture(t) {
  let mono = 1000, wall = 1800000000000;
  const proofs = new WeakMap(), calls = [];
  const accounts = {
    authorize(req, options) {
      calls.push(options);
      const proof = proofs.get(req);
      if (!proof || proof.signal.aborted) throw Object.assign(new Error('Account required.'), { status: 401 });
      return proof;
    }
  };
  const authority = createRemoteAuthority({ origin, accounts, now: () => mono, wallNow: () => wall });
  t.after(() => authority.close());
  const account = (subject = 'account-1') => {
    const controller = new AbortController();
    const req = { headers: { origin } };
    proofs.set(req, Object.freeze({ issuer: origin, subject, signal: controller.signal }));
    return { req, controller };
  };
  const mac = () => {
    const key = identity(), macID = randomUUID();
    const challenge = authority.beginMac({ macID, publicKey: key.publicKey });
    return { key, ...authority.registerMac({ id: challenge.id, signature: key.sign(challenge.challenge) }) };
  };
  const pair = async (host, session = account()) => {
    const key = identity(), deviceID = randomUUID();
    const pending = await authority.requestPair(session.req, {
      setupID: host.setupID, deviceID, publicKey: key.publicKey, name: 'My phone'
    });
    return { key, deviceID, session, ...pending };
  };
  const grant = async (host, phone, role = 'phone') => {
    const challenge = await authority.beginGrant(phone.session.req, {
      role, macID: host.macID, deviceID: phone.deviceID,
      ...(role === 'mac' ? { credential: host.credential } : {})
    });
    return authority.finishGrant({ id: challenge.id,
      signature: (role === 'mac' ? host.key : phone.key).sign(challenge.challenge) }, phone.session.req);
  };
  const relay = (grant, options) => authority.authorizeRelay({ headers: grant.role === 'mac'
    ? { authorization: `Bearer ${grant.credential}` }
    : { origin, cookie: `__Host-notify-relay=${grant.credential}` } }, options);
  return { authority, account, mac, pair, grant, relay, calls,
    advance: ms => { mono += ms; wall += ms; },
    setMono: value => { mono = value; }, setWall: value => { wall = value; } };
}

test('signed bootstrap, account-bound pending routing and explicit local approval', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  assert.deepEqual(f.calls, [{ requireFresh: true }]);
  assert.deepEqual(phone.account, { issuer: origin, subject: 'account-1' });
  assert.equal(phone.macPublicKey, host.key.publicKey);
  let state = f.authority.macStatus(host.credential);
  assert.equal(state.account, null);
  assert.equal(state.pending.publicKey, phone.key.publicKey);
  assert.deepEqual(state.devices, []);
  const pendingGrant = await f.grant(host, phone);
  assert.equal(pendingGrant.approved, false);
  const live = f.relay(pendingGrant);
  assert.deepEqual(Object.keys(live).sort(),
    ['issuer', 'subject', 'macID', 'deviceID', 'role', 'expiresAt', 'signal'].sort());
  assert.equal(live.subject, 'account-1');
  assert.equal(live.deviceID, phone.deviceID);
  assert.equal(live.role, 'phone');
  assert.ok(pendingGrant.expiresAt <= 1800000000000 + 30000);
  f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  state = f.authority.macStatus(host.credential);
  assert.equal(state.pending, null);
  assert.deepEqual(state.account, phone.account);
  assert.equal(state.devices[0].publicKey, phone.key.publicKey);
  assert.equal((await f.grant(host, phone)).approved, true);
  const nativeGrant = await f.grant(host, phone, 'mac');
  assert.equal(f.relay(nativeGrant).role, 'mac');
  state.devices[0].publicKey = 'changed';
  assert.equal(f.authority.macStatus(host.credential).devices[0].publicKey, phone.key.publicKey);
});

test('fractional monotonic deadlines produce whole-millisecond pairing and relay expiries', async t => {
  const f = fixture(t), host = f.mac();
  f.setMono(1000.25);
  const phone = await f.pair(host);
  assert.ok(Number.isSafeInteger(phone.expiresAt), 'Pairing expiry must be an integer');
  assert.ok(phone.expiresAt <= host.expiresAt);
  f.setMono(1000 + host.expiresAt - 1800000000000 - 10000.5);
  const challenge = await f.authority.beginGrant(phone.session.req, {
    role: 'phone', macID: host.macID, deviceID: phone.deviceID
  });
  assert.equal(challenge.expiresAt, 1800000010000);
  const grant = f.authority.finishGrant({
    id: challenge.id, signature: phone.key.sign(challenge.challenge)
  }, phone.session.req);
  assert.equal(grant.expiresAt, challenge.expiresAt);
  assert.equal(f.relay(grant).expiresAt, grant.expiresAt);
});

const renewalInput = (grant, key) => ({
  id: grant.renewal.id, signature: key.sign(grant.renewal.challenge)
});

test('connected leases renew without changing authority or allowing nonce replay', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  const originalPhone = await f.grant(host, phone), originalMac = await f.grant(host, phone, 'mac');
  let phoneGrant = originalPhone, macGrant = originalMac;
  const phoneLive = f.relay(phoneGrant), macLive = f.relay(macGrant);
  for (let index = 0; index < 5; index++) {
    f.advance(10000);
    const input = renewalInput(phoneGrant, phone.key);
    const next = await f.authority.renewGrant(phone.session.req, input);
    assert.equal(next.renewal.id, phoneGrant.renewal.id);
    assert.notEqual(next.renewal.challenge, phoneGrant.renewal.challenge);
    assert.equal(next.credential, undefined, 'Renewal must not mint a reusable relay credential');
    assert.equal(next.expiresAt, 1800000000000 + (index + 1) * 10000 + 30000);
    await assert.rejects(f.authority.renewGrant(phone.session.req, input), status(401));
    phoneGrant = next;
    macGrant = await f.authority.renewGrant({ headers: {} }, renewalInput(macGrant, host.key), host.credential);
    assert.equal(phoneLive.expiresAt, phoneGrant.expiresAt);
    assert.equal(macLive.expiresAt, macGrant.expiresAt);
    assert.equal(phoneLive.signal.aborted, false);
    assert.equal(macLive.signal.aborted, false);
  }
  assert.throws(() => f.relay(originalPhone), status(409));
  assert.throws(() => f.relay(originalMac), status(409));
  phone.session.controller.abort();
  assert.equal(phoneLive.signal.aborted, true);
  assert.equal(macLive.signal.aborted, true);
});

test('renewal rejects unconnected, wrong-account, wrong-key and expired leases', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host), other = f.mac();
  const phoneGrant = await f.grant(host, phone), macGrant = await f.grant(host, phone, 'mac');
  const input = renewalInput(phoneGrant, phone.key);
  await assert.rejects(f.authority.renewGrant(phone.session.req, input), status(401));
  const live = f.relay(phoneGrant);
  f.relay(macGrant);
  await assert.rejects(f.authority.renewGrant(f.account('other').req, input), status(403));
  await assert.rejects(f.authority.renewGrant({ headers: {} }, input), status(403));
  await assert.rejects(f.authority.renewGrant(phone.session.req, renewalInput(phoneGrant, host.key)), status(401));
  await assert.rejects(f.authority.renewGrant({ headers: {} }, renewalInput(macGrant, host.key), other.credential), status(403));
  assert.equal(live.expiresAt, phoneGrant.expiresAt);
  const attempts = await Promise.allSettled([
    f.authority.renewGrant(phone.session.req, input),
    f.authority.renewGrant(phone.session.req, input)
  ]);
  assert.equal(attempts.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(attempts.filter(value => value.status === 'rejected' && value.reason.status === 401).length, 1);
  f.advance(30000);
  await assert.rejects(f.authority.renewGrant(phone.session.req, input), status(401));
  assert.equal(live.signal.aborted, true);
});

test('pending renewal cannot extend local pairing consent or survive connection revocation', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  let grant = await f.grant(host, phone);
  const live = f.relay(grant);
  for (let index = 0; index < 8; index++) {
    f.advance(20000);
    grant = await f.authority.renewGrant(phone.session.req, renewalInput(grant, phone.key));
    assert.equal(grant.approved, false);
    assert.ok(grant.expiresAt <= phone.expiresAt);
    assert.deepEqual(f.authority.macStatus(host.credential).devices, []);
  }
  f.advance(20000);
  await assert.rejects(f.authority.renewGrant(phone.session.req, renewalInput(grant, phone.key)), status(401));
  assert.equal(live.signal.aborted, true);
  const secondHost = f.mac(), second = await f.pair(secondHost);
  const secondGrant = await f.grant(secondHost, second), controller = new AbortController();
  const secondLive = f.relay(secondGrant, { signal: controller.signal });
  const renewed = await f.authority.renewGrant(second.session.req, renewalInput(secondGrant, second.key));
  controller.abort();
  assert.equal(secondLive.signal.aborted, true);
  await assert.rejects(f.authority.renewGrant(second.session.req, renewalInput(renewed, second.key)), status(401));
});

test('bootstrap rejects wrong keys, unsigned domain, replay and noncanonical keys', t => {
  const { authority } = fixture(t), key = identity(), other = identity(), macID = randomUUID();
  assert.throws(() => authority.beginMac({ macID, publicKey: key.publicKey + '=' }), status(400));
  assert.throws(() => authority.beginMac({ macID: 'not-an-id', publicKey: key.publicKey }), status(400));
  const flow = authority.beginMac({ macID, publicKey: key.publicKey });
  assert.throws(() => authority.beginMac({ macID, publicKey: other.publicKey }), status(409));
  assert.throws(() => authority.registerMac({ id: flow.id, signature: other.sign(flow.challenge) }), status(401));
  assert.throws(() => authority.registerMac({ id: flow.id, signature: key.sign(flow.challenge) }), status(401));
  const next = authority.beginMac({ macID, publicKey: key.publicKey });
  assert.throws(() => authority.registerMac({ id: next.id, signature: key.rawSign(next.challenge) }), status(401));
});

test('account JSON cannot authorize pairing, account mismatch and key replacement are refused', async t => {
  const f = fixture(t), host = f.mac(), session = f.account(), key = identity();
  await assert.rejects(f.authority.requestPair({ account: { issuer: origin, subject: 'account-1' } },
    { setupID: host.setupID, deviceID: randomUUID(), publicKey: key.publicKey, name: 'phone' }), status(401));
  const phone = await f.pair(host, session);
  await assert.rejects(f.pair(host, session), status(409));
  f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  await assert.rejects(f.pair(host, f.account('account-2')), status(403));
  await assert.rejects(f.authority.requestPair(session.req, { setupID: host.setupID,
    deviceID: phone.deviceID, publicKey: key.publicKey, name: 'renamed' }), status(409));
  await assert.rejects(f.authority.beginGrant(f.account('account-2').req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID }), status(403));
});

test('grant challenge pins role and key, consumes failed attempts and expires', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  const begin = role => f.authority.beginGrant(phone.session.req, {
    role, deviceID: phone.deviceID, macID: host.macID,
    ...(role === 'mac' ? { credential: host.credential } : {})
  });
  const wrong = await begin('phone');
  assert.throws(() => f.authority.finishGrant({ id: wrong.id,
    signature: host.key.sign(wrong.challenge) }, phone.session.req), status(401));
  assert.throws(() => f.authority.finishGrant({ id: wrong.id,
    signature: phone.key.sign(wrong.challenge) }, phone.session.req), status(401));
  const expiry = await begin('phone');
  f.advance(30000);
  assert.throws(() => f.authority.finishGrant({ id: expiry.id, signature: phone.key.sign(expiry.challenge) }), status(401));
  await assert.rejects(begin('admin'), status(400));
  await assert.rejects(f.authority.beginGrant(phone.session.req,
    { role: 'mac', macID: host.macID, deviceID: phone.deviceID }), status(401));
});

test('relay strictly separates exact-origin cookie phone and absent-origin bearer Mac', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  const p = await f.grant(host, phone), m = await f.grant(host, phone, 'mac');
  const auth = headers => f.authority.authorizeRelay({ headers });
  assert.throws(() => auth({ authorization: `Bearer ${p.credential}` }), status(403));
  assert.throws(() => auth({ origin, cookie: `__Host-notify-relay=${m.credential}` }), status(403));
  assert.throws(() => auth({ origin: 'https://evil.example', cookie: `__Host-notify-relay=${p.credential}` }), status(403));
  assert.throws(() => auth({ origin, authorization: `Bearer ${p.credential}`,
    cookie: `__Host-notify-relay=${p.credential}` }), status(400));
  assert.throws(() => auth({ origin, cookie: `__Host-notify-relay=${p.credential}; __Host-notify-relay=${p.credential}` }), status(400));
  assert.throws(() => f.authority.authorizeRelay({ headers: { authorization: `Bearer ${m.credential}` },
    rawHeaders: ['Authorization', `Bearer ${m.credential}`, 'Authorization', `Bearer ${m.credential}`] }), status(400));
  assert.throws(() => auth({ authorization: [`Bearer ${m.credential}`] }), status(400));
  assert.throws(() => auth({ authorization: `Bearer ${m.credential}=` }), status(400));
  assert.equal(f.relay(p).role, 'phone');
  assert.equal(f.relay(m).role, 'mac');
});

test('logout, rejection, revoke, lease expiry and close abort active routing', async t => {
  for (const reason of ['logout', 'reject', 'revoke', 'expiry', 'close', 'disconnect']) {
    const f = fixture(t), host = f.mac(), phone = await f.pair(host);
    const p = await f.grant(host, phone), m = await f.grant(host, phone, 'mac');
    const connection = new AbortController();
    const first = f.relay(p, { signal: connection.signal }), second = f.relay(m);
    if (reason === 'logout') phone.session.controller.abort();
    if (reason === 'reject') f.authority.decidePair(host.credential, { id: phone.id, allow: false });
    if (reason === 'revoke') f.authority.revokeDevice(host.credential, { deviceID: phone.deviceID });
    if (reason === 'expiry') { f.advance(30000); f.authority.macStatus(host.credential); }
    if (reason === 'close') f.authority.close();
    if (reason === 'disconnect') connection.abort();
    assert.equal(first.signal.aborted, true, reason);
    if (reason !== 'disconnect') assert.equal(second.signal.aborted, true, reason);
  }
});

test('expired bootstrap, unlinked Mac and candidate disappear; linked Mac persists', async t => {
  const f = fixture(t), key = identity();
  const bootstrap = f.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey });
  const host = f.mac(), linked = f.mac(), phone = await f.pair(linked);
  f.authority.decidePair(linked.credential, { id: phone.id, allow: true });
  const candidate = await f.pair(linked);
  const flow = await f.authority.beginGrant(candidate.session.req,
    { role: 'phone', macID: linked.macID, deviceID: candidate.deviceID });
  f.advance(180000);
  assert.throws(() => f.authority.registerMac({ id: bootstrap.id, signature: key.sign(bootstrap.challenge) }), status(401));
  assert.throws(() => f.authority.macStatus(host.credential), status(401));
  assert.throws(() => f.authority.finishGrant({ id: flow.id, signature: candidate.key.sign(flow.challenge) }), status(401));
  assert.equal(f.authority.macStatus(linked.credential).pending, null);
  assert.equal(f.authority.macStatus(linked.credential).devices.length, 1);
});

test('clock rollback and invalid time fail closed and abort issued authority', async t => {
  for (const change of [f => f.setMono(999), f => f.setMono(NaN),
    f => f.setWall(1799999999999), f => f.setWall(Infinity)]) {
    const f = fixture(t), host = f.mac(), phone = await f.pair(host);
    const live = f.relay(await f.grant(host, phone));
    change(f);
    assert.throws(() => f.authority.macStatus(host.credential), status(503));
    assert.equal(live.signal.aborted, true);
    f.setMono(1000); f.setWall(1800000000000);
    assert.throws(() => f.authority.macStatus(host.credential), status(503));
  }
});

test('restart never resurrects bearer credentials or enrollment state', async t => {
  const first = fixture(t), host = first.mac(), phone = await first.pair(host);
  const grant = await first.grant(host, phone);
  first.authority.close();
  const second = fixture(t);
  assert.throws(() => second.authority.macStatus(host.credential), status(401));
  assert.throws(() => second.relay(grant), status(401));
});

test('bounded bootstraps, Macs, devices, challenges and leases reject overload', async t => {
  const boot = fixture(t), key = identity();
  for (let n = 0; n < 128; n++) boot.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey });
  assert.throws(() => boot.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey }), status(429));
  boot.advance(180000);
  assert.ok(boot.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey }).id);
  const macs = fixture(t);
  for (let n = 0; n < 64; n++) macs.mac();
  assert.throws(() => macs.mac(), status(429));
  const f = fixture(t), host = f.mac();
  let phone;
  for (let n = 0; n < 8; n++) {
    phone = await f.pair(host);
    f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  }
  await assert.rejects(f.pair(host), status(429));
  for (let n = 0; n < 256; n++) await f.grant(host, phone);
  await assert.rejects(f.grant(host, phone), status(429));
  f.advance(30000);
  for (let n = 0; n < 128; n++) await f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
  await assert.rejects(f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID }), status(429));
});

test('successful challenges cannot replay and setup locators never authorize a Mac', async t => {
  const f = fixture(t), key = identity();
  const bootstrap = f.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey });
  const host = { key, ...f.authority.registerMac({ id: bootstrap.id, signature: key.sign(bootstrap.challenge) }) };
  assert.throws(() => f.authority.registerMac({ id: bootstrap.id, signature: key.sign(bootstrap.challenge) }), status(401));
  assert.throws(() => f.authority.macStatus(host.setupID), status(401));
  const phone = await f.pair(host);
  const challenge = await f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
  const payload = JSON.parse(challenge.challenge);
  assert.equal(payload.purpose, 'grant');
  assert.equal(payload.origin, origin);
  assert.equal(payload.role, 'phone');
  assert.equal(payload.macID, host.macID);
  assert.equal(payload.deviceID, phone.deviceID);
  assert.equal(Buffer.from(payload.challenge, 'base64url').length, 32);
  assert.throws(() => f.authority.finishGrant({
    id: challenge.id, signature: phone.key.sign(challenge.challenge), role: 'mac'
  }), status(400));
  const grant = f.authority.finishGrant({
    id: challenge.id, signature: phone.key.sign(challenge.challenge)
  }, phone.session.req);
  assert.throws(() => f.authority.finishGrant({ id: challenge.id,
    signature: phone.key.sign(challenge.challenge) }), status(401));
  f.relay(grant);
  assert.throws(() => f.relay(grant), status(409));
});

test('approved devices survive logout but their old proof and issued challenges do not', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  const challenge = await f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
  const live = f.relay(await f.grant(host, phone, 'mac'));
  phone.session.controller.abort();
  assert.equal(live.signal.aborted, true);
  assert.throws(() => f.authority.finishGrant({ id: challenge.id,
    signature: phone.key.sign(challenge.challenge) }), status(401));
  assert.equal(f.authority.macStatus(host.credential).devices.length, 1);
  await assert.rejects(f.grant(host, phone, 'mac'), status(401));
  phone.session = f.account();
  assert.equal((await f.grant(host, phone)).approved, true);
  assert.equal((await f.grant(host, phone, 'mac')).approved, true);
});

test('revoke/new approval cannot resurrect grants pinned to the former device key', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  f.authority.decidePair(host.credential, { id: phone.id, allow: true });
  const challenge = await f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
  const oldGrant = await f.grant(host, phone);
  f.authority.revokeDevice(host.credential, { deviceID: phone.deviceID });
  const replacement = identity();
  const pending = await f.authority.requestPair(phone.session.req, {
    setupID: host.setupID, deviceID: phone.deviceID, publicKey: replacement.publicKey, name: 'Same name'
  });
  f.authority.decidePair(host.credential, { id: pending.id, allow: true });
  assert.throws(() => f.relay(oldGrant), status(401));
  assert.throws(() => f.authority.finishGrant({ id: challenge.id,
    signature: phone.key.sign(challenge.challenge) }), status(401));
  await assert.rejects(f.grant(host, phone), status(401));
  phone.key = replacement;
  assert.equal((await f.grant(host, phone)).approved, true);
});

test('scheduled expiry aborts routing without a subsequent request', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  const live = f.relay(await f.grant(host, phone));
  f.advance(30000);
  t.mock.timers.tick(30000);
  assert.equal(live.signal.aborted, true);
});

test('an unrelated logout cannot postpone another connection lease deadline', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), first = f.mac(), second = f.mac();
  const phone = await f.pair(first), other = await f.pair(second);
  const live = f.relay(await f.grant(first, phone));
  f.advance(20000);
  t.mock.timers.tick(20000);
  other.session.controller.abort();
  f.advance(10000);
  t.mock.timers.tick(10000);
  assert.equal(live.signal.aborted, true);
});

test('invalid curve points and malformed DER do not become enrolled identities', t => {
  const f = fixture(t), invalid = Buffer.alloc(65);
  invalid[0] = 4;
  assert.throws(() => f.authority.beginMac({ macID: randomUUID(),
    publicKey: invalid.toString('base64url') }), status(400));
  const key = identity(), challenge = f.authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey });
  assert.throws(() => f.authority.registerMac({
    id: challenge.id, signature: Buffer.alloc(64).toString('base64url')
  }), status(401));
});

test('a delayed account proof cannot enroll after expiry or close, and concurrency is bounded', async t => {
  let resolve;
  const pending = new Promise(done => { resolve = done; });
  let clock = 1000;
  const session = new AbortController(), key = identity();
  const authority = createRemoteAuthority({ origin, accounts: { authorize: () => pending },
    now: () => clock, wallNow: () => 1800000000000 });
  t.after(() => authority.close());
  const challenge = authority.beginMac({ macID: randomUUID(), publicKey: key.publicKey });
  const host = authority.registerMac({ id: challenge.id, signature: key.sign(challenge.challenge) });
  const request = () => authority.requestPair({}, {
    setupID: host.setupID, deviceID: randomUUID(), publicKey: key.publicKey, name: 'Phone'
  });
  const requests = Array.from({ length: 128 }, () => request());
  await assert.rejects(request(), status(429));
  clock += 180000;
  resolve(Object.freeze({ issuer: origin, subject: 'account-1', signal: session.signal }));
  await Promise.all(requests.map(result => assert.rejects(result, status(401))));
  authority.close();
  await assert.rejects(request(), status(503));
});

test('phone finish requires an exact-origin actual account proof before consuming its challenge', async t => {
  const f = fixture(t), host = f.mac(), phone = await f.pair(host);
  const challenge = await f.authority.beginGrant(phone.session.req,
    { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
  const input = { id: challenge.id, signature: phone.key.sign(challenge.challenge) };
  assert.throws(() => f.authority.finishGrant(input), status(403));
  assert.throws(() => f.authority.finishGrant(input, {
    headers: { origin }, account: { issuer: origin, subject: 'account-1' }
  }), status(401));
  assert.throws(() => f.authority.finishGrant(input, f.account('account-2').req), status(403));
  const wrongOrigin = f.account();
  wrongOrigin.req.headers.origin = 'https://other.example';
  assert.throws(() => f.authority.finishGrant(input, wrongOrigin.req), status(403));
  const grant = f.authority.finishGrant(input, phone.session.req);
  assert.equal(f.relay(grant).subject, 'account-1');
  assert.deepEqual(f.calls.at(-1), { requireFresh: false });
});

test('phone grants bind both begin and finish account session revocation', async t => {
  for (const sessionToAbort of ['begin', 'finish']) {
    const f = fixture(t), host = f.mac(), phone = await f.pair(host);
    f.authority.decidePair(host.credential, { id: phone.id, allow: true });
    const finishing = f.account();
    const challenge = await f.authority.beginGrant(phone.session.req,
      { role: 'phone', macID: host.macID, deviceID: phone.deviceID });
    const grant = f.authority.finishGrant({
      id: challenge.id, signature: phone.key.sign(challenge.challenge)
    }, finishing.req);
    const live = f.relay(grant);
    (sessionToAbort === 'begin' ? phone.session : finishing).controller.abort();
    assert.equal(live.signal.aborted, true, sessionToAbort);
  }
});
