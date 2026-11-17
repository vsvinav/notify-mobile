import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { once } from 'node:events';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { join } from 'node:path';
import { rm, readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { certificates } from '../src/certificates.mjs';
import { privateDirectory, stateStore } from '../src/storage.mjs';
import { createAccountService } from '../src/account-service.mjs';

const origin = 'https://accounts.notify.invalid', rpID = 'accounts.notify.invalid';
const flowCookie = '__Host-notify-account-flow', sessionCookie = '__Host-notify-account';
const b64 = value => Buffer.from(value).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();

function authenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialID = randomBytes(32);
  const cose = isoCBOR.encode(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(Buffer.from(jwk.x, 'base64url'))],
    [-3, new Uint8Array(Buffer.from(jwk.y, 'base64url'))]
  ]));
  let userHandle, counter = 0;
  function response(options, registration, extra = {}) {
    if (registration) userHandle = options.user.id;
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: registration ? 'webauthn.create' : 'webauthn.get',
      challenge: options.challenge, origin, crossOrigin: false, ...extra.clientData
    }));
    const flags = (extra.up === false ? 0 : 1) | (extra.uv === false ? 0 : 4) | (registration ? 64 : 0) |
      (extra.backupEligible ? 8 : 0) | (extra.backedUp ? 16 : 0);
    const count = Buffer.alloc(4);
    count.writeUInt32BE(extra.counter ?? (registration ? counter : ++counter));
    const length = Buffer.alloc(2); length.writeUInt16BE(credentialID.length);
    const authData = Buffer.concat([hash(extra.rpID ?? rpID), Buffer.from([flags]), count,
      ...(registration ? [Buffer.alloc(16), length, credentialID, Buffer.from(cose)] : [])]);
    const result = { id: b64(credentialID), rawId: b64(credentialID), type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64(clientDataJSON) } };
    if (registration) result.response.attestationObject = b64(isoCBOR.encode(new Map([
      ['fmt', 'none'], ['authData', new Uint8Array(authData)], ['attStmt', new Map()]
    ])));
    else Object.assign(result.response, {
      authenticatorData: b64(authData), userHandle: extra.userHandle ?? userHandle,
      signature: b64(sign('sha256', Buffer.concat([authData, hash(clientDataJSON)]), privateKey))
    });
    return result;
  }
  return { register: (options, extra) => response(options, true, extra),
    login: (options, extra) => response(options, false, extra) };
}

async function fixture(t, override = {}) {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await privateDirectory(directory);
  const tls = await certificates(directory, '127.0.0.1', true), store = override.store ?? stateStore(directory);
  let clock = 0, server, service;
  const errors = [];
  async function start() {
    server = https.createServer(tls);
    service = await createAccountService({ server, origin, store, now: () => clock,
      reportError: error => errors.push(error) });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
  }
  async function stop() {
    service.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  await start();
  t.after(async () => { await stop(); await rm(directory, { recursive: true, force: true }); });
  function browser() {
    const cookies = new Map();
    async function request(path, data = {}, headers = {}) {
      const body = typeof data === 'string' ? data : JSON.stringify(data);
      return new Promise((resolve, reject) => {
        const req = https.request({ host: '127.0.0.1', port: server.address().port,
          ca: tls.ca, rejectUnauthorized: true, servername: '', method: 'POST', path: `/v1/account/${path}`,
          headers: { host: rpID, origin, 'content-type': 'application/json',
            cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join(';'), ...headers } }, res => {
          let text = '';
          res.on('data', chunk => { text += chunk; });
          res.on('error', reject);
          res.on('end', () => {
            for (const cookie of res.headers['set-cookie'] ?? []) {
              const [pair] = cookie.split(';'), index = pair.indexOf('=');
              if (pair.slice(index + 1)) cookies.set(pair.slice(0, index), pair.slice(index + 1));
              else cookies.delete(pair.slice(0, index));
            }
            resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(text) });
          });
        });
        req.on('error', reject); req.end(body);
      });
    }
    async function register(auth = authenticator()) {
      const options = await request('register/options', { name: 'Synthetic account' });
      assert.equal(options.status, 200);
      const result = await request('register/verify', { response: auth.register(options.body) });
      assert.equal(result.status, 200);
      return { auth, result };
    }
    return { cookies, request, register };
  }
  return { browser, errors, store, directory, advance: ms => { clock += ms; },
    restart: async () => { await stop(); await start(); }, close: () => service.close() };
}

test('real passkey registration/login persist public credentials and issue account-only sessions', { timeout: 15000 }, async t => {
  const f = await fixture(t), browser = f.browser(), auth = authenticator();
  const options = await browser.request('register/options', { name: 'My Mac' });
  assert.equal(options.body.authenticatorSelection.userVerification, 'required');
  assert.equal(options.body.authenticatorSelection.residentKey, 'required');
  const created = await browser.request('register/verify', { response: auth.register(options.body) });
  assert.equal(created.status, 200);
  assert.equal(created.body.scope, 'account');
  assert.equal(created.body.account.issuer, origin);
  for (const cookie of created.headers['set-cookie']) {
    assert.match(cookie, /Secure/); assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/); assert.match(cookie, /Path=\//);
    assert.doesNotMatch(cookie, /Domain=/);
  }
  const token = browser.cookies.get(sessionCookie);
  const persisted = await readFile(join(f.directory, 'state.json'), 'utf8');
  assert.ok(persisted.includes('publicKey'));
  assert.ok(!persisted.includes(token));
  assert.doesNotMatch(persisted, /privateKey|BEGIN PRIVATE/);
  await f.restart();
  assert.equal((await browser.request('session')).status, 401);
  const login = await browser.request('login/options');
  assert.equal(login.body.userVerification, 'required');
  assert.equal(login.body.allowCredentials?.length ?? 0, 0);
  const loggedIn = await browser.request('login/verify', { response: auth.login(login.body) });
  assert.equal(loggedIn.status, 200);
  assert.deepEqual(loggedIn.body.account, created.body.account);
  assert.equal((await browser.request('session')).body.fresh, true);
  assert.equal((await browser.request('relay-grant')).status, 404);
  const oldCookie = browser.cookies.get(sessionCookie);
  assert.equal((await browser.request('logout')).status, 200);
  assert.equal((await browser.request('session', {}, { cookie: `${sessionCookie}=${oldCookie}` })).status, 401);
});

test('ceremonies bind to one browser and are consumed before failed or repeated verification', { timeout: 10000 }, async t => {
  const f = await fixture(t), a = f.browser(), b = f.browser(), auth = authenticator();
  const options = await a.request('register/options', { name: 'A' });
  const response = auth.register(options.body);
  assert.equal((await b.request('register/verify', { response })).status, 401);
  assert.equal((await a.request('register/verify', { response })).status, 200);
  assert.equal((await a.request('register/verify', { response })).status, 401);
  const login = await a.request('login/options');
  const saved = a.cookies.get(flowCookie);
  const bad = auth.login(login.body, { uv: false });
  assert.equal((await a.request('login/verify', { response: bad })).status, 401);
  const good = auth.login(login.body);
  assert.equal((await a.request('login/verify', { response: good }, { cookie: `${flowCookie}=${saved}` })).status, 401);
});

test('registration rejects missing verification, wrong origin/RP/challenge and cross-origin frames', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  for (const extra of [
    { uv: false }, { up: false }, { rpID: 'other.invalid' },
    { clientData: { origin: 'https://other.invalid' } },
    { clientData: { challenge: b64(randomBytes(32)) } },
    { clientData: { crossOrigin: true } }
  ]) {
    const browser = f.browser(), options = await browser.request('register/options', { name: 'Rejected' });
    const result = await browser.request('register/verify', { response: authenticator().register(options.body, extra) });
    assert.equal(result.status, 401, JSON.stringify(extra));
    assert.equal(browser.cookies.has(sessionCookie), false);
  }
});

test('authentication checks signatures, counter, user handle, UV and exact origin', { timeout: 10000 }, async t => {
  const f = await fixture(t), browser = f.browser(), { auth } = await browser.register();
  for (const extra of [
    { uv: false }, { up: false }, { userHandle: b64(randomBytes(32)) },
    { rpID: 'other.invalid' }, { clientData: { origin: 'https://other.invalid' } },
    { clientData: { crossOrigin: true } }, { tamper: true }
  ]) {
    const options = await browser.request('login/options');
    const response = auth.login(options.body, extra);
    if (extra.tamper) response.response.signature = b64(randomBytes(72));
    assert.equal((await browser.request('login/verify', { response })).status, 401, JSON.stringify(extra));
  }
  const first = await browser.request('login/options');
  assert.equal((await browser.request('login/verify', { response: auth.login(first.body, { counter: 20 }) })).status, 200);
  const replay = await browser.request('login/options');
  assert.equal((await browser.request('login/verify', { response: auth.login(replay.body, { counter: 20 }) })).status, 401);
});

test('two accounts cannot substitute user handles or choose another account identity', { timeout: 10000 }, async t => {
  const f = await fixture(t), a = f.browser(), b = f.browser();
  const { auth: authA, result: accountA } = await a.register();
  const { result: accountB } = await b.register();
  assert.notEqual(accountA.body.account.subject, accountB.body.account.subject);
  const options = await b.request('login/options');
  const proof = authA.login(options.body);
  const signedIn = await b.request('login/verify', { response: proof });
  assert.deepEqual(signedIn.body.account, accountA.body.account);
  const userB = (await f.store.read()).accounts.find(account => account.id === accountB.body.account.subject);
  const swapped = await b.request('login/options');
  assert.equal((await b.request('login/verify', {
    response: authA.login(swapped.body, { userHandle: userB.userID })
  })).status, 401);
  const forged = await b.request('login/options', { subject: accountB.body.account.subject });
  assert.equal(forged.status, 400);
});

test('expiry, freshness and clock rollback fail closed without trusting client clocks', { timeout: 10000 }, async t => {
  const f = await fixture(t), browser = f.browser();
  const { auth } = await browser.register();
  f.advance(300001);
  assert.equal((await browser.request('session')).body.fresh, false);
  const options = await browser.request('login/options');
  f.advance(180000);
  assert.equal((await browser.request('login/verify', { response: auth.login(options.body) })).status, 401);
  f.advance(3600000);
  assert.equal((await browser.request('session')).status, 401);
  f.advance(-1);
  assert.equal((await browser.request('login/options')).status, 503);
});

test('HTTP origin, Host, JSON size and duplicate-cookie guards reject invalid traffic', { timeout: 10000 }, async t => {
  const f = await fixture(t), browser = f.browser();
  for (const [headers, data, status] of [
    [{ origin: 'https://evil.invalid' }, {}, 403], [{ host: 'evil.invalid' }, {}, 403],
    [{ 'content-type': 'text/plain' }, {}, 415],
    [{}, 'not-json', 400], [{}, { data: 'x'.repeat(32768) }, 413],
    [{ cookie: `${flowCookie}=${b64(randomBytes(32))}; ${flowCookie}=${b64(randomBytes(32))}` }, {}, 400]
  ]) assert.equal((await browser.request('login/options', data, headers)).status, status);
  const anonymous = await browser.request('session');
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.headers['cache-control'], 'no-store');
});

test('storage failure issues no session and disables existing account access', { timeout: 10000 }, async t => {
  let saved = null, broken = false;
  const f = await fixture(t, { store: {
    read: async () => saved,
    write: async value => { if (broken) throw new Error('private disk detail'); saved = structuredClone(value); }
  } });
  const browser = f.browser(), { auth } = await browser.register();
  const options = await browser.request('login/options');
  broken = true;
  const result = await browser.request('login/verify', { response: auth.login(options.body) });
  assert.equal(result.status, 503);
  assert.equal(result.headers['set-cookie']?.some(cookie => cookie.startsWith(`${sessionCookie}=`) &&
    !cookie.startsWith(`${sessionCookie}=;`)) ?? false, false);
  assert.equal((await browser.request('session')).status, 503);
  assert.doesNotMatch(JSON.stringify(f.errors.map(error => error.message)), /private disk detail/);
});

test('shutdown during persistence cannot issue a late successful session', { timeout: 10000 }, async t => {
  let entered, release, saved = null;
  const writing = new Promise(resolve => { entered = resolve; });
  const f = await fixture(t, { store: { read: async () => saved,
    write: async value => { entered(); await new Promise(resolve => { release = resolve; }); saved = value; } } });
  const browser = f.browser(), options = await browser.request('register/options', { name: 'Pending' });
  const result = browser.request('register/verify', { response: authenticator().register(options.body) });
  await writing;
  f.close(); release();
  assert.equal((await result).status, 503);
  assert.equal(browser.cookies.has(sessionCookie), false);
});

test('account capacity is rechecked when an older registration ceremony finishes', { timeout: 10000 }, async t => {
  const f = await fixture(t);
  await f.browser().register();
  const state = await f.store.read(), sample = state.accounts[0];
  state.accounts = Array.from({ length: 255 }, () => ({
    ...sample, id: randomUUID(), userID: b64(randomBytes(32)),
    credential: { ...sample.credential, id: b64(randomBytes(32)) }
  }));
  await f.store.write(state);
  await f.restart();
  const a = f.browser(), b = f.browser();
  const first = await a.request('register/options', { name: 'Last slot' });
  const second = await b.request('register/options', { name: 'Too late' });
  assert.equal((await a.request('register/verify', { response: authenticator().register(first.body) })).status, 200);
  assert.equal((await b.request('register/verify', { response: authenticator().register(second.body) })).status, 429);
  assert.equal((await f.store.read()).accounts.length, 256);
});

test('logout immediately cancels an in-flight login rather than creating a late session', { timeout: 10000 }, async t => {
  let saved = null, hold = false, release, entered;
  const writing = new Promise(resolve => { entered = resolve; });
  const f = await fixture(t, { store: {
    read: async () => saved,
    write: async value => {
      if (hold) { entered(); await new Promise(resolve => { release = resolve; }); }
      saved = structuredClone(value);
    }
  } });
  const browser = f.browser(), { auth } = await browser.register();
  const options = await browser.request('login/options');
  hold = true;
  const signingIn = browser.request('login/verify', { response: auth.login(options.body) });
  await writing;
  const signingOut = browser.request('logout');
  try {
    const result = await Promise.race([signingOut, delay(500).then(() => null)]);
    assert.ok(result, 'Logout must not wait for the blocked login write.');
    assert.equal(result.status, 200);
  } finally {
    release();
    await Promise.allSettled([signingIn, signingOut]);
  }
  assert.equal((await signingIn).status, 401);
  assert.equal((await browser.request('session')).status, 401);
});

test('concurrent proof submissions cannot reuse a challenge or regress a signature counter', { timeout: 10000 }, async t => {
  const f = await fixture(t), a = f.browser(), b = f.browser(), { auth } = await a.register();
  const options = await a.request('login/options'), proof = auth.login(options.body);
  const results = await Promise.all([a.request('login/verify', { response: proof }),
    a.request('login/verify', { response: proof })]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 401]);
  const first = await a.request('login/options'), second = await b.request('login/options');
  const counters = await Promise.all([
    a.request('login/verify', { response: auth.login(first.body, { counter: 50 }) }),
    b.request('login/verify', { response: auth.login(second.body, { counter: 50 }) })
  ]);
  assert.deepEqual(counters.map(result => result.status).sort(), [200, 401]);
  assert.equal((await f.store.read()).accounts[0].credential.counter, 50);
});

test('synced passkeys may keep a zero counter but cannot change backup eligibility', { timeout: 10000 }, async t => {
  const f = await fixture(t), browser = f.browser(), auth = authenticator();
  const registration = await browser.request('register/options', { name: 'Synced passkey' });
  assert.equal((await browser.request('register/verify', {
    response: auth.register(registration.body, { backupEligible: true, backedUp: true, counter: 0 })
  })).status, 200);
  for (const backedUp of [false, true]) {
    const options = await browser.request('login/options');
    assert.equal((await browser.request('login/verify', {
      response: auth.login(options.body, { backupEligible: true, backedUp, counter: 0 })
    })).status, 200);
  }
  const changed = await browser.request('login/options');
  assert.equal((await browser.request('login/verify', {
    response: auth.login(changed.body, { backupEligible: false, counter: 0 })
  })).status, 401);
});

test('rate and pending ceremony limits do not trust forwarded IP claims', { timeout: 10000 }, async t => {
  const f = await fixture(t), browser = f.browser();
  for (let i = 0; i < 60; i++)
    assert.equal((await browser.request('login/options', {}, { 'x-forwarded-for': `192.0.2.${i}` })).status, 200);
  assert.equal((await browser.request('login/options')).status, 429);
  f.advance(180000);
  for (let i = 0; i < 128; i++) {
    if (i && i % 44 === 0) f.advance(60001);
    assert.equal((await f.browser().request('login/options')).status, 200);
  }
  assert.equal((await f.browser().request('login/options')).status, 429);
  f.advance(180000);
  assert.equal((await f.browser().request('login/options')).status, 200);
});

test('malformed persisted accounts are rejected without resetting the database', async () => {
  for (const accounts of [[{}], 'not-accounts', []]) {
    let writes = 0;
    await assert.rejects(createAccountService({ server: https.createServer(), origin,
      store: { read: async () => ({ version: 1, origin: accounts.length === 0 ? 'https://other.invalid' : origin, accounts }),
        write: async () => { writes++; } },
      reportError() {}
    }), /Invalid account storage/);
    assert.equal(writes, 0);
  }
});
