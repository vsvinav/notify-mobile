import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHostedService } from '../src/hosted-main.mjs';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import WebSocket from 'ws';

const hostname = 'notify-test.onrender.com', origin = `https://${hostname}`;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';

function deviceKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return { publicKey: Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url')]).toString('base64url'),
  finish: flow => ({ id: flow.id, signature: sign('sha256', Buffer.concat([
    Buffer.from('Notify remote authorization v1\0'), Buffer.from(flow.challenge)]), privateKey).toString('base64url') }) };
}

async function registerAccount(app) {
  const options = await app.request('/v1/account/register/options', { body: { name: 'Hosted account' }, headers: { origin } });
  assert.equal(options.status, 200);
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' }), credential = randomBytes(32);
  const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x, 'base64url'))], [-3, new Uint8Array(Buffer.from(jwk.y, 'base64url'))]]));
  const size = Buffer.alloc(2); size.writeUInt16BE(credential.length);
  const authData = Buffer.concat([createHash('sha256').update(hostname).digest(),
    Buffer.from([69]), Buffer.alloc(4), Buffer.alloc(16), size, credential, Buffer.from(cose)]);
  const response = { id: credential.toString('base64url'), rawId: credential.toString('base64url'),
    type: 'public-key', clientExtensionResults: {}, response: {
      clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.json().challenge,
        origin, crossOrigin: false })).toString('base64url'),
      attestationObject: Buffer.from(isoCBOR.encode(new Map([['fmt', 'none'],
        ['authData', new Uint8Array(authData)], ['attStmt', new Map()]]))).toString('base64url') } };
  const verified = await app.request('/v1/account/register/verify', { body: { response }, headers: {
    origin, cookie: options.headers['set-cookie'].map(value => value.split(';')[0]).join('; ') } });
  assert.equal(verified.status, 200);
  return verified.headers['set-cookie'].filter(value => !value.includes('Max-Age=0'))
    .map(value => value.split(';')[0]).join('; ');
}

async function fixture(t) {
  const previous = { RENDER: process.env.RENDER, RENDER_EXTERNAL_HOSTNAME: process.env.RENDER_EXTERNAL_HOSTNAME };
  process.env.RENDER = 'true';
  process.env.RENDER_EXTERNAL_HOSTNAME = hostname;
  const directory = resolve('.test-data', `hosted-${randomUUID()}`);
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'remote.html'), '<!doctype html><title>Remote</title>');
  await writeFile(resolve(directory, 'remote-app.mjs'), 'export const remote = true;');
  await writeFile(resolve(directory, 'icon-192.png'), Buffer.from([137, 80, 78, 71]));
  await mkdir(resolve(directory, 'remote-crypto'));
  await writeFile(resolve(directory, 'remote-crypto/LICENSES.txt'), 'Dependency notices fixture');
  const errors = [];
  const app = await createHostedService({ origin, managedIngress: 'render-free',
    publicDirectory: directory, store: { read: async () => null, write: async () => {} },
    reportError: error => errors.push(error.message) });
  app.server.listen(0, '127.0.0.1');
  await once(app.server, 'listening');
  t.after(async () => {
    await app.close();
    await rm(directory, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  function request(path, { body, method = body === undefined ? 'GET' : 'POST', headers = {}, chunks } = {}) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
      const req = http.request({ hostname: '127.0.0.1', port: app.server.address().port, path, method,
        headers: { host: hostname, 'x-forwarded-proto': 'https',
          ...(data === undefined ? {} : { 'content-type': 'application/json' }), ...headers } }, res => {
        let text = '';
        res.on('data', chunk => { text += chunk; });
        res.on('error', reject);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text,
          json: () => JSON.parse(text) }));
      });
      req.on('error', reject);
      if (chunks) {
        for (const chunk of chunks) req.write(chunk);
        req.end();
      } else req.end(data);
    });
  }
  return { ...app, request, errors };
}

test('hosted factory never enables plaintext ingress by default', async () => {
  await assert.rejects(createHostedService({ origin,
    store: { read: async () => null, write: async () => {} }, reportError() {} }), /HTTPS|ingress/);
});

test('managed hosting rejects configuration mismatches before reading account storage', async t => {
  await fixture(t);
  let reads = 0;
  const store = { read: async () => { reads++; return null; }, write: async () => {} };
  await assert.rejects(createHostedService({ origin: 'https://wrong.onrender.com',
    managedIngress: 'render-free', store }), /exact HTTPS/);
  await assert.rejects(createHostedService({ origin: `${origin}/`,
    managedIngress: 'render-free', store }), /exact HTTPS/);
  process.env.RENDER = 'false';
  await assert.rejects(createHostedService({ origin, managedIngress: 'render-free', store }), /Render Free/);
  assert.equal(reads, 0);
});

test('unexpected storage failures are reported without request or error details', async t => {
  await fixture(t);
  const errors = [];
  await assert.rejects(createHostedService({ origin, managedIngress: 'render-free',
    store: { read: async () => { throw new Error('private account file contents'); }, write: async () => {} },
    reportError: error => errors.push(error.message) }), /Account storage unavailable/);
  assert.deepEqual(errors, ['Hosted service operation failed.']);
});

test('only health and the explicit remote assets are public', async t => {
  const app = await fixture(t);
  const health = await app.request('/healthz');
  assert.equal(health.status, 200);
  assert.deepEqual(health.json(), { status: 'ok' });
  assert.equal(health.headers['set-cookie'], undefined);
  const home = await app.request('/');
  assert.equal(home.status, 200);
  assert.match(home.text, /Remote/);
  assert.match(home.headers['content-security-policy'], /script-src 'self' 'wasm-unsafe-eval'/);
  assert.ok(home.headers['content-security-policy'].includes(`connect-src 'self' wss://${hostname}`));
  assert.equal(home.headers['x-frame-options'], 'DENY');
  assert.equal(home.headers['referrer-policy'], 'no-referrer');
  assert.equal((await app.request('/', { method: 'HEAD' })).text, '');
  assert.equal((await app.request('/remote-app.mjs')).status, 200);
  const icon = await app.request('/icon-192.png');
  assert.equal(icon.status, 200);
  assert.equal(icon.headers['content-type'], 'image/png');
  const notices = await app.request('/remote-crypto/LICENSES.txt');
  assert.equal(notices.status, 200);
  assert.match(notices.text, /Dependency notices fixture/);
  for (const path of ['/app.mjs', '/sw.js', '/v1/sessions', '/state.json', '/remote.html', '/?secret=x',
    '/remote-crypto/channel_bg.wasm', '/%2e%2e/package.json']) {
    assert.equal((await app.request(path)).status, 404, path);
  }
  await app.close();
  await app.close();
  assert.equal(app.server.listening, false);
  assert.deepEqual(app.errors, []);
});

test('outer ingress rejects wrong hosts, forwarding, origins and duplicate headers', async t => {
  const app = await fixture(t);
  for (const headers of [
    { host: 'evil.invalid' }, { 'x-forwarded-proto': 'http' }, { 'x-forwarded-proto': 'https,http' },
    { forwarded: 'proto=https' }, { 'x-forwarded-host': 'evil.invalid' }, { 'x-forwarded-port': '80' },
    { origin: 'https://evil.invalid' }, { origin: [origin, origin] }
  ]) assert.equal((await app.request('/healthz', { headers })).status, 403);
});

test('account ceremonies receive the real request with origin and flow cookies', async t => {
  const app = await fixture(t);
  const options = await app.request('/v1/account/register/options', {
    body: { name: 'Hosted test' }, headers: { origin, 'sec-fetch-site': 'same-origin' } });
  assert.equal(options.status, 200);
  assert.equal(options.json().rp.id, hostname);
  assert.match(options.headers['set-cookie'][0], /__Host-notify-account-flow=.*Secure; HttpOnly; SameSite=Strict/);
  for (const headers of [{}, { origin: 'https://evil.invalid' }, { origin, 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await app.request('/v1/account/login/options', { body: {}, headers })).status, 403);
  }
  assert.equal((await app.request('/v1/account/session', { body: {}, headers: { origin } })).status, 401);
});

test('remote native and browser routes are isolated and fields cannot inject credentials', async t => {
  const app = await fixture(t);
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const macID = randomUUID();
  const input = { macID, publicKey: Buffer.concat([Buffer.from([4]),
    Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64url') };
  assert.equal((await app.request('/v1/remote/mac/begin', { body: input, headers: { origin } })).status, 403);
  assert.equal((await app.request('/v1/remote/mac/begin', { body: input,
    headers: { 'sec-fetch-site': 'none' } })).status, 403);
  const begun = await app.request('/v1/remote/mac/begin', { body: input });
  assert.equal(begun.status, 200);
  const flow = begun.json();
  const signature = sign('sha256', Buffer.concat([Buffer.from('Notify remote authorization v1\0'),
    Buffer.from(flow.challenge)]), privateKey).toString('base64url');
  const registered = await app.request('/v1/remote/mac/register', { body: { id: flow.id, signature } });
  assert.equal(registered.status, 200);
  const authorization = `Bearer ${registered.json().credential}`;
  const status = await app.request('/v1/remote/mac/status', { body: {}, headers: { authorization } });
  assert.equal(status.status, 200);
  assert.equal(status.json().macID, macID);
  assert.equal((await app.request('/v1/remote/mac/status', { body: {} })).status, 401);
  assert.equal((await app.request('/v1/remote/mac/status', {
    body: { credential: registered.json().credential }, headers: { authorization } })).status, 400);
  assert.equal((await app.request('/v1/remote/pair', { body: {} })).status, 403);
  assert.equal((await app.request('/v1/remote/grant/begin', {
    body: { role: 'phone', macID, deviceID: randomUUID(), credential: 'injected' }, headers: { origin } })).status, 400);
  assert.equal((await app.request('/v1/remote/grant/begin', {
    body: { role: 'mac', deviceID: randomUUID() }, headers: { origin, authorization } })).status, 403);
});

test('JSON limits reject malformed, excessive, extra-field and non-JSON requests', async t => {
  const app = await fixture(t);
  for (const [body, headers, expected] of [
    ['{', {}, 400], ['[]', {}, 400], [{ unexpected: true }, {}, 400],
    [{}, { 'content-type': 'application/json; charset=utf-8' }, 415],
    [' '.repeat(16385), { 'content-length': '16385' }, 413],
    [' '.repeat(16385), {}, 413]
  ]) {
    const result = await app.request('/v1/remote/mac/begin', { body, headers });
    assert.equal(result.status, expected);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal(result.headers['set-cookie'], undefined);
  }
  const result = await app.request('/v1/account/register/options', {
    body: ' '.repeat(16385), headers: { origin } });
  assert.equal(result.status, 413);
  assert.deepEqual(app.errors, []);
});

test('chunked bodies cannot bypass the outer 16 KiB cap on account or remote routes', async t => {
  const app = await fixture(t);
  for (const path of ['/v1/remote/mac/begin', '/v1/account/register/options']) {
    const result = await app.request(path, {
      method: 'POST', chunks: [' '.repeat(8192), ' '.repeat(8192), '{"name":"Test"}'],
      headers: { ...(path.startsWith('/v1/account/') ? { origin } : {}),
        'content-type': 'application/json', 'transfer-encoding': 'chunked' }
    });
    assert.equal(result.status, 413);
    assert.equal(result.headers['set-cookie'], undefined);
  }
  assert.deepEqual(app.errors, []);
});

test('bootstrap requests are bounded per actual socket peer, not forwarded IP', async t => {
  const app = await fixture(t);
  const statuses = [];
  for (let i = 0; i < 25; i++) statuses.push((await app.request('/v1/remote/mac/begin', {
    body: {}, headers: { 'x-forwarded-for': `203.0.113.${i}` } })).status);
  assert.ok(statuses.includes(429));
  assert.equal(statuses.at(-1), 429);
});

test('phone finalization binds actual account cookies and WebSocket upgrades preserve requests', async t => {
  const app = await fixture(t);
  const cookie = await registerAccount(app), otherCookie = await registerAccount(app);
  const mac = deviceKey(), phone = deviceKey(), macID = randomUUID(), deviceID = randomUUID();
  const macFlow = await app.request('/v1/remote/mac/begin', { body: { macID, publicKey: mac.publicKey } });
  const registration = await app.request('/v1/remote/mac/register', { body: mac.finish(macFlow.json()) });
  const authorization = `Bearer ${registration.json().credential}`;
  const pairing = await app.request('/v1/remote/pair', { body: {
    setupID: registration.json().setupID, deviceID, publicKey: phone.publicKey, name: 'Test phone'
  }, headers: { origin, cookie } });
  assert.equal(pairing.status, 200);
  assert.equal((await app.request('/v1/remote/mac/decision', {
    body: { id: pairing.json().id, allow: true }, headers: { authorization } })).status, 200);
  const phoneFlow = await app.request('/v1/remote/grant/begin', {
    body: { role: 'phone', macID, deviceID }, headers: { origin, cookie } });
  assert.equal(phoneFlow.status, 200);
  const finishBody = phone.finish(phoneFlow.json());
  for (const [headers, expected] of [[{}, 403], [{ origin }, 401], [{ origin, cookie: otherCookie }, 403],
    [{ origin: 'https://evil.invalid', cookie }, 403]]) {
    const rejected = await app.request('/v1/remote/grant/finish', { body: finishBody, headers });
    assert.equal(rejected.status, expected);
    assert.equal(rejected.headers['set-cookie'], undefined);
  }
  const finished = await app.request('/v1/remote/grant/finish', { body: finishBody, headers: { origin, cookie } });
  assert.equal(finished.status, 200);
  assert.equal(finished.json().role, 'phone');
  assert.equal(Object.hasOwn(finished.json(), 'credential'), false);
  const relayCookie = finished.headers['set-cookie'][0];
  assert.match(relayCookie, /^__Host-notify-relay=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=(?:[1-9]|[12][0-9]|30); Secure; HttpOnly; SameSite=Strict$/);
  const macGrant = await app.request('/v1/remote/grant/begin', {
    body: { role: 'mac', deviceID }, headers: { authorization } });
  assert.equal(macGrant.status, 200);
  const macFinished = await app.request('/v1/remote/grant/finish', { body: mac.finish(macGrant.json()) });
  assert.equal(macFinished.status, 200);
  assert.equal(typeof macFinished.json().credential, 'string');
  assert.equal(macFinished.headers['set-cookie'], undefined);
  const url = `ws://127.0.0.1:${app.server.address().port}/v1/relay`;
  const nativeSocket = new WebSocket(url, 'notify-relay-v1', {
    headers: { host: hostname, authorization: `Bearer ${macFinished.json().credential}` } });
  t.after(() => nativeSocket.terminate());
  await once(nativeSocket, 'open');
  const ready = once(nativeSocket, 'message');
  const browserSocket = new WebSocket(url, 'notify-relay-v1', { headers: {
    host: hostname, origin, cookie: relayCookie.split(';')[0], 'sec-fetch-mode': 'websocket', 'sec-fetch-site': 'same-origin'
  } });
  t.after(() => browserSocket.terminate());
  await once(browserSocket, 'open');
  assert.equal(JSON.parse((await ready)[0].toString()).type, 'ready');
  const received = once(nativeSocket, 'message');
  browserSocket.send(Buffer.from('opaque authenticated ciphertext'));
  assert.equal((await received)[0].toString(), 'opaque authenticated ciphertext');
  const nativeClosed = once(nativeSocket, 'close'), browserClosed = once(browserSocket, 'close');
  await app.close();
  await Promise.all([nativeClosed, browserClosed]);
});

test('outer request concurrency is bounded while liveness remains available', async t => {
  const app = await fixture(t);
  let seen = 0, allArrived;
  const arrived = new Promise(resolve => { allArrived = resolve; });
  const observe = req => { if (req.url === '/v1/remote/mac/status' && ++seen === 16) allArrived(); };
  app.server.on('request', observe);
  const held = Array.from({ length: 16 }, () => {
    const req = http.request({ hostname: '127.0.0.1', port: app.server.address().port,
      method: 'POST', path: '/v1/remote/mac/status', headers: { host: hostname, 'content-type': 'application/json' } });
    req.on('error', () => {});
    req.write('{');
    return req;
  });
  t.after(() => { for (const req of held) req.destroy(); });
  await arrived;
  assert.equal((await app.request('/v1/remote/mac/status', { body: {} })).status, 503);
  assert.equal((await app.request('/healthz')).status, 200);
  for (const req of held) req.destroy();
  app.server.off('request', observe);
  await app.close();
});

test('WebSocket upgrades cannot reach other paths or bypass ingress', async t => {
  const app = await fixture(t);
  for (const [path, headers, expected] of [
    ['/app.mjs', {}, 404], ['/v1/relay?credential=not-allowed', {}, 404],
    ['/v1/relay', { host: 'evil.invalid' }, 403], ['/v1/relay', { 'x-forwarded-proto': 'http' }, 403],
    ['/v1/relay', { origin, 'sec-fetch-site': 'cross-site' }, 403]
  ]) {
    const status = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${app.server.address().port}${path}`,
        'notify-relay-v1', { headers: { host: hostname, ...headers } });
      socket.once('error', reject);
      socket.once('unexpected-response', (req, res) => {
        res.resume();
        resolve(res.statusCode);
        req.destroy();
      });
    });
    assert.equal(status, expected);
  }
});
