import http, { STATUS_CODES } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { AccountServiceError, createAccountService } from './account-service.mjs';
import { createIngressPolicy } from './managed-ingress.mjs';
import { createRemoteAuthority } from './remote-authority.mjs';
import { createRemoteRelay } from './remote-relay.mjs';
import { privateDirectory, stateStore } from './storage.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const BODY_LIMIT = 16384;
const ASSETS = new Map([
  ['/', ['remote.html', 'text/html; charset=utf-8']],
  ['/remote-app.mjs', ['remote-app.mjs', 'text/javascript; charset=utf-8']],
  ['/remote-transport.mjs', ['remote-transport.mjs', 'text/javascript; charset=utf-8']],
  ['/remote-identity.mjs', ['remote-identity.mjs', 'text/javascript; charset=utf-8']],
  ['/workspace.mjs', ['workspace.mjs', 'text/javascript; charset=utf-8']],
  ['/remote-crypto/channel.js', ['remote-crypto/channel.js', 'text/javascript; charset=utf-8']],
  ['/remote-crypto/channel_bg.wasm', ['remote-crypto/channel_bg.wasm', 'application/wasm']],
  ['/remote-crypto/LICENSES.txt', ['remote-crypto/LICENSES.txt', 'text/plain; charset=utf-8']],
  ['/icon-192.png', ['icon-192.png', 'image/png']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]
]);
const ACCOUNTS = new Set(['register/options', 'register/verify', 'login/options', 'login/verify',
  'session', 'logout'].map(path => `/v1/account/${path}`));
const FIELDS = new Map([
  ['/v1/remote/mac/begin', [['macID', 'publicKey']]],
  ['/v1/remote/mac/register', [['id', 'signature']]],
  ['/v1/remote/pair', [['setupID', 'deviceID', 'publicKey', 'name']]],
  ['/v1/remote/mac/status', [[]]],
  ['/v1/remote/mac/decision', [['id', 'allow']]],
  ['/v1/remote/mac/revoke', [['deviceID']]],
  ['/v1/remote/grant/begin', [['role', 'deviceID'], ['macID']]],
  ['/v1/remote/grant/finish', [['id', 'signature']]]
]);
const securityHeaders = {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
    "img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
    "form-action 'self'; frame-ancestors 'none'; worker-src 'none'"
};
function fail(status) { throw Object.assign(new Error('Hosted request rejected.'), { status }); }
function reply(res, status, value = { error: STATUS_CODES[status] ?? 'Request rejected' }) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status);
  res.end(JSON.stringify(value));
}
function browser(req, origin, upgrade = false) {
  if (req.headers.origin !== origin ||
    (req.headers['sec-fetch-site'] !== undefined && req.headers['sec-fetch-site'] !== 'same-origin') ||
    (req.headers['sec-fetch-mode'] !== undefined &&
      !(upgrade ? ['websocket'] : ['cors', 'same-origin']).includes(req.headers['sec-fetch-mode'])) ||
    (req.headers['sec-fetch-dest'] !== undefined && req.headers['sec-fetch-dest'] !== 'empty') ||
    req.headers.authorization !== undefined) fail(403);
}
function native(req) {
  if (req.headers.origin !== undefined || req.headers.cookie !== undefined ||
    Object.keys(req.headers).some(name => name.startsWith('sec-fetch-'))) fail(403);
}
function bearer(req) {
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
  if (!match) fail(401);
  return match[1];
}
function shape(value, [required, optional = []]) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    required.some(key => !Object.hasOwn(value, key)) ||
    Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail(400);
}
function bodyHeaders(req) {
  if (req.headers['content-type'] !== 'application/json' || req.headers['content-encoding'] !== undefined) fail(415);
  if (Number(req.headers['content-length'] ?? 0) > BODY_LIMIT) fail(413);
}
function tooLarge(req, res) {
  req.pause();
  if (res.destroyed || res.writableEnded) return;
  res.setHeader('Connection', 'close');
  res.once('finish', () => req.destroy(new AccountServiceError(413, 'Hosted request is too large.')));
  reply(res, 413);
}
async function json(req, res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        tooLarge(req, res);
        reject(Object.assign(new Error('Body limit reached.'), { status: 413 }));
      } else chunks.push(chunk);
    });
    req.once('error', () => reject(Object.assign(new Error('Request interrupted.'), { status: 400 })));
    req.once('end', () => {
      try {
        resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))));
      } catch { reject(Object.assign(new Error('Invalid JSON.'), { status: 400 })); }
    });
  });
}

// Only the outer server listens. Inner modules receive the original request/socket.
export async function createHostedService({ origin, managedIngress, store,
  publicDirectory = resolve(ROOT, 'public'), reportError = () => {} } = {}) {
  if (typeof origin !== 'string' || new URL(origin).origin !== origin) throw new Error('An exact HTTPS origin is required.');
  const server = http.createServer({ maxHeaderSize: 8192, connectionsCheckingInterval: 1000 });
  const ingress = createIngressPolicy({ server, publicOrigin: origin, managedIngress });
  const headers = { ...securityHeaders, 'Content-Security-Policy':
    `${securityHeaders['Content-Security-Policy']}; connect-src 'self' wss://${new URL(origin).host}` };
  if (typeof reportError !== 'function') throw new Error('An error reporter is required.');
  const report = () => { try { reportError(new Error('Hosted service operation failed.')); } catch {} };
  const assets = new Map();
  for (const [path, [file, type]] of ASSETS) {
    try { assets.set(path, { bytes: await readFile(resolve(publicDirectory, file)), type }); }
    catch (error) { if (error.code !== 'ENOENT') throw new Error('Hosted assets could not be read.'); }
  }
  const accountServer = http.createServer(), relayServer = http.createServer();
  const accounts = await createAccountService({ server: accountServer, origin, store, managedIngress, reportError: report });
  let authority, relay;
  try {
    authority = createRemoteAuthority({ origin, accounts });
    relay = createRemoteRelay({ server: relayServer, publicOrigin: origin, webOrigin: origin,
      managedIngress, authorize: authority.authorizeRelay, reportError: report });
  } catch (error) {
    accounts.close(); authority?.close();
    throw error;
  }
  let closed = false, closing, active = 0;
  const sockets = new Set(), rates = new Map();
  server.maxConnections = 160;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 100;
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.setTimeout(5000, socket => socket.destroy());
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {});
  });
  function checkIngress(req) {
    if (!ingress.accepts(req) || req.rawHeaders.length > 64 ||
      (req.headers.origin !== undefined && req.headers.origin !== origin)) fail(403);
    const names = req.rawHeaders.filter((_, index) => index % 2 === 0).map(name => name.toLowerCase());
    if (new Set(names).size !== names.length) fail(403);
    if (closed) fail(503);
  }
  function limit(req) {
    const now = performance.now();
    for (const [key, rate] of rates) if (rate.expires <= now) rates.delete(key);
    const peer = req.socket.remoteAddress;
    if (!peer) fail(403);
    let rate = rates.get(peer);
    if (!rate) {
      if (rates.size >= 128) fail(503);
      rates.set(peer, rate = { requests: 0, bootstrap: 0, expires: now + 60000 });
    }
    if (++rate.requests > 120) fail(429);
    if (['/v1/remote/mac/begin', '/v1/remote/mac/register'].includes(req.url) && ++rate.bootstrap > 20) fail(429);
  }
  server.on('request', async (req, res) => {
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    let reserved = false;
    const timer = setTimeout(() => res.destroy(), 5000);
    timer.unref();
    res.once('close', () => {
      clearTimeout(timer);
      if (reserved) active--;
    });
    try {
      checkIngress(req);
      if (ingress.health(req, res)) return;
      if (active >= 16) fail(503);
      active++; reserved = true;
      if (ASSETS.has(req.url)) {
        if (!['GET', 'HEAD'].includes(req.method)) fail(405);
        const asset = assets.get(req.url);
        if (!asset) fail(404);
        res.writeHead(200, { 'Content-Type': asset.type, 'Content-Length': asset.bytes.length });
        res.end(req.method === 'HEAD' ? undefined : asset.bytes);
        return;
      }
      if (!ACCOUNTS.has(req.url) && !FIELDS.has(req.url)) fail(404);
      if (req.method !== 'POST') fail(405);
      limit(req);
      if (ACCOUNTS.has(req.url)) {
        browser(req, origin);
        bodyHeaders(req);
        let size = 0;
        req.on('data', chunk => {
          size += chunk.length;
          if (size > BODY_LIMIT) tooLarge(req, res);
        });
        accountServer.emit('request', req, res);
        return;
      }
      if (req.url.startsWith('/v1/remote/mac/')) native(req);
      else if (req.url === '/v1/remote/pair') browser(req, origin);
      bodyHeaders(req);
      const data = await json(req, res);
      if (closed || res.destroyed || res.writableEnded) return;
      shape(data, FIELDS.get(req.url));
      let result;
      switch (req.url) {
        case '/v1/remote/mac/begin': result = authority.beginMac(data); break;
        case '/v1/remote/mac/register': result = authority.registerMac(data); break;
        case '/v1/remote/pair': result = await authority.requestPair(req, data); break;
        case '/v1/remote/mac/status': result = authority.macStatus(bearer(req)); break;
        case '/v1/remote/mac/decision': result = authority.decidePair(bearer(req), data); break;
        case '/v1/remote/mac/revoke': result = authority.revokeDevice(bearer(req), data); break;
        case '/v1/remote/grant/begin':
          if (data.role === 'mac') {
            native(req);
            result = await authority.beginGrant(req, { ...data, credential: bearer(req) });
          } else {
            browser(req, origin);
            result = await authority.beginGrant(req, data);
          }
          break;
        case '/v1/remote/grant/finish':
          if (req.headers.origin === undefined) native(req); else browser(req, origin);
          result = authority.finishGrant(data, req);
          if (result.role === 'phone') {
            browser(req, origin);
            const age = Math.min(30, Math.floor((result.expiresAt - Date.now()) / 1000));
            if (age <= 0) fail(401);
            res.setHeader('Set-Cookie', `__Host-notify-relay=${result.credential}; Path=/; Max-Age=${age}; Secure; HttpOnly; SameSite=Strict`);
            const { credential, ...publicResult } = result;
            result = publicResult;
          } else native(req);
          break;
      }
      reply(res, 200, result);
    } catch (error) {
      const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
      if (status === 500) report();
      if (!req.complete && !res.writableEnded) res.setHeader('Connection', 'close');
      reply(res, status);
    }
  });
  server.on('upgrade', (req, socket, head) => {
    try {
      checkIngress(req);
      if (req.url !== '/v1/relay') fail(404);
      limit(req);
      if (req.headers.origin === undefined) native(req); else browser(req, origin, true);
      relayServer.emit('upgrade', req, socket, head);
    } catch (error) {
      const status = error.status ?? 500;
      socket.end(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      const timer = setTimeout(() => socket.destroy(), 1000);
      timer.unref();
      socket.once('close', () => clearTimeout(timer));
    }
  });
  return Object.freeze({
    server,
    close() {
      if (closing) return closing;
      closed = true;
      closing = (async () => {
        accounts.close(); authority.close(); rates.clear();
        const stopped = server.listening ? new Promise(resolve => server.close(resolve)) : Promise.resolve();
        server.closeAllConnections();
        await relay.close();
        for (const socket of sockets) socket.destroy();
        await stopped;
      })();
      return closing;
    }
  });
}

export async function main() {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
  process.umask(0o077);
  const hostname = process.env.RENDER_EXTERNAL_HOSTNAME;
  const origin = process.env.NOTIFY_ORIGIN ?? `https://${hostname}`;
  if (!/^[1-9][0-9]{0,4}$/.test(process.env.PORT ?? '') || Number(process.env.PORT) > 65535)
    throw new Error('Render PORT is required.');
  for (const [, [file]] of ASSETS) await readFile(resolve(ROOT, 'public', file));
  const directory = resolve(ROOT, '.hosted-data');
  await privateDirectory(directory);
  const app = await createHostedService({ origin, managedIngress: 'render-free', store: stateStore(directory),
    reportError: () => process.stderr.write('Hosted service operation failed.\n') });
  try {
    await new Promise((resolve, reject) => {
      app.server.once('error', reject);
      app.server.listen(Number(process.env.PORT), '0.0.0.0', () => {
        app.server.off('error', reject); resolve();
      });
    });
  } catch (error) { await app.close(); throw error; }
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let app, stopping = false;
  const stop = () => { stopping = true; void app?.close(); };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  main().then(value => { app = value; if (stopping) return app.close(); }).catch(() => {
    process.stderr.write('Hosted startup failed; check Render origin, PORT, assets and private storage.\n');
    process.exitCode = 1;
  });
}
