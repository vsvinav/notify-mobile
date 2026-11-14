import https from 'node:https';
import http from 'node:http';
import { randomBytes, randomInt, createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { certificates } from './certificates.mjs';
import { privateDirectory, stateStore } from './storage.mjs';
import { selectNetwork, privateIPv4, sameSubnet, networkPresent } from './network.mjs';
import { genericPayload, generateVAPIDKeys, validSubscription, pushSender } from './push.mjs';
import { object, validSnapshot, validReply } from './validation.mjs';

const BODY_LIMIT = 131072, LEASE = 12000, PAIR_TTL = 180000, DEVICE_TTL = 90 * 86400000;
const MAX_DEVICES = 8, MAX_SEEN = 2048;
const hash = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const comparison = () => String(randomInt(0, 1000000)).padStart(6, '0');
const keyOf = item => `${item.sessionID}\0${item.request.id}\0${item.ticket}`;
const publicDirectory = new URL('../public/', import.meta.url);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new HttpError(status, message); };
const safeEqual = (a, b) => typeof a === 'string' && typeof b === 'string' &&
  Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function headers(response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
}

function json(response, status, data) {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
}

function cookie(request, name) {
  const match = (request.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith(`${name}=`));
  return match?.slice(name.length + 1);
}
const setCookie = (response, name, value, age) =>
  response.setHeader('Set-Cookie', `${name}=${value}; Path=/; Max-Age=${age}; Secure; HttpOnly; SameSite=Strict`);

async function body(request) {
  if (request.headers['content-type'] !== 'application/json') fail(415, 'Use application/json.');
  const declared = Number(request.headers['content-length'] ?? 0);
  if (declared > BODY_LIMIT) fail(413, 'Reply is too large. Limit answers to 128 KiB in total.');
  let length = 0;
  const chunks = [];
  for await (const chunk of request) {
    length += chunk.length;
    if (length > BODY_LIMIT) fail(413, 'Reply is too large. Limit answers to 128 KiB in total.');
    chunks.push(chunk);
  }
  try {
    const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!object(result)) fail(400, 'Expected a JSON object.');
    return result;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    fail(400, 'Invalid JSON.');
  }
}

const mime = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.mjs': ['app.mjs', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/sw.js': ['sw.js', 'text/javascript; charset=utf-8'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'],
  '/icon-192.png': ['icon-192.png', 'image/png'],
  '/icon-512.png': ['icon-512.png', 'image/png']
};

function listen(server, port, address) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, address, () => { server.off('error', reject); resolve(); });
  });
}

export async function createCompanion({
  directory, emit, network = selectNetwork(), httpsPort = 8443, httpPort = 8080,
  testOnlyLoopback = false, pushSend, now = () => Date.now(), ackTimeout = 20000
}) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
  process.umask(0o077);
  if (!(privateIPv4(network.address) || (testOnlyLoopback && network.address === '127.0.0.1'))) {
    throw new Error('Mobile HTTPS must bind a private IPv4 LAN address.');
  }
  await privateDirectory(directory);
  const tls = await certificates(directory, network.address, testOnlyLoopback);
  const store = stateStore(directory);
  let state = await store.read();
  if (!state) {
    state = { version: 1, vapid: generateVAPIDKeys(), devices: [], seen: [] };
    await store.write(state);
  }
  if (state.version !== 1 || !Array.isArray(state.devices) || state.devices.length > MAX_DEVICES ||
    !Array.isArray(state.seen) || state.seen.length > MAX_SEEN ||
    !state.seen.every(id => /^[a-f0-9]{64}$/.test(id)) ||
    !state.vapid?.publicKey || !state.vapid?.privateKey ||
    !state.devices.every(d => typeof d.id === 'string' && typeof d.name === 'string' &&
      /^[a-f0-9]{64}$/.test(d.tokenHash) && Number.isFinite(d.expires) &&
      (!d.subscription || validSubscription(d.subscription)))) {
    throw new Error('Invalid private mobile state. Disable mobile and inspect its data directory.');
  }
  state.devices = state.devices.filter(d => d.expires > now());
  const sendPush = pushSend ?? pushSender(state.vapid);
  const lastSeen = new Map(), pendingPairs = new Map(), pendingReplies = new Map(), blocked = new Set(), rates = new Map();
  let invite, requests = [], total = 0, snapshotAt = 0, available = false, closed = false, pushMessage;
  let pushQueue = Promise.resolve(), pushQueued = 0, activeRequests = 0;
  const app = { ca: tls.ca, url: '', setupURL: '', command, close, flushPush: () => pushQueue };
  const fresh = () => available && now() - snapshotAt < LEASE;
  const status = () => {
    if (invite && invite.expires <= now()) invite = undefined;
    emit({ type: 'status', status: {
      url: app.url, setupURL: app.setupURL, fingerprint: tls.fingerprint,
      ...(invite ? { pairingCode: invite.code } : {}),
      devices: state.devices.map(d => ({
        id: d.id, name: d.name,
        online: d.expires > now() && now() - (lastSeen.get(d.id) ?? -Infinity) < 10000,
        pushEnabled: !!d.subscription && d.expires > now()
      })),
      ...(pushMessage ? { pushMessage } : {})
    } });
  };
  const report = message => emit({ type: 'error', message: message.slice(0, 500) });
  function rate(key, max, interval) {
    const previous = rates.get(key);
    if (!previous || previous.until <= now()) {
      if (rates.size >= 512) {
        for (const [k, value] of rates) if (value.until <= now()) rates.delete(k);
        if (rates.size >= 512) fail(429, 'Too many connections. Try again in a minute.');
      }
      rates.set(key, { count: 1, until: now() + interval });
    } else {
      if (++previous.count > max) fail(429, 'Too many attempts. Wait a minute before trying again.');
    }
  }
  function authenticate(request) {
    const token = cookie(request, '__Host-notify');
    if (!token || token.length > 128) fail(401, 'Pair this installed app with your Mac.');
    const digest = hash(token);
    const device = state.devices.find(d => safeEqual(d.tokenHash, digest) && d.expires > now());
    if (!device) fail(401, 'Pairing expired or was revoked. Pair again on your Mac.');
    lastSeen.set(device.id, now());
    return device;
  }
  function pairingSession(request) {
    const token = cookie(request, '__Host-notify-pair');
    if (!token || token.length > 128) fail(401, 'Pairing session expired. Create a new code on your Mac.');
    const pending = [...pendingPairs.values()].find(p => safeEqual(p.tokenHash, hash(token)));
    if (!pending || pending.expires <= now()) fail(401, 'Pairing session expired. Create a new code on your Mac.');
    return pending;
  }
  function cancelReplies(message, code = 409, deviceID) {
    for (const [id, pending] of pendingReplies) {
      if (!deviceID || deviceID === pending.deviceID) {
        clearTimeout(pending.timer); pendingReplies.delete(id);
        pending.resolve({ status: code, error: message });
      }
    }
  }
  function enqueuePush() {
    if (pushQueued >= 1 || closed) return;
    pushQueued++;
    pushQueue = pushQueue.then(async () => {
      if (closed) return;
      const failures = [];
      for (const device of [...state.devices]) {
        if (closed || !device.subscription || device.expires <= now() || !state.devices.includes(device)) continue;
        const subscription = device.subscription;
        try {
          await sendPush(subscription, genericPayload);
        } catch (error) {
          if (error.statusCode === 404 || error.statusCode === 410) {
            if (state.devices.includes(device) && device.subscription === subscription) {
              delete device.subscription; await store.write(state);
            }
            failures.push('A push subscription expired. Enable alerts again on that phone.');
          } else {
            failures.push('Push could not reach a provider. Check the Mac internet connection and try a generic test from Settings.');
          }
        }
      }
      pushMessage = failures.length ? [...new Set(failures)].join(' ') : undefined;
      status();
    }).catch(() => {
      pushMessage = 'Push state could not be saved. Check permissions and free space in the mobile data directory.';
      report(pushMessage); status();
    }).finally(() => { pushQueued--; });
  }
  async function command(message) {
    if (!object(message) || typeof message.type !== 'string') throw new Error('Invalid mobile command.');
    switch (message.type) {
      case 'snapshot': {
        if (Buffer.byteLength(JSON.stringify(message)) > 1048576 || !validSnapshot(message)) {
          available = false; requests = []; total = 0;
          cancelReplies('Snapshot invalid or too large. Mobile actions are disabled.', 503);
          status();
          throw new Error('Mobile snapshot is invalid or exceeds the supported size. No request fields were truncated.');
        }
        requests = message.requests; total = message.total; snapshotAt = now(); available = true;
        const liveKeys = new Set(requests.map(keyOf));
        for (const key of blocked) if (!liveKeys.has(key)) blocked.delete(key);
        for (const [id, pending] of pendingReplies) {
          if (!liveKeys.has(pending.key)) {
            clearTimeout(pending.timer); pendingReplies.delete(id);
            pending.resolve({ status: 409, error: 'This request changed or was cancelled. Refresh and review the current request.' });
          }
        }
        const seen = new Set(state.seen);
        let unseen = false;
        for (const item of requests) {
          const id = hash(item.notificationID);
          if (!seen.has(id)) { unseen = true; seen.add(id); }
        }
        if (unseen) {
          state.seen = [...seen].slice(-MAX_SEEN);
          try { await store.write(state); }
          catch { available = false; status(); throw new Error('Cannot save mobile notification deduplication state. Check disk permissions and space.'); }
          enqueuePush();
        }
        status();
        break;
      }
      case 'invite':
        if (state.devices.length >= MAX_DEVICES) throw new Error('Eight phones are already paired. Revoke a device before pairing another.');
        invite = { code: String(randomInt(0, 100000000)).padStart(8, '0'), expires: now() + PAIR_TTL };
        status(); break;
      case 'pair': {
        const pending = pendingPairs.get(message.id);
        if (!pending || pending.expires <= now() || pending.state !== 'pending') throw new Error('Phone pairing expired. Generate a new code.');
        if (message.allow !== true) { pending.state = 'denied'; status(); break; }
        if (state.devices.length >= MAX_DEVICES) throw new Error('Eight phones are already paired. Revoke a device first.');
        const token = secret();
        const device = { id: secret(), name: pending.name, tokenHash: hash(token), expires: now() + DEVICE_TTL };
        state.devices.push(device);
        try { await store.write(state); }
        catch (error) { state.devices = state.devices.filter(d => d !== device); throw error; }
        pending.state = 'accepted'; pending.device = device; pending.token = token;
        status(); break;
      }
      case 'revoke': {
        state.devices = state.devices.filter(d => d.id !== message.id);
        lastSeen.delete(message.id);
        for (const [id, p] of pendingPairs) if (p.device?.id === message.id) pendingPairs.delete(id);
        cancelReplies('This phone was revoked on the Mac.', 401, message.id);
        await store.write(state); status(); break;
      }
      case 'result': {
        const pending = pendingReplies.get(message.id);
        if (!pending) break;
        clearTimeout(pending.timer); pendingReplies.delete(message.id);
        pending.resolve(message.ok === true
          ? { status: 200 }
          : { status: 502, error: typeof message.error === 'string' ? message.error.slice(0, 1000) : 'The agent did not acknowledge this reply. Check Notify on the Mac.' });
        break;
      }
      case 'test-push': enqueuePush(); break;
      case 'offline':
        available = false; requests = []; total = 0;
        cancelReplies('The Mac is unavailable. Review a fresh request after reconnecting.', 503);
        status(); break;
      case 'stop': await close(); break;
      default: throw new Error('Unknown mobile command.');
    }
  }

  async function api(request, response, path) {
    if (request.method !== 'POST') fail(405, 'Use POST for mobile API requests.');
    if (request.headers.origin !== app.url || (request.headers['sec-fetch-site'] && request.headers['sec-fetch-site'] !== 'same-origin')) {
      fail(403, 'Open Notify from the exact HTTPS address shown on your Mac.');
    }
    const input = await body(request);
    const peer = request.socket.remoteAddress;
    rate(`api:${peer}`, 120, 60000);
    if (path === '/api/pair') {
      rate('pair:global', 20, 60000); rate(`pair:${peer}`, 5, 60000);
      for (const [id, pending] of pendingPairs) if (pending.expires <= now()) pendingPairs.delete(id);
      if (state.devices.length >= MAX_DEVICES) fail(409, 'Eight phones are paired. Revoke one on the Mac first.');
      if (!invite || invite.expires <= now() || !safeEqual(input.code, invite.code)) fail(403, 'Incorrect, used, or expired code. Create a new pairing code on your Mac.');
      if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 80 || /[\x00-\x1f\x7f]/.test(input.name)) {
        fail(400, 'Enter a phone name of 1–80 characters.');
      }
      if (pendingPairs.size >= 8) fail(429, 'Too many pending pairings. Wait three minutes.');
      invite = undefined;
      const token = secret();
      const pending = { id: secret(), tokenHash: hash(token), name: input.name.trim(),
        code: comparison(), expires: now() + PAIR_TTL, state: 'pending' };
      pendingPairs.set(pending.id, pending);
      setCookie(response, '__Host-notify-pair', token, PAIR_TTL / 1000);
      emit({ type: 'pairing', id: pending.id, name: pending.name, code: pending.code });
      status();
      return json(response, 202, { state: 'pending', code: pending.code });
    }
    if (path === '/api/pair-status') {
      const pending = pairingSession(request);
      if (pending.state !== 'accepted') return json(response, 200, { state: pending.state, code: pending.code });
      if (!state.devices.includes(pending.device)) fail(401, 'Pairing was revoked.');
      setCookie(response, '__Host-notify', pending.token, DEVICE_TTL / 1000);
      // Keep the short-lived pending session until expiry, so a lost confirmation response can be recovered.
      return json(response, 200, { state: 'accepted', device: { id: pending.device.id, name: pending.name } });
    }
    const device = authenticate(request);
    if (path === '/api/state') {
      return json(response, 200, {
        paired: true, device: { id: device.id, name: device.name }, connected: fresh(),
        requests: fresh() ? requests.map(item => ({ ...item, sending: item.sending || blocked.has(keyOf(item)) })) : [],
        total: fresh() ? total : 0, lease: LEASE, pushEnabled: !!device.subscription,
        vapidPublicKey: state.vapid.publicKey, ...(pushMessage ? { pushMessage } : {})
      });
    }
    if (path === '/api/push') {
      if (input.subscription !== null && !validSubscription(input.subscription)) fail(400, 'Unsupported push provider or invalid subscription.');
      const previous = device.subscription;
      if (input.subscription === null) delete device.subscription;
      else device.subscription = { endpoint: input.subscription.endpoint, keys: {
        p256dh: input.subscription.keys.p256dh, auth: input.subscription.keys.auth
      } };
      try { await store.write(state); }
      catch (error) { device.subscription = previous; throw error; }
      status(); return json(response, 200, { pushEnabled: !!device.subscription });
    }
    if (path === '/api/reply') {
      if (!fresh()) fail(503, 'The Mac is offline or the request list is stale. Reconnect before replying.');
      const item = requests.find(r => r.sessionID === input.sessionID && r.request.id === input.requestID && r.ticket === input.ticket);
      if (!item) fail(409, 'This request changed. Review the latest request before replying.');
      const key = keyOf(item);
      if (item.sending || blocked.has(key)) fail(409, 'This request was already sent or is awaiting acknowledgment. Check the Mac; do not resend it.');
      if (!validReply(item.request, input)) fail(400, 'Choose only offered options or an allowed custom answer. Review required questions.');
      if (pendingReplies.size >= 8) fail(429, 'Too many replies are awaiting acknowledgment. Wait for the Mac.');
      const id = secret();
      blocked.add(key);
      const result = await new Promise(resolve => {
        const timer = setTimeout(() => {
          pendingReplies.delete(id);
          resolve({ status: 504, error: 'The agent did not acknowledge in time. Check the Mac before taking another action.' });
        }, ackTimeout);
        pendingReplies.set(id, { key, deviceID: device.id, resolve, timer });
        emit({ type: 'reply', id, sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket,
          decision: input.decision, answers: input.answers,
          ...(input.permissionOptionID !== undefined ? { permissionOptionID: input.permissionOptionID } : {}),
          ...(input.feedback !== undefined ? { feedback: input.feedback } : {})
        });
      });
      return json(response, result.status, result.error ? { error: result.error } : { ok: true });
    }
    fail(404, 'Unknown route.');
  }

  function guard(request, response, expectedHost) {
    headers(response);
    if (!sameSubnet(request.socket.remoteAddress, network)) fail(403, 'Same-subnet LAN connections only.');
    if (request.headers.host !== expectedHost) fail(403, 'Unrecognized host.');
    if (request.url.length > 4096) fail(414, 'URL too long.');
    rate(`all:${request.socket.remoteAddress}`, 240, 60000);
    if (activeRequests >= 32) fail(503, 'Too many active requests. Try again shortly.');
    activeRequests++;
    let done = false;
    const release = () => { if (!done) { activeRequests--; done = true; } };
    response.once('finish', release); response.once('close', release);
  }
  async function handle(request, response, bootstrap) {
    try {
      guard(request, response, new URL(bootstrap ? app.setupURL : app.url).host);
      const path = request.url;
      if (bootstrap) {
        if (request.method !== 'GET') fail(405, 'Setup is read-only.');
        if (path === '/ca.cer') {
          response.writeHead(200, { 'Content-Type': 'application/x-x509-ca-cert', 'Content-Disposition': 'attachment; filename="Notify-Local-CA.cer"' });
          response.end(new (await import('node:crypto')).X509Certificate(tls.ca).raw);
        } else if (path === '/') {
          response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          response.end('<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"><title>Notify certificate setup</title><h1>Connect Notify securely</h1><p>This HTTP page is not authenticated. Never enter pairing codes here.</p><ol><li>Download the public <a href="/ca.cer">Notify local CA certificate</a>.</li><li>Before trusting it, compare its SHA-256 fingerprint with Notify Settings on your Mac using a trusted certificate viewer. If you cannot verify the fingerprint, stop.</li><li>Only after a match, manually install and trust the certificate for websites. This grants trust for private-network sites; remove it when finished.</li><li>Open the exact HTTPS address shown on the Mac. Install to Home Screen, open the installed app, then pair there with a fresh Mac code.</li></ol><p>iPhone: Settings → General → VPN &amp; Device Management to install; General → About → Certificate Trust Settings to enable full trust. Android: Settings → Security → Encryption &amp; credentials → Install a CA certificate (names vary).</p><p>To remove trust: delete the Notify certificate/profile from those settings. No private key, pairing code, or request data is available on this setup server.</p></html>');
        } else fail(404, 'Setup route not found.');
        return;
      }
      if (path.startsWith('/api/')) return await api(request, response, path);
      if (!mime[path]) fail(404, 'Not found.');
      if (request.method !== 'GET') fail(405, 'Use GET for the app shell.');
      const [file, type] = mime[path];
      const content = await readFile(fileURLToPath(new URL(file, publicDirectory)));
      response.writeHead(200, { 'Content-Type': type });
      response.end(content);
    } catch (error) {
      if (!(error instanceof HttpError)) report('Mobile request failed. Check private data permissions and the packaged app resources.');
      json(response, error.status ?? 500, { error: error instanceof HttpError ? error.message : 'The Mac could not complete this request. Check Notify on the Mac.' });
    }
  }
  const secure = https.createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2', maxHeaderSize: 8192 },
    (request, response) => { void handle(request, response, false); });
  const setup = http.createServer({ maxHeaderSize: 8192 }, (request, response) => { void handle(request, response, true); });
  for (const server of [secure, setup]) {
    server.maxConnections = 48;
    server.requestTimeout = 10000;
    server.headersTimeout = 10000;
    server.keepAliveTimeout = 3000;
    server.setTimeout(30000, socket => socket.destroy());
  }
  try {
    await listen(secure, httpsPort, network.address);
    app.url = `https://${network.address}:${secure.address().port}`;
    await listen(setup, httpPort, network.address);
    app.setupURL = `http://${network.address}:${setup.address().port}`;
  } catch (error) {
    secure.closeAllConnections(); secure.close();
    setup.closeAllConnections(); setup.close();
    throw new Error(`Cannot bind local mobile ports (${error.code ?? 'listen failure'}). Check ports 8443/8080 and the LAN connection.`);
  }
  for (const server of [secure, setup]) server.on('error', () => {
    available = false; report('Mobile LAN listener failed. Disable and enable mobile to reconnect.');
    void close();
  });
  const timer = setInterval(() => {
    for (const [id, pending] of pendingPairs) if (pending.expires <= now()) pendingPairs.delete(id);
    if (invite?.expires <= now()) { invite = undefined; status(); }
    if (available && !fresh()) {
      available = false;
      cancelReplies('The native request snapshot expired. Reconnect to the Mac.', 503);
      status();
    }
    if (!testOnlyLoopback && !networkPresent(network)) {
      available = false; report('The Mac LAN address changed. Disable and enable mobile, then open the new address on your phone.');
      void close();
    }
  }, 1000);
  timer.unref();
  async function close() {
    if (closed) return;
    closed = true; available = false; requests = [];
    clearInterval(timer);
    cancelReplies('Mobile was disabled on the Mac.', 503);
    pendingPairs.clear(); lastSeen.clear();
    for (const server of [secure, setup]) server.closeAllConnections();
    await Promise.all([secure, setup].map(server => new Promise(resolve => server.close(resolve))));
    await pushQueue;
  }
  status();
  return app;
}
