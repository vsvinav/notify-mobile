import { performance } from 'node:perf_hooks';
import WebSocket from 'ws';

const FRAME_LIMIT = 1_048_576 + 16_384;
const READY = '{"type":"ready","version":1}';

// Opaque transport only. receive must authenticate/decrypt before any dispatch.
// A successful send is a local socket write, never a peer or runtime receipt.
export async function connectRemoteRelay({ url, credential, expiresAt, signal, receive, ca }) {
  let endpoint;
  try {
    if (typeof url !== 'string' || url.length > 2048) throw new Error();
    endpoint = new URL(url);
    if (endpoint.protocol !== 'wss:' || endpoint.username || endpoint.password ||
      endpoint.pathname !== '/v1/relay' || endpoint.search || endpoint.hash) throw new Error();
  } catch {
    throw new Error('Invalid remote relay endpoint.');
  }
  if (typeof credential !== 'string' || credential.length > 4096 || !/^[a-zA-Z0-9._~+/-]+=*$/.test(credential))
    throw new Error('Invalid remote relay credential.');
  const remaining = expiresAt - Date.now();
  if (!Number.isSafeInteger(expiresAt) || !(remaining > 0 && remaining <= 30000))
    throw new Error('Invalid remote relay authorization lifetime.');
  if (!(signal instanceof AbortSignal) || signal.aborted || typeof receive !== 'function')
    throw new Error('Remote relay authorization is revoked or its receiver is invalid.');
  if (ca !== undefined && typeof ca !== 'string' && !Buffer.isBuffer(ca))
    throw new Error('Invalid remote relay trusted certificate.');

  const deadline = performance.now() + remaining;
  let ws;
  try {
    ws = new WebSocket(endpoint, 'notify-relay-v1', {
      headers: { authorization: `Bearer ${credential}` },
      ca, rejectUnauthorized: true, followRedirects: false, perMessageDeflate: false,
      autoPong: false, maxPayload: FRAME_LIMIT, handshakeTimeout: Math.min(5000, remaining)
    });
  } catch {
    throw new Error('Remote relay connection failed.');
  }
  const controller = new AbortController(), queue = [], writes = new Set();
  let opened = false, stopped = false, terminalError = null, processing = false, queuedBytes = 0;
  let window = performance.now(), messages = 0, bytes = 0;
  let readyResolve, readyReject, closedResolve;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const closed = new Promise(resolve => { closedResolve = resolve; });
  const expired = () => finish(new Error('Remote relay authorization expired.'));
  const revoked = () => finish(new Error('Remote relay authorization revoked.'));
  const timer = setTimeout(expired, remaining);
  timer.unref();

  function finish(error) {
    if (stopped) return;
    stopped = true; terminalError = error;
    clearTimeout(timer);
    signal.removeEventListener('abort', revoked);
    controller.abort();
    queue.length = 0; queuedBytes = 0;
    const failure = error ?? new Error('Remote relay connection closed.');
    readyReject(failure);
    for (const write of writes) write.reject(failure);
    writes.clear();
    ws.terminate();
  }

  function live() {
    if (stopped) return false;
    if (signal.aborted) { revoked(); return false; }
    if (performance.now() >= deadline) { expired(); return false; }
    return true;
  }

  function consume(size) {
    if (!live()) return false;
    const now = performance.now();
    if (now - window >= 1000) { window = now; messages = 0; bytes = 0; }
    messages++; bytes += size;
    if (messages > 64 || bytes > 4 * FRAME_LIMIT) {
      finish(new Error('Remote relay receive rate limit reached.'));
      return false;
    }
    return true;
  }

  async function drain() {
    if (processing) return;
    processing = true;
    while (queue.length && live()) {
      const data = queue.shift();
      try {
        await receive(data, { signal: controller.signal });
      } catch {
        finish(new Error('Remote relay frame processing failed.'));
      }
      if (!stopped) queuedBytes -= data.length;
    }
    processing = false;
  }

  const connection = Object.freeze({
    signal: controller.signal, closed,
    close() { finish(null); return closed; },
    async send(data) {
      if (!live() || !opened || ws.readyState !== WebSocket.OPEN)
        throw terminalError ?? new Error('Remote relay connection closed.');
      if (!Buffer.isBuffer(data) || data.length > FRAME_LIMIT)
        throw new Error('Remote relay requires a bounded binary frame.');
      if (writes.size >= 8 || ws.bufferedAmount + data.length > 2 * FRAME_LIMIT) {
        finish(new Error('Remote relay write buffer limit reached.'));
        throw terminalError;
      }
      const payload = Buffer.from(data);
      return new Promise((resolve, reject) => {
        const write = { reject };
        writes.add(write);
        ws.send(payload, { binary: true }, error => {
          writes.delete(write);
          if (error) finish(new Error('Remote relay write failed.'));
          if (stopped) reject(terminalError ?? new Error('Remote relay connection closed.'));
          else resolve();
        });
      });
    }
  });

  ws.on('error', () => finish(new Error('Remote relay connection failed.')));
  ws.on('close', () => {
    finish(new Error('Remote relay peer disconnected; delivery may be unknown.'));
    closedResolve(terminalError);
  });
  ws.on('ping', data => {
    if (!consume(data.length)) return;
    if (ws.bufferedAmount + data.length > 2 * FRAME_LIMIT)
      return finish(new Error('Remote relay write buffer limit reached.'));
    ws.pong(data, error => { if (error) finish(new Error('Remote relay write failed.')); });
  });
  ws.on('pong', data => { consume(data.length); });
  ws.on('message', (data, binary) => {
    if (!consume(data.length)) return;
    if (!opened) {
      if (binary || data.length !== READY.length || data.toString() !== READY)
        return finish(new Error('Invalid remote relay ready frame.'));
      opened = true;
      readyResolve(connection);
      return;
    }
    if (!binary || !Buffer.isBuffer(data))
      return finish(new Error('Remote relay requires binary frames after readiness.'));
    if (queue.length + Number(processing) >= 8 || queuedBytes + data.length > 2 * FRAME_LIMIT)
      return finish(new Error('Remote relay receive buffer limit reached.'));
    queuedBytes += data.length;
    queue.push(Buffer.from(data));
    void drain();
  });
  signal.addEventListener('abort', revoked, { once: true });
  if (signal.aborted) revoked();
  return ready;
}
