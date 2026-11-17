import { STATUS_CODES } from 'node:http';
import { performance } from 'node:perf_hooks';
import WebSocket, { WebSocketServer } from 'ws';
import { createIngressPolicy } from './managed-ingress.mjs';

const PROTOCOL = 'notify-relay-v1';
const FRAME_LIMIT = 1_048_576 + 16_384;
const GRANT_FIELDS = ['issuer', 'subject', 'macID', 'deviceID', 'role', 'expiresAt', 'signal'];
const identity = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !value.includes('\0');

function origin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash)
    throw new Error('Relay origins must be HTTPS origins without credentials, paths or queries.');
  return url;
}

function rejectUpgrade(socket, status) {
  if (socket.destroyed || socket.writableEnded) return;
  socket.end(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n`);
  const timer = setTimeout(() => socket.destroy(), 1000);
  timer.unref();
  socket.once('close', () => clearTimeout(timer));
}

// Transport only. authorize must verify service credentials; endpoint crypto must
// authenticate peers and payloads. Neither routing nor "ready" grants session access.
export function createRemoteRelay({ server, publicOrigin, webOrigin, authorize, reportError, managedIngress }) {
  const ingress = createIngressPolicy({ server, publicOrigin, managedIngress });
  if (server.listening || server.listenerCount('upgrade'))
    throw new Error('Relay requires a dedicated HTTPS server before it starts listening.');
  if (typeof authorize !== 'function' || typeof reportError !== 'function')
    throw new Error('Relay requires an authorizer and an error reporter.');
  origin(publicOrigin);
  const browserOrigin = origin(webOrigin).origin;
  const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, autoPong: false,
    maxPayload: FRAME_LIMIT, handleProtocols: () => PROTOCOL });
  const rooms = new Map(), pending = new Set();
  let closed = false, closing;
  server.maxConnections = 160;
  server.maxHeadersCount = 32;
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  server.keepAliveTimeout = 1000;

  function drop(room, code, reason) {
    if (rooms.get(room.key) !== room) return;
    rooms.delete(room.key);
    for (const connection of [room.mac, room.phone]) {
      if (!connection) continue;
      clearTimeout(connection.timer);
      connection.signal.removeEventListener('abort', connection.revoked);
      if (connection.ws.readyState === WebSocket.CLOSED) continue;
      connection.ws.close(code, reason);
      const timer = setTimeout(() => connection.ws.terminate(), 1000);
      timer.unref();
      connection.ws.once('close', () => clearTimeout(timer));
    }
  }

  function live(room, connection) {
    if (rooms.get(room.key) !== room) return false;
    if (!connection || connection.ws.readyState !== WebSocket.OPEN || connection.signal.aborted ||
      performance.now() >= connection.deadline) {
      drop(room, 1008, 'Peer unavailable or authorization expired.');
      return false;
    }
    return true;
  }

  function consume(room, connection, size) {
    if (!live(room, connection)) return false;
    const now = performance.now();
    if (now - connection.window >= 1000) {
      connection.window = now; connection.messages = 0; connection.bytes = 0;
    }
    connection.messages++; connection.bytes += size;
    if (connection.messages > 64 || connection.bytes > 4 * FRAME_LIMIT) {
      drop(room, 1008, 'Relay rate limit reached.');
      return false;
    }
    return true;
  }

  function send(room, destination, data) {
    if (!live(room, destination)) return;
    if (destination.ws.bufferedAmount + data.length > 2 * FRAME_LIMIT) {
      drop(room, 1008, 'Relay backpressure limit reached.');
      return;
    }
    destination.ws.send(data, error => {
      if (error) {
        reportError(new Error('Relay delivery failed.'));
        drop(room, 1011, 'Relay delivery failed.');
      }
    });
  }

  async function upgrade(req, socket, head) {
    let controller;
    const socketFailed = () => { controller?.abort(); reportError(new Error('Relay connection failed.')); };
    const socketClosed = () => socket.off('error', socketFailed);
    socket.once('error', socketFailed);
    socket.once('close', socketClosed);
    if (closed) return rejectUpgrade(socket, 503);
    if (!ingress.accepts(req)) return rejectUpgrade(socket, 403);
    if (req.url !== '/v1/relay') return rejectUpgrade(socket, 404);
    if (req.method !== 'GET' || req.headers['sec-websocket-protocol'] !== PROTOCOL)
      return rejectUpgrade(socket, 400);
    if (req.headers.origin !== undefined && req.headers.origin !== browserOrigin)
      return rejectUpgrade(socket, 403);
    if (pending.size >= 16 || pending.size + wss.clients.size >= 128) return rejectUpgrade(socket, 503);
    controller = new AbortController();
    const record = { socket, controller };
    pending.add(record);
    const deny = status => {
      rejectUpgrade(socket, status);
      controller.abort();
    };
    const timer = setTimeout(() => deny(504), 2000);
    timer.unref();
    const disconnected = () => controller.abort();
    socket.once('close', disconnected);
    let upgraded = false;
    try {
      const grant = await authorize(req, { signal: controller.signal });
      if (controller.signal.aborted || socket.destroyed || closed) return;
      const remaining = grant?.expiresAt - Date.now();
      if (!grant || Object.keys(grant).length !== GRANT_FIELDS.length ||
        !GRANT_FIELDS.every(field => Object.hasOwn(grant, field)) ||
        !['issuer', 'subject', 'macID', 'deviceID'].every(field => identity(grant[field])) ||
        !['mac', 'phone'].includes(grant.role) || !Number.isSafeInteger(grant.expiresAt) ||
        !(remaining > 0 && remaining <= 30000) || !(grant.signal instanceof AbortSignal) || grant.signal.aborted)
        return deny(401);
      const role = grant.role;
      if (role === 'phone' ? req.headers.origin !== browserOrigin : req.headers.origin !== undefined)
        return deny(403);
      const owner = JSON.stringify([grant.issuer, grant.subject, grant.macID]);
      const key = JSON.stringify([grant.issuer, grant.subject, grant.macID, grant.deviceID]);
      let room = rooms.get(key);
      if (room?.[role]) return deny(409);
      if (!room && (rooms.size >= 64 || [...rooms.values()].filter(value => value.owner === owner).length >= 8))
        return deny(429);
      if (wss.clients.size >= 128) return deny(503);
      const deadline = performance.now() + remaining;
      wss.handleUpgrade(req, socket, head, ws => {
        upgraded = true;
        room ??= { key, owner };
        rooms.set(key, room);
        const connection = { ws, signal: grant.signal, deadline, window: performance.now(), messages: 0, bytes: 0 };
        room[role] = connection;
        connection.revoked = () => drop(room, 1008, 'Relay authorization revoked.');
        connection.signal.addEventListener('abort', connection.revoked, { once: true });
        connection.timer = setTimeout(() => drop(room, 1008, 'Relay authorization expired.'), remaining);
        connection.timer.unref();
        ws.on('error', () => {
          reportError(new Error('Relay WebSocket failed.'));
          drop(room, 1011, 'Relay WebSocket failed.');
        });
        ws.on('close', () => drop(room, 1001, 'Peer disconnected.'));
        ws.on('ping', data => { if (consume(room, connection, data.length)) ws.pong(data); });
        ws.on('pong', data => { consume(room, connection, data.length); });
        ws.on('message', (data, binary) => {
          if (!consume(room, connection, data.length)) return;
          if (!binary || !Buffer.isBuffer(data)) return drop(room, 1003, 'Binary relay frames required.');
          send(room, room[role === 'mac' ? 'phone' : 'mac'], data);
        });
        if (room.mac && room.phone) {
          send(room, room.mac, '{"type":"ready","version":1}');
          send(room, room.phone, '{"type":"ready","version":1}');
        }
      });
    } catch {
      if (!controller.signal.aborted && !closed) {
        reportError(new Error('Relay authorization or upgrade failed.'));
        deny(503);
      }
    } finally {
      clearTimeout(timer);
      socket.off('close', disconnected);
      if (upgraded || socket.destroyed) {
        socket.off('error', socketFailed);
        socket.off('close', socketClosed);
      } else {
        controller.abort();
      }
      // Keep timed-out authorizers in this bounded set until they actually settle.
      pending.delete(record);
    }
  }

  const request = (req, res) => {
    if (ingress.health(req, res)) return;
    res.writeHead(404, { 'Cache-Control': 'no-store' }); res.end();
  };
  if (managedIngress && !server.listenerCount('request')) server.on('request', request);
  server.on('upgrade', upgrade);
  return Object.freeze({
    close() {
      if (closing) return closing;
      closed = true;
      server.off('request', request);
      server.off('upgrade', upgrade);
      for (const record of pending) { record.controller.abort(); record.socket.destroy(); }
      for (const room of rooms.values()) drop(room, 1001, 'Relay shutting down.');
      for (const ws of wss.clients) ws.terminate();
      closing = new Promise((resolve, reject) => wss.close(error => error ? reject(error) : resolve()));
      return closing;
    }
  });
}
