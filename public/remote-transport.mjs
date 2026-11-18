import { leaseStart, localLease } from './remote-lease.mjs';

const MAX_FRAME = 1_064_960;
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const base64 = bytes => {
  bytes = new Uint8Array(bytes);
  let value = '';
  for (let start = 0; start < bytes.length; start += 8192) value += String.fromCharCode(...bytes.subarray(start, start + 8192));
  return btoa(value);
};
export const base64url = bytes => base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export function decodeBase64url(value) {
  if (typeof value !== 'string' || value.length > MAX_FRAME * 2 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid base64url value.');
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
  if (base64url(bytes) !== value) throw new Error('Non-canonical base64url value.');
  return bytes;
}
export function publicKey(value) {
  const bytes = decodeBase64url(value);
  if (bytes.length !== 65 || bytes[0] !== 4) throw new Error('A complete P-256 public key is required. Scan the QR code on your Mac again.');
  return bytes;
}
export function parseSetup(hash) {
  if (!hash) return null;
  if (hash.length > 1024) throw new Error('Invalid setup QR code.');
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  if ([...params].length !== 3 || !identifier(params.get('setup')) || !identifier(params.get('mac'))) throw new Error('Invalid setup QR code.');
  publicKey(params.get('key'));
  return { setupID: params.get('setup'), macID: params.get('mac'), macPublicKey: params.get('key') };
}
export async function postJSON(path, data, timeout = 15000, signal) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeout);
  const aborted = () => controller.abort();
  signal?.addEventListener('abort', aborted, { once: true });
  if (signal?.aborted) aborted();
  try {
    const response = await fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(data), signal: controller.signal });
    const httpError = response.ok ? null : Object.assign(new Error(`Request failed (${response.status}).`), { status: response.status });
    const reader = response.body?.getReader();
    if (!reader) throw httpError ?? new Error('Server response is empty.');
    const chunks = []; let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > MAX_FRAME) { await reader.cancel(); throw new Error('Server response is too large.'); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const body = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
    controller.signal.throwIfAborted();
    let result;
    try { result = JSON.parse(decoder.decode(body)); }
    catch { throw httpError ?? new Error('Invalid server response.'); }
    if (httpError) {
      if (typeof result?.error === 'string' && result.error.trim().length && result.error.length <= 500)
        httpError.message = result.error;
      throw httpError;
    }
    if (!object(result)) throw new Error('Invalid server response.');
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Request timed out. Check your connection and try again.');
    throw error;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', aborted); }
}
export function credentialJSON(credential, mode) {
  if (!credential || credential.type !== 'public-key') throw new Error('Passkey authentication did not complete.');
  const r = credential.response;
  if (mode === 'login' && (!r.userHandle || !r.userHandle.byteLength)) throw new Error('This passkey did not supply its user handle. Choose an account passkey; no fallback identity is used.');
  const response = { clientDataJSON: base64url(r.clientDataJSON) };
  if (mode === 'register') {
    response.attestationObject = base64url(r.attestationObject);
    if (r.getTransports) response.transports = r.getTransports();
  } else {
    Object.assign(response, { authenticatorData: base64url(r.authenticatorData),
      signature: base64url(r.signature), userHandle: base64url(r.userHandle) });
  }
  return { id: credential.id, rawId: base64url(credential.rawId), type: credential.type, response,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}) };
}
export async function authenticate(mode, name) {
  if (!['login', 'register'].includes(mode) || !globalThis.PublicKeyCredential) throw new Error('Passkeys require a supported browser and a secure connection.');
  const options = await postJSON(`/v1/account/${mode}/options`, mode === 'register' ? { name } : {});
  const helper = mode === 'register' ? PublicKeyCredential.parseCreationOptionsFromJSON : PublicKeyCredential.parseRequestOptionsFromJSON;
  let parsed;
  if (helper) parsed = helper.call(PublicKeyCredential, options);
  else {
    parsed = { ...options, challenge: decodeBase64url(options.challenge) };
    if (mode === 'register') parsed.user = { ...options.user, id: decodeBase64url(options.user.id) };
    for (const field of ['allowCredentials', 'excludeCredentials']) {
      if (options[field]) parsed[field] = options[field].map(item => ({ ...item, id: decodeBase64url(item.id) }));
    }
  }
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 60000);
  try {
    const credential = await navigator.credentials[mode === 'register' ? 'create' : 'get']({ publicKey: parsed, signal: controller.signal });
    return await postJSON(`/v1/account/${mode}/verify`, { response: credentialJSON(credential, mode) });
  } finally { clearTimeout(timer); }
}

let cryptoModule;
export async function loadCrypto() {
  if (!cryptoModule) cryptoModule = (async () => {
    const module = await import('./remote-crypto/channel.js');
    const response = await fetch(new URL('./remote-crypto/channel_bg.wasm', import.meta.url),
      { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error('Encrypted channel could not load. Reload to try again.');
    await module.default({ module_or_path: await response.arrayBuffer() });
    return module;
  })().catch(error => { cryptoModule = undefined; throw error; });
  return cryptoModule;
}

/** Connect creates a fresh MLS group; signed short-lease renewal preserves it without replaying RPCs. */
export function createRemoteTransport({ origin = location.origin, macID, deviceID, pinnedMacKey, autoReconnect = false,
  restorePeer, post = postJSON, WebSocketImpl = WebSocket, onStatus = () => {},
  lifecycle = globalThis.window, visibility = globalThis.document }) {
  let generation = 0, peer, socket, stage = 'closed', epoch, handshakeTimer, reconnectTimer, attempts = 0;
  let lease, deadline, expiryTimer, renewalTimer, controller, renewing = false, wanted = false;
  const pending = new Map();
  const uncertainty = () => Object.assign(new Error('Connection lost; delivery is uncertain. Check the Mac before sending again. Nothing was retried.'), { network: true, uncertain: true });
  function reset(message = 'Disconnected. No actions are queued.') {
    generation++; clearTimeout(handshakeTimer); clearTimeout(reconnectTimer);
    clearTimeout(expiryTimer); clearTimeout(renewalTimer); controller?.abort();
    stage = 'closed'; epoch = undefined; lease = undefined; renewing = false;
    for (const call of pending.values()) call.reject(uncertainty());
    pending.clear();
    const old = socket; socket = undefined;
    if (old) { old.onopen = old.onclose = old.onerror = old.onmessage = null; old.close(); }
    peer?.free(); peer = undefined;
    onStatus({ state: 'disconnected', message });
  }
  function close(message) {
    wanted = false;
    lifecycle?.removeEventListener('online', resume);
    visibility?.removeEventListener('visibilitychange', resume);
    reset(message);
  }
  function resume() {
    if (!wanted || !autoReconnect || visibility?.hidden) return;
    if (stage === 'closed' || (lease && !liveLease())) {
      attempts = 0;
      void start().catch(() => {});
    }
  }
  function disconnected(message) {
    reset(message);
    if (!autoReconnect || !wanted) return;
    const delay = attempts < 5 ? 1000 * 2 ** attempts++ : 30000;
    onStatus({ state: 'disconnected', message: `${message} Reconnecting safely in ${delay / 1000}s; no actions will be retried.` });
    reconnectTimer = setTimeout(() => { void start().catch(() => {}); }, delay);
  }
  function validLease(result, id, started, previousChallenge) {
    const renewal = result?.renewal;
    if (!object(result) || result.role !== 'phone' || result.macID !== macID || result.deviceID !== deviceID ||
      typeof result.approved !== 'boolean' || (previousChallenge !== undefined && lease.approved && !result.approved) ||
      !object(renewal) || renewal.id !== id || !/^[A-Za-z0-9_-]{43}$/.test(id) ||
      typeof renewal.challenge !== 'string' || !renewal.challenge.length ||
      encoder.encode(renewal.challenge).length > 4096 || renewal.challenge === previousChallenge)
      throw new Error('Channel authorization does not match this phone.');
    return localLease(result, started);
  }
  function liveLease() {
    return lease && Date.now() < lease.expiresAt && performance.now() < deadline;
  }
  function applyLease(result, timing) {
    lease = { ...result, expiresAt: timing.expiresAt };
    const { remaining } = timing;
    deadline = timing.deadline;
    clearTimeout(expiryTimer);
    expiryTimer = setTimeout(() => disconnected('Channel authorization expired. No actions were retried.'), remaining);
  }
  function scheduleRenewal(current, signal) {
    renewalTimer = setTimeout(async () => {
      if (current !== generation || signal.aborted) return;
      scheduleRenewal(current, signal);
      if (renewing) return;
      renewing = true;
      try {
        if (!liveLease() || socket?.readyState !== 1) throw uncertainty();
        const { id, challenge } = lease.renewal;
        const signature = base64url(peer.sign_authorization(encoder.encode(challenge)));
        const started = leaseStart();
        const result = await post('/v1/remote/grant/renew', { id, signature }, 10000, signal);
        if (current !== generation || signal.aborted) return;
        if (!liveLease()) throw uncertainty();
        applyLease(result, validLease(result, id, started, challenge));
      } catch (error) {
        // An uncertain response may already have consumed the nonce. Never retry it.
        if (current === generation && !signal.aborted) {
          if (error.status === 401 || error.status === 403) close(error.message);
          else disconnected('Channel authorization lost. Delivery may be uncertain; no actions were retried.');
        }
      } finally { if (current === generation) renewing = false; }
    }, 10000);
  }
  function send(bytes) {
    if (!liveLease() || !socket || socket.readyState !== 1 || bytes.byteLength > MAX_FRAME || socket.bufferedAmount > MAX_FRAME) throw uncertainty();
    socket.send(bytes);
  }
  function encrypted(value) { send(peer.send(encoder.encode(JSON.stringify(value)))); }
  function receive(event) {
    if (!liveLease()) {
      disconnected('Channel authorization expired. No actions were retried.');
      return;
    }
    try {
      if (stage === 'greeting') {
        if (event.data !== '{"type":"ready","version":1}') throw new Error('Invalid relay greeting.');
        send(encoder.encode(JSON.stringify({ type: 'key_package', bytes: [...peer.key_package()] })));
        stage = 'welcome'; return;
      }
      if (!(event.data instanceof ArrayBuffer) || !event.data.byteLength || event.data.byteLength > MAX_FRAME) throw new Error('Invalid relay frame.');
      const bytes = new Uint8Array(event.data);
      if (stage === 'welcome') {
        const value = JSON.parse(decoder.decode(bytes));
        const validBytes = value => Array.isArray(value) && value.length > 0 && value.length <= MAX_FRAME
          && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255);
        if (value.type !== 'welcome' || !validBytes(value.welcome) || !validBytes(value.tree)) throw new Error('Invalid encrypted-channel welcome.');
        peer.join_pinned(new Uint8Array(value.welcome), new Uint8Array(value.tree), pinnedMacKey);
        stage = 'approval'; encrypted({ type: 'hello' });
        onStatus({ state: 'pending', message: 'Compare the complete public key on your Mac, then approve there.' });
        return;
      }
      const message = peer.receive(bytes);
      let value;
      try {
        // sender() is the authenticated MLS credential label, not the identity key.
        // join_pinned above verifies the complete Mac key; native owns this label.
        if (decoder.decode(message.sender()) !== 'native') throw new Error('Unexpected encrypted message sender.');
        value = JSON.parse(decoder.decode(message.bytes()));
      } finally { message.free(); }
      if (!object(value)) throw new Error('Invalid encrypted response.');
      if (value.type === 'pending' && stage === 'approval') return;
      if (value.type === 'ready' && stage === 'approval' && uuid(value.epoch)) {
        epoch = value.epoch; stage = 'ready'; attempts = 0; clearTimeout(handshakeTimer);
        onStatus({ state: 'connected', message: 'Encrypted channel connected.' }); return;
      }
      if (stage !== 'ready' || !uuid(value.id) || !Number.isInteger(value.status) || value.status < 100 || value.status > 599 || !object(value.data)) {
        throw new Error('Invalid encrypted RPC response.');
      }
      const call = pending.get(value.id);
      if (!call) return; // A timed-out read may finish later; it must not resolve a different call.
      if (value.status >= 200 && value.status < 300) call.resolve(value.data);
      else call.reject(Object.assign(new Error(typeof value.data.error === 'string' ? value.data.error : `Mac request failed (${value.status}).`), { status: value.status }));
    } catch { close('Encrypted channel validation failed. Reconnect only after checking the paired Mac.'); }
  }
  function connect() {
    wanted = true; attempts = 0;
    if (autoReconnect) {
      lifecycle?.addEventListener('online', resume);
      visibility?.addEventListener('visibilitychange', resume);
    }
    return start();
  }
  async function start() {
    reset(); const current = generation;
    controller = new AbortController();
    const signal = controller.signal;
    stage = 'connecting';
    onStatus({ state: 'connecting', message: 'Connecting to your Mac…' });
    try {
      const restored = await restorePeer();
      if (current !== generation) { restored.free(); return; }
      peer = restored;
      const grant = await post('/v1/remote/grant/begin', { role: 'phone', macID, deviceID }, 15000, signal);
      if (current !== generation) return;
      if (!/^[A-Za-z0-9_-]{43}$/.test(grant.id) || typeof grant.challenge !== 'string' || !grant.challenge.length ||
        encoder.encode(grant.challenge).length > 4096) throw new Error('Invalid channel authorization challenge.');
      const signature = base64url(peer.sign_authorization(encoder.encode(grant.challenge)));
      const started = leaseStart();
      const result = await post('/v1/remote/grant/finish', { id: grant.id, signature }, 15000, signal);
      if (current !== generation) return;
      applyLease(result, validLease(result, grant.id, started));
      const url = new URL('/v1/relay', origin);
      if (url.protocol === 'https:') url.protocol = 'wss:';
      else if (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) url.protocol = 'ws:';
      else throw new Error('A secure connection is required.');
      socket = new WebSocketImpl(url.href, 'notify-relay-v1'); socket.binaryType = 'arraybuffer';
      stage = 'greeting'; socket.onmessage = receive;
      socket.onopen = () => {
        if (current !== generation || signal.aborted) return;
        scheduleRenewal(current, signal);
      };
      socket.onerror = socket.onclose = () => disconnected('Mac connection lost. Check its network. No replies were retried.');
      handshakeTimer = setTimeout(() => disconnected('Pairing or connection timed out. Check your Mac.'), 120000);
    } catch (error) {
      if (current === generation) {
        if ((error.status && error.status !== 429 && error.status < 500) || error.code) close(error.message);
        else disconnected(error.message);
        throw error;
      }
    }
  }
  function api(path, data = {}, timeout, signal) {
    return new Promise((resolve, reject) => {
      if (stage !== 'ready') { reject(new Error('An approved, connected Mac is required.')); return; }
      if (!['state', 'workspace', 'reply', 'control'].includes(path) || !object(data)) { reject(new Error('Unsupported Mac request.')); return; }
      if (pending.size >= 8) { reject(new Error('Connection is busy. Wait for the current requests.')); return; }
      if (signal?.aborted) { reject(Object.assign(new Error('Request cancelled.'), { aborted: true })); return; }
      const id = crypto.randomUUID();
      let timer;
      const finish = fn => value => { clearTimeout(timer); signal?.removeEventListener('abort', abort); pending.delete(id); fn(value); };
      const abort = () => pending.get(id)?.reject(Object.assign(uncertainty(), { aborted: true }));
      pending.set(id, { resolve: finish(resolve), reject: finish(reject) });
      signal?.addEventListener('abort', abort, { once: true });
      const mutation = path === 'reply' || path === 'control';
      const wait = timeout === undefined ? (mutation ? 25000 : 12000) : timeout;
      timer = setTimeout(abort, Number.isFinite(wait) ? Math.min(mutation ? 30000 : 15000, Math.max(1, wait)) : (mutation ? 25000 : 12000));
      try { encrypted({ id, epoch, payload: { path, data } }); }
      catch { disconnected('Connection lost; delivery is uncertain. No actions were retried.'); }
    });
  }
  return { connect, api, close };
}
