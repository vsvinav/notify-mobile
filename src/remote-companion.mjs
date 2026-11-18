import { randomUUID, createHash, createPublicKey } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { privateDirectory, readPrivate, writePrivate } from './storage.mjs';
import { RemoteAccess } from './remote-access.mjs';
import { connectRemoteRelay } from './remote-relay-client.mjs';
import { NativeCrypto } from './remote-crypto.mjs';
import { RemoteActions } from './remote-actions.mjs';
import { isOffID, isPolicyOffRPC } from './workspace.mjs';
import { object } from './validation.mjs';
import { leaseStart, localLease } from '../public/remote-lease.mjs';

const execute = promisify(execFile);
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(value);
const text = (value, limit) => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\0-\x1f\x7f]/.test(value);
const hash = key => createHash('sha256').update(Buffer.from(key, 'base64url')).digest('hex');
const ownerMismatchMessage = 'This account differs from the locally approved owner. Sign in with the original Notify passkey on your phone. If you cannot, turn off Enable internet and choose "Start fresh internet setup" on this Mac. Existing trust was not transferred.';
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const transient = error => error.retryable || ['TimeoutError', 'AbortError'].includes(error.name) ||
  ['ECONNRESET', 'ENETUNREACH', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EHOSTUNREACH', 'EPIPE', 'ECONNABORTED'].includes(error.code);
function bytes(value) {
  if (!Array.isArray(value) || value.length > 1_064_960 ||
    !value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) fail(400, 'Invalid encrypted-channel bytes.');
  return Buffer.from(value);
}
function validKey(value) {
  if (typeof value !== 'string' || !/^[\w-]{87}$/.test(value)) return false;
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 65 || key[0] !== 4 || key.toString('base64url') !== value) return false;
  try {
    createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
      x: key.subarray(1, 33).toString('base64url'), y: key.subarray(33).toString('base64url') } });
    return true;
  } catch { return false; }
}
function validDevice(device) {
  return object(device) && uuid(device.id) && text(device.name, 100) && validKey(device.publicKey);
}

function nativeRequest(url, { method, headers, body, signal }) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method, headers, signal, rejectUnauthorized: true }, response => {
      resolve({ status: response.statusCode, ok: response.statusCode >= 200 && response.statusCode < 300, body: response });
    });
    request.on('error', reject);
    request.end(body);
  });
}

export async function createRemoteCompanion({ directory, origin, emit,
  executable = fileURLToPath(new URL('../../remote-crypto/notify-channel', import.meta.url)),
  fetchRequest = nativeRequest, connectRelay = connectRemoteRelay,
  cryptoProcess = (path, args) => new NativeCrypto(path, args) }) {
  let endpoint;
  try { endpoint = new URL(origin); } catch { fail(400, 'Invalid internet service origin.'); }
  if (endpoint.protocol !== 'https:' || endpoint.origin !== origin || endpoint.username || endpoint.password)
    fail(400, 'Use an exact HTTPS internet service origin without a path.');
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
  await privateDirectory(directory);
  const file = join(directory, 'identity.json');
  let state, writer = Promise.resolve(), auth, signer, signerWork, policyWork;
  let closed = false, paused = false, polling, pollController, registration, pending, approving, setupID, serverDevices = [];
  let invitationWork, invitationUnavailable = false;
  let message = 'Waiting for phone sign-in.', fault, enrollmentError;
  const channels = new Map();
  const channelWork = new Set(), lifetime = new AbortController();
  let attentionWork, lastAttention = -Infinity;
  let genericAttention = false, attentionWaiting = false, attentionPending = false;
  let attentionUntil = 0, attentionWallUntil = 0, attentionError;
  const openCrypto = () => cryptoProcess(executable, ['load-identity', state.macID, JSON.stringify([...Buffer.from(state.publicKey, 'base64url')])]);
  const raw = await readPrivate(file);
  if (raw === null) {
    const macID = randomUUID();
    const { stdout } = await execute(executable, ['create-identity', macID], {
      timeout: 15000, maxBuffer: 4096, env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1' }
    });
    const publicKey = bytes(JSON.parse(stdout)).toString('base64url');
    if (!validKey(publicKey)) fail(503, 'Native identity creation returned an invalid public key.');
    state = { version: 1, origin, macID, publicKey, owner: null, devices: [], credential: null, setupID: null };
    try { await writePrivate(file, JSON.stringify(state)); }
    catch (error) {
      try { await execute(executable, ['delete-identity', macID], { timeout: 15000, maxBuffer: 4096 }); }
      catch { throw new AggregateError([error], 'Identity storage failed and the unused key needs local cleanup.'); }
      throw error;
    }
  } else {
    state = JSON.parse(raw.toString('utf8'));
    if (!object(state) || state.version !== 1 || state.origin !== origin || !uuid(state.macID) ||
      !validKey(state.publicKey) || !Array.isArray(state.devices) || state.devices.length > 8 ||
      !state.devices.every(validDevice) || new Set(state.devices.map(d => d.id)).size !== state.devices.length ||
      !(state.owner === null || (object(state.owner) && state.owner.issuer === origin && text(state.owner.subject, 256))) ||
      !(state.credential === null || (typeof state.credential === 'string' && /^[\w-]{43}$/.test(state.credential))) ||
      !(state.setupID === null || text(state.setupID, 256)) ||
      (state.owner === null && state.devices.length !== 0)) fail(503, 'Saved internet identity is invalid or belongs to another service. It was not replaced.');
  }
  function save(change) {
    const next = writer.then(async () => {
      const updated = change(state);
      await writePrivate(file, JSON.stringify(updated));
      state = updated;
    });
    writer = next.then(() => undefined, () => undefined);
    return next;
  }
  async function updatePolicy(work) {
    policyWork = work;
    try { await work; }
    finally { if (policyWork === work) policyWork = undefined; }
  }
  const actions = new RemoteActions({
    attention() { if (!genericAttention) publishAttention(true, true); },
    emit, devices: () => [...channels.values()].filter(c => c.handle && !c.signal.aborted)
      .map(c => ({ id: c.device.id, name: c.device.name, expires: c.expiresAt }))
  });
  function publishAttention(waiting, changed) {
    attentionWaiting = waiting;
    if (!waiting) { attentionPending = false; attentionError = undefined; return; }
    const now = performance.now();
    if (changed) {
      attentionPending = true;
      attentionUntil = now + 120000;
      attentionWallUntil = Date.now() + 120000;
    }
    if (attentionPending && (now >= attentionUntil || Date.now() >= attentionWallUntil)) {
      attentionPending = false;
      if (attentionError) {
        attentionError = 'Phone alert delivery was not confirmed. Check notification registration on the phone.';
        status();
      }
    }
    if (!attentionPending || closed || paused || fault || enrollmentError ||
      !state.owner || !state.credential || !state.devices.length || attentionWork || now - lastAttention < 32000) return;
    attentionPending = false;
    lastAttention = now;
    const credential = state.credential;
    const unavailable = () => {
      if (closed || credential !== state.credential || !attentionWaiting) return;
      attentionPending = true;
      attentionError = 'Phone alert delivery was not confirmed. Retrying briefly while a request is waiting.';
      status();
    };
    attentionWork = api('mac/attention', { eventID: randomUUID(), issuedAt: Date.now() }, credential)
      .then(result => {
        if (closed || credential !== state.credential) return;
        if (result.accepted !== true) { unavailable(); return; }
        attentionError = undefined;
        status();
      })
      .catch(unavailable)
      .finally(() => { attentionWork = undefined; });
  }
  async function api(path, body = {}, credential, signal) {
    const requestSignal = AbortSignal.any([lifetime.signal, AbortSignal.timeout(10000), ...(signal ? [signal] : [])]);
    requestSignal.throwIfAborted();
    const response = await fetchRequest(`${origin}/v1/remote/${path}`, {
      method: 'POST', redirect: 'error', headers: {
        'Content-Type': 'application/json', ...(credential ? { Authorization: `Bearer ${credential}` } : {})
      }, body: JSON.stringify(body), signal: requestSignal
    });
    requestSignal.throwIfAborted();
    const chunks = []; let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 65536) fail(502, 'Internet service response is too large.');
      chunks.push(chunk);
    }
    requestSignal.throwIfAborted();
    let value;
    try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { if (response.ok) fail(502, 'Invalid internet service response.'); }
    if (!response.ok) {
      let message = text(value?.error, 500) ? value.error : 'Internet service rejected the request.';
      if (response.status === 409 && path === 'mac/begin')
        message = 'This Mac already has an enrollment at the service. Wait three minutes, then choose "Pair an internet device" again. If it still fails, turn off Enable internet and choose "Start fresh internet setup". Your saved identity has not changed.';
      else if (response.status === 409 && path === 'mac/invite')
        message = 'Finish or reject the pending phone pairing on this Mac before requesting another invitation, or wait up to three minutes for it to expire. Your saved identity has not changed.';
      throw Object.assign(new Error(message),
        { status: response.status, retryable: response.status === 429 || response.status >= 500 });
    }
    if (!object(value)) fail(502, 'Invalid internet service response.');
    return value;
  }
  function status() {
    if (closed) return;
    const devices = state.devices.map(device => ({ id: device.id, name: device.name,
      online: !!channels.get(device.id)?.handle && !channels.get(device.id).signal.aborted, pushEnabled: false }));
    const active = devices.some(d => d.online);
    emit({ type: 'status', status: {
      state: fault || enrollmentError ? 'error' : paused ? 'paused' : active ? 'connected' : pending ? 'pairing' : 'connecting',
      url: origin, devices, pendingPairingIDs: pending ? [pending.id] : [],
      ...(setupID && !invitationUnavailable ? { setupURL: `${origin}/#setup=${encodeURIComponent(setupID)}&mac=${state.macID}&key=${state.publicKey}` } : {}),
      ...(message || attentionError ? { message: fault || enrollmentError ? message : attentionError ?? message } : {})
    } });
  }
  function fatal(error) {
    if (closed || fault) return;
    fault = error; message = error.message || 'Internet connection failed.';
    auth?.disable();
    for (const channel of channels.values()) channel.controller.abort();
    actions.close();
    status();
    emit({ type: 'error', message: message.slice(0, 500) });
  }
  async function openAuthorization(owner) {
    const expectedOwner = { issuer: owner.issuer, subject: owner.subject, macID: state.macID };
    if (state.owner && (state.owner.issuer !== owner.issuer || state.owner.subject !== owner.subject))
      fail(403, ownerMismatchMessage);
    auth = await RemoteAccess.open({ owner: expectedOwner, store: {
      read: async () => state.owner ? { version: 1, owner: expectedOwner,
        devices: state.devices.map(d => ({ deviceID: d.id, keyHash: hash(d.publicKey) })) } : null,
      write: async policy => save(current => {
        const candidates = [...current.devices, ...(approving ? [{
          id: approving.deviceID, name: approving.name, publicKey: approving.publicKey
        }] : [])];
        const devices = policy.devices.map(d => {
          const found = candidates.find(candidate => candidate.id === d.deviceID && hash(candidate.publicKey) === d.keyHash);
          if (!found) fail(503, 'Cannot save an unknown phone identity.');
          return found;
        });
        return { ...current, owner: { issuer: owner.issuer, subject: owner.subject }, devices };
      })
    } });
    auth.enable();
  }
  function verifiedSigner() {
    if (signerWork) return signerWork;
    if (signer && !signer.failed) return Promise.resolve(signer);
    signerWork = (async () => {
      await signer?.close();
      lifetime.signal.throwIfAborted();
      const candidate = openCrypto();
      signer = candidate;
      try {
        if (bytes(await candidate.call('identity')).toString('base64url') !== state.publicKey) {
          const error = new Error('Saved Mac identity changed. Internet access stopped; saved pairing was not replaced.');
          fatal(error);
          throw error;
        }
        lifetime.signal.throwIfAborted();
        return candidate;
      } catch (error) {
        await candidate.close();
        throw error;
      }
    })().finally(() => { signerWork = undefined; });
    return signerWork;
  }
  async function sign(challenge) {
    if (typeof challenge !== 'string' || !challenge.length || Buffer.byteLength(challenge) > 4096)
      fail(502, 'Invalid internet authorization challenge.');
    const identity = await verifiedSigner();
    return bytes(await identity.call('sign', { bytes: [...Buffer.from(challenge)] })).toString('base64url');
  }
  function validateGrant(grant, channel, id, started, previous) {
    const renewal = grant?.renewal;
    if (!object(grant) || grant.role !== 'mac' || grant.macID !== state.macID || grant.deviceID !== channel.device.id ||
      typeof grant.approved !== 'boolean' || (previous?.approved && !grant.approved) ||
      !object(renewal) || renewal.id !== id || typeof id !== 'string' || !/^[\w-]{43}$/.test(id) ||
      typeof renewal.challenge !== 'string' || !renewal.challenge.length || Buffer.byteLength(renewal.challenge) > 4096 ||
      renewal.challenge === previous?.renewal.challenge ||
      (!grant.approved && channel.enrollmentExpiresAt && grant.expiresAt > channel.enrollmentExpiresAt))
      fail(502, 'Invalid Mac relay grant.');
    return localLease(grant, started);
  }
  function register(signal) {
    registration ??= registerOnce(signal).finally(() => { registration = undefined; });
    return registration;
  }
  async function registerOnce(signal) {
    const begin = await api('mac/begin', { macID: state.macID, publicKey: state.publicKey }, undefined, signal);
    const result = await api('mac/register', { id: begin.id, signature: await sign(begin.challenge) }, undefined, signal);
    if (result.macID !== state.macID || typeof result.credential !== 'string' ||
      !/^[\w-]{43}$/.test(result.credential) || !text(result.setupID, 256)) fail(502, 'Invalid Mac registration.');
    await save(current => ({ ...current, credential: result.credential, setupID: result.setupID }));
    setupID = result.setupID;
  }
  async function ready(channel) {
    if (!channel.possession || channel.handle || channel.signal.aborted || !auth) return;
    const approved = state.devices.find(d => d.id === channel.device.id && d.publicKey === channel.device.publicKey);
    if (!approved || !serverDevices.some(d => d.deviceID === approved.id && d.publicKey === approved.publicKey)) return;
    const remaining = Math.floor(Math.min(channel.expiresAt - Date.now(), channel.deadline - performance.now()));
    if (remaining <= 0) return;
    channel.handle = auth.connect({ ...state.owner, macID: state.macID,
      deviceID: approved.id, keyHash: hash(approved.publicKey) }, remaining);
    channel.handle.signal.addEventListener('abort', () => channel.controller.abort(), { once: true });
    message = undefined;
    status();
    await channel.send({ type: 'ready', epoch: auth.epoch });
  }
  async function startChannel(device, candidateID) {
    if (closed || paused || fault || channels.has(device.id)) return;
    const controller = new AbortController();
    const channel = { device, candidateID, controller, signal: controller.signal, stage: 'package', possession: false, inflight: new Set(),
      enrollmentExpiresAt: candidateID && candidateID === pending?.id ? pending.expiresAt : undefined };
    channels.set(device.id, channel);
    let crypto, relay, grant, renewalTimer, renewalWork, renewalStarted = false;
    const current = () => !closed && !paused && !fault && !channel.signal.aborted && channels.get(device.id) === channel;
    const unexpired = () => Date.now() < channel.expiresAt && performance.now() < channel.deadline;
    function requireLive() {
      if (!current() || !unexpired()) {
        controller.abort();
        fail(403, 'Encrypted channel closed or authorization expired.');
      }
    }
    function scheduleRenewal() {
      if (!current()) return;
      renewalTimer = setTimeout(() => {
        if (!current()) return;
        scheduleRenewal();
        if (renewalWork) return;
        renewalWork = renew().finally(() => { renewalWork = undefined; });
      }, 10000);
      renewalTimer.unref();
    }
    async function renew() {
      if (!current()) return;
      try {
        if (!unexpired()) fail(403, 'Mac relay authorization expired.');
        const { id, challenge } = grant.renewal;
        const signature = await sign(challenge);
        if (!current()) return;
        const started = leaseStart();
        const next = await api('grant/renew', { id, signature }, state.credential, channel.signal);
        if (!current()) return;
        if (!unexpired()) fail(403, 'Mac relay authorization expired.');
        const timing = validateGrant(next, channel, id, started, grant);
        const remaining = timing.remaining;
        if (channel.handle) auth.renew(channel.handle, remaining);
        relay.renew(timing.expiresAt, timing.deadline);
        channel.expiresAt = timing.expiresAt;
        channel.deadline = timing.deadline;
        grant = next;
      } catch {
        // The service may have consumed the nonce even when its reply was lost.
        controller.abort();
      }
    }
    function opened(connection) {
      if (renewalStarted) return;
      renewalStarted = true; relay = connection;
      connection.signal?.addEventListener('abort', () => controller.abort(), { once: true });
      if (connection.signal?.aborted) controller.abort();
      scheduleRenewal();
    }
    channel.signal.addEventListener('abort', () => clearTimeout(renewalTimer), { once: true });
    try {
      const challenge = await api('grant/begin', { role: 'mac', deviceID: device.id }, state.credential, channel.signal);
      if (typeof challenge.id !== 'string' || !/^[\w-]{43}$/.test(challenge.id))
        fail(502, 'Invalid Mac authorization challenge.');
      const signature = await sign(challenge.challenge);
      const started = leaseStart();
      grant = await api('grant/finish', { id: challenge.id, signature }, undefined, channel.signal);
      const timing = validateGrant(grant, channel, challenge.id, started);
      channel.expiresAt = timing.expiresAt;
      channel.deadline = timing.deadline;
      crypto = openCrypto();
      channel.send = async data => {
        requireLive();
        const frame = bytes(await crypto.call('send', { bytes: [...Buffer.from(JSON.stringify(data))] }));
        requireLive();
        await relay.send(frame);
      };
      const relayReady = connectRelay({ url: `${origin.replace('https:', 'wss:')}/v1/relay`,
        credential: grant.credential, expiresAt: channel.expiresAt, deadline: channel.deadline,
        signal: channel.signal, onOpen: opened,
        receive: async data => {
          relay = await relayReady;
          requireLive();
          if (channel.stage === 'package') {
            let value;
            try { value = JSON.parse(data.toString('utf8')); } catch { fail(400, 'Invalid key-package frame.'); }
            if (!object(value) || value.type !== 'key_package' || Object.keys(value).length !== 2)
              fail(400, 'Expected a phone key package.');
            const key = bytes(value.bytes);
            await crypto.call('create', { id: randomUUID() });
            const welcome = await crypto.call('add', { bytes: [...key], publicKey: [...Buffer.from(device.publicKey, 'base64url')] });
            const tree = await crypto.call('tree');
            channel.stage = 'hello';
            await relay.send(Buffer.from(JSON.stringify({ type: 'welcome', welcome, tree })));
            return;
          }
          const decrypted = await crypto.call('receive', { bytes: [...data] });
          requireLive();
          let value;
          try { value = JSON.parse(bytes(decrypted.bytes).toString('utf8')); } catch { fail(400, 'Invalid encrypted request.'); }
          if (!object(value)) fail(400, 'Invalid encrypted request.');
          if (channel.stage === 'hello') {
            if (value.type !== 'hello' || Object.keys(value).length !== 1) fail(400, 'Expected encrypted key confirmation.');
            channel.stage = 'ready'; channel.possession = true;
            if (candidateID && pending?.id === candidateID) {
              status();
              emit({ type: 'pairing', id: pending.id, name: pending.name,
                verificationData: Buffer.from(pending.publicKey, 'base64url').toString('base64') });
              await channel.send({ type: 'pending' });
            }
            await ready(channel);
            return;
          }
          if (!channel.handle || !auth) fail(403, 'Approve this phone locally before accessing sessions.');
          if (!uuid(value.id) || typeof value.epoch !== 'string' || !object(value.payload) ||
            !['state', 'reply', 'workspace', 'control'].includes(value.payload.path) || !object(value.payload.data) ||
            Object.keys(value).some(k => !['id', 'epoch', 'payload'].includes(k)) ||
            Object.keys(value.payload).some(k => !['path', 'data'].includes(k))) fail(400, 'Invalid encrypted action envelope.');
          const payload = Buffer.from(JSON.stringify(value.payload));
          const off = isPolicyOffRPC(value.id, value.payload);
          if (isOffID(value.id) && !off) fail(400, 'Off UUIDs cannot identify other remote work.');
          const rpcID = value.id.toLowerCase();
          if (payload.length > 131072 || channel.inflight.has(rpcID))
            fail(429, 'Remote request is too large, duplicated or already busy.');
          auth.authorize(channel.handle);
          if (value.epoch !== auth.epoch) fail(409, 'Remote request belongs to an expired connection.');
          if (channel.inflight.size >= (off ? 9 : 8)) {
            if (off) return channel.send({ id: value.id, status: 429,
              data: { notDispatched: true, error: 'Remote connection is busy. Off was not dispatched.' } });
            fail(429, 'Remote request is already busy.');
          }
          channel.inflight.add(rpcID);
          const invoke = () => actions.request(value.payload.path, value.payload.data, {
              id: device.id, name: device.name, expires: channel.expiresAt
            }, channel.signal);
          // Read polling cannot exhaust the mutation replay ledger.
          const operation = ['reply', 'control'].includes(value.payload.path)
            ? auth.dispatch(channel.handle, { id: value.id, epoch: value.epoch, payload }, invoke)
            : invoke();
          void operation
            .then(result => { if (!channel.signal.aborted) return channel.send({ id: value.id, ...result }); })
            .catch(async error => {
              if (!channel.signal.aborted) {
                try { await channel.send({ id: value.id, status: error.status ?? 503, data: { error: error.message.slice(0, 500) } }); }
                catch { channel.controller.abort(); }
              }
            }).finally(() => channel.inflight.delete(rpcID));
        }
      });
      relay = await relayReady;
      opened(relay);
      await relay.closed;
    } catch (error) {
      if (!closed && !paused && !fault) message = text(error.message, 500) ? error.message : 'Waiting for phone authorization.';
    } finally {
      controller.abort();
      clearTimeout(renewalTimer);
      if (channel.handle) auth?.disconnect(channel.handle);
      actions.disconnect(device.id);
      await renewalWork;
      await relay?.close();
      await crypto?.close();
      if (channels.get(device.id) === channel) channels.delete(device.id);
      if (channels.size === 0) {
        auth?.disable(); actions.close();
      }
      status();
    }
  }
  function tick() {
    if (closed || paused || fault || enrollmentError || polling) return;
    pollController = new AbortController();
    polling = poll(pollController.signal);
  }
  async function poll(signal) {
    let credential;
    try {
      if (!state.credential) await register(signal);
      credential = state.credential;
      const remote = await api('mac/status', {}, credential, signal);
      signal.throwIfAborted();
      if (credential !== state.credential) return;
      if (remote.macID !== state.macID || !Array.isArray(remote.devices) || remote.devices.length > 8 ||
        !remote.devices.every(d => uuid(d.deviceID) && validKey(d.publicKey) && text(d.name, 100)))
        fail(502, 'Invalid registered-phone state.');
      while (policyWork) await policyWork;
      signal.throwIfAborted();
      if (credential !== state.credential) return;
      serverDevices = remote.devices;
      if (auth) auth.enable();
      if (remote.pending !== null) {
        const p = remote.pending;
        if (!object(p) || !text(p.id, 256) || !uuid(p.deviceID) || !validKey(p.publicKey) ||
          !text(p.name, 100) || !object(p.account) || p.account.issuer !== origin || !text(p.account.subject, 256) ||
          !Number.isSafeInteger(p.expiresAt) || p.expiresAt <= Date.now()) fail(502, 'Invalid pending phone identity.');
        pending = Object.freeze({ ...p });
        if (state.owner && (state.owner.issuer !== p.account.issuer || state.owner.subject !== p.account.subject))
          fail(403, ownerMismatchMessage);
      } else pending = undefined;
      setupID = state.setupID ?? undefined;
      for (const channel of channels.values()) {
        if (channel.candidateID && pending?.id !== channel.candidateID &&
          !serverDevices.some(d => d.deviceID === channel.device.id && d.publicKey === channel.device.publicKey)) channel.controller.abort();
      }
      const candidates = [...state.devices, ...(pending ? [{
        id: pending.deviceID, name: pending.name, publicKey: pending.publicKey
      }] : [])];
      for (const device of candidates) if (!channels.has(device.id)) {
        const task = startChannel(device, pending?.deviceID === device.id ? pending.id : undefined);
        channelWork.add(task);
        void task.catch(fatal).finally(() => channelWork.delete(task));
      }
      status();
    } catch (error) {
      if (closed || signal.aborted || (credential && credential !== state.credential)) return;
      if (error.status === 401 || error.status === 403 || error.status === 409) {
        enrollmentError = error;
        message = error.status === 401
          ? 'This Mac pairing registration expired or is no longer accepted. Choose "Pair an internet device" on this Mac for a fresh invitation. Signing in again on the phone cannot restore the Mac registration.'
          : error.message;
        setupID = undefined; pending = undefined; serverDevices = [];
        auth?.disable();
        for (const channel of channels.values()) channel.controller.abort();
        status();
      } else if (transient(error)) {
        message = 'Internet connection unavailable. Reconnecting safely; no actions will be retried.';
        auth?.disable();
        for (const channel of channels.values()) channel.controller.abort();
        actions.close();
        status();
      } else fatal(error);
    } finally { polling = undefined; }
  }
  function invite() {
    invitationWork ??= inviteOnce().finally(() => { invitationWork = undefined; });
    return invitationWork;
  }
  async function inviteOnce() {
    invitationUnavailable = true;
    status();
    if (pending) fail(409, 'Finish or reject the pending phone first.');
    let existing = false;
    if (state.credential) {
      try { await api('mac/status', {}, state.credential); existing = true; }
      catch (error) { if (error.status !== 401) throw error; }
    }
    if (!existing) await register();
    else {
      const invitation = await api('mac/invite', {}, state.credential);
      if (!/^[\w-]{43}$/.test(invitation.setupID) || !Number.isSafeInteger(invitation.expiresAt) ||
        invitation.expiresAt <= Date.now() || invitation.expiresAt > Date.now() + 180000)
        fail(502, 'Invalid pairing invitation.');
      await save(current => ({ ...current, setupID: invitation.setupID }));
    }
    enrollmentError = undefined;
    invitationUnavailable = false;
    setupID = state.setupID ?? undefined;
    message = "Scan this Mac's code and sign in on your phone."; status();
  }
  async function prepareInvitation() {
    try { await command({ type: 'invite' }); }
    catch (error) {
      if (closed || paused) return;
      message = `Could not prepare a fresh pairing QR. Choose "Pair an internet device" to retry. ${error.message}`.slice(0, 500);
      status();
    }
  }
  async function command(input) {
    if (!object(input) || closed || fault) fail(503, 'Internet helper is unavailable.');
    if (input.type === 'offline') {
      paused = true; pollController?.abort(); auth?.disable();
      for (const channel of channels.values()) channel.controller.abort();
      actions.close(); status(); return;
    }
    if (input.type === 'heartbeat') {
      paused = false;
      status(); void tick(); return;
    }
    if (input.type === 'attention') {
      if (Object.keys(input).length !== 3 || typeof input.waiting !== 'boolean' ||
        typeof input.changed !== 'boolean' || (input.changed && !input.waiting))
        fail(400, 'Invalid generic attention signal.');
      genericAttention = true;
      publishAttention(input.waiting, input.changed);
      return;
    }
    if (input.type === 'invite') {
      return invite();
    }
    if (input.type === 'pair') {
      if (!pending || pending.id !== input.id || pending.expiresAt <= Date.now()) fail(409, 'Phone pairing expired.');
      const candidate = pending;
      const channel = channels.get(candidate.deviceID);
      if (input.allow === true) {
        if (state.owner && (state.owner.issuer !== candidate.account.issuer || state.owner.subject !== candidate.account.subject))
          fail(403, ownerMismatchMessage);
        if (!channel?.possession || channel.signal.aborted ||
          channel.device.publicKey !== candidate.publicKey ||
          input.verificationData !== Buffer.from(candidate.publicKey, 'base64url').toString('base64'))
          fail(403, 'The complete phone public key must match the confirmed encrypted channel.');
        if (!auth) await openAuthorization(candidate.account);
        approving = candidate;
        try { await updatePolicy(auth.approveDevice({ deviceID: candidate.deviceID, keyHash: hash(candidate.publicKey) })); }
        finally { approving = undefined; }
        await api('mac/decision', { id: candidate.id, allow: true }, state.credential);
        serverDevices.push({ deviceID: candidate.deviceID, name: candidate.name, publicKey: candidate.publicKey });
        if (pending?.id === candidate.id) pending = undefined;
        await ready(channel);
      } else {
        await api('mac/decision', { id: candidate.id, allow: false }, state.credential);
        channel?.controller.abort();
        if (pending?.id === candidate.id) pending = undefined;
      }
      status(); return;
    }
    if (input.type === 'revoke') {
      if (!uuid(input.id) || !auth) fail(400, 'Invalid phone revocation.');
      await updatePolicy(auth.revokeDevice(input.id));
      channels.get(input.id)?.controller.abort();
      await api('mac/revoke', { deviceID: input.id }, state.credential);
      status(); return;
    }
    actions.command(input);
    status();
  }
  try {
    await verifiedSigner();
    if (state.owner) await openAuthorization(state.owner);
  } catch (error) { await signer?.close(); throw error; }
  const timer = setInterval(() => { void tick(); }, 3000);
  timer.unref();
  status(); void tick();
  return { command, prepareInvitation, async close() {
    if (closed) return;
    closed = true; clearInterval(timer); lifetime.abort(); auth?.disable(); actions.close();
    for (const channel of channels.values()) channel.controller.abort();
    await signer.close();
    await polling;
    await Promise.allSettled([invitationWork]);
    await attentionWork;
    await Promise.all(channelWork);
    await writer;
  } };
}
