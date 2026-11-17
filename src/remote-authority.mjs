import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const ENROLL_TTL = 180000, GRANT_TTL = 30000;
const PREFIX = Buffer.from('Notify remote authorization v1\0');
const COOKIE = '__Host-notify-relay';
const secret = () => randomBytes(32).toString('base64url');
const uuid = value => typeof value === 'string' &&
  /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/.test(value);
const identity = value => typeof value === 'string' && value.length > 0 &&
  value.length <= 256 && !/[\0-\x1f\x7f]/.test(value);

export class RemoteAuthorityError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'RemoteAuthorityError';
    this.status = status;
  }
}
const fail = (status, message) => { throw new RemoteAuthorityError(status, message); };
function shape(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    !required.every(key => Object.hasOwn(value, key)) ||
    Object.keys(value).some(key => !required.includes(key) && !optional.includes(key)))
    fail(400, 'Invalid authorization request.');
}
function decode(value, min, max = min) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)) fail(400, 'Invalid authorization encoding.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value)
    fail(400, 'Invalid authorization encoding.');
  return bytes;
}
function key(value) {
  const bytes = decode(value, 65);
  if (bytes[0] !== 4) fail(400, 'Invalid device public key.');
  try {
    return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
      x: bytes.subarray(1, 33).toString('base64url'), y: bytes.subarray(33).toString('base64url') } });
  } catch { fail(400, 'Invalid device public key.'); }
}
function signed(record, signature) {
  const bytes = decode(signature, 8, 72);
  try {
    if (verify('sha256', Buffer.concat([PREFIX, Buffer.from(record.challenge)]), record.key, bytes)) return;
  } catch { /* Invalid DER is an authentication failure. */ }
  fail(401, 'Device signature rejected.');
}
const sameAccount = (a, b) => a?.issuer === b?.issuer && a?.subject === b?.subject;
const accountCopy = account => account && ({ issuer: account.issuer, subject: account.subject });

// Memory-only enrollment and routing, never device trust. A local Mac allowlist
// and end-to-end key verification remain mandatory, including for pending grants.
// Sign PREFIX + UTF8(challenge) with P-256/SHA-256; keys are x963 and signatures
// ASN.1 DER, both canonical base64url. expiresAt is Unix milliseconds. Never put
// credentials in URLs or logs. Account-bound operations may be asynchronous.
// finishGrant(input, req) requires the real account request for phone challenges;
// accounts.authorize must be synchronous, and both begin/finish sessions stay live.
export function createRemoteAuthority({ origin, accounts, now = () => performance.now(), wallNow = Date.now }) {
  let endpoint;
  try { endpoint = new URL(origin); } catch { fail(400, 'Invalid authorization origin.'); }
  if (endpoint.protocol !== 'https:' || endpoint.origin !== origin ||
    typeof accounts?.authorize !== 'function' || typeof now !== 'function' || typeof wallNow !== 'function')
    fail(400, 'Invalid authorization configuration.');

  const bootstraps = new Map(), macs = new Map(), challenges = new Map(), grants = new Map();
  const subscriptions = new Map();
  let closed = false, fault = false, mono = -Infinity, wall = -Infinity, timer, active = 0;

  function unwatch(record) {
    for (const remove of record.unwatch ?? []) remove();
    record.unwatch = [];
  }
  function watch(record, signal, revoked) {
    if (signal.aborted) { revoked(); return; }
    let entry = subscriptions.get(signal);
    if (!entry) {
      entry = { callbacks: new Set() };
      entry.abort = () => {
        for (const callback of [...entry.callbacks]) callback();
      };
      subscriptions.set(signal, entry);
      signal.addEventListener('abort', entry.abort, { once: true });
    }
    entry.callbacks.add(revoked);
    (record.unwatch ??= []).push(() => {
      entry.callbacks.delete(revoked);
      if (!entry.callbacks.size) {
        signal.removeEventListener('abort', entry.abort);
        subscriptions.delete(signal);
      }
    });
  }
  function dropChallenge(record) {
    challenges.delete(record.id);
    unwatch(record);
  }
  function dropGrant(record) {
    grants.delete(record.credential);
    unwatch(record);
    record.controller.abort();
  }
  function dropDevice(mac, device) {
    if (mac.pending === device) mac.pending = null;
    if (mac.devices.get(device.deviceID) === device) mac.devices.delete(device.deviceID);
    unwatch(device);
    for (const record of challenges.values()) if (record.device === device) dropChallenge(record);
    for (const record of grants.values()) if (record.device === device) dropGrant(record);
  }
  function clear() {
    clearTimeout(timer);
    timer = undefined;
    for (const record of challenges.values()) dropChallenge(record);
    for (const record of grants.values()) dropGrant(record);
    for (const mac of macs.values()) if (mac.pending) unwatch(mac.pending);
    bootstraps.clear();
    macs.clear();
  }
  function close() { closed = true; clear(); }
  function time() {
    if (closed || fault) fail(503, 'Remote authorization unavailable.');
    let nextMono, nextWall;
    try { nextMono = now(); nextWall = wallNow(); } catch { nextMono = NaN; }
    if (!Number.isFinite(nextMono) || nextMono < 0 || nextMono < mono ||
      nextMono > Number.MAX_SAFE_INTEGER - ENROLL_TTL ||
      !Number.isSafeInteger(nextWall) || nextWall < 0 || nextWall < wall ||
      nextWall > Number.MAX_SAFE_INTEGER - ENROLL_TTL) {
      fault = true;
      clear();
      fail(503, 'Remote authorization clock is invalid.');
    }
    mono = nextMono;
    wall = nextWall;
  }
  function current(mac, device) {
    return macs.get(mac.macID) === mac &&
      (mac.devices.get(device.deviceID) === device ||
        (mac.pending === device && mono < device.deadline && !device.proof.signal.aborted));
  }
  function valid(record) {
    return mono < record.deadline && !record.proof.signal.aborted &&
      !record.finishProof?.signal.aborted &&
      current(record.mac, record.device) &&
      sameAccount(record.proof, record.mac.account ?? record.device.account);
  }
  function prune() {
    for (const [id, record] of bootstraps) if (mono >= record.deadline) bootstraps.delete(id);
    for (const mac of macs.values()) {
      if (mac.pending && (mono >= mac.pending.deadline || mac.pending.proof.signal.aborted))
        dropDevice(mac, mac.pending);
      if (!mac.account && mono >= mac.deadline) macs.delete(mac.macID);
    }
    for (const record of challenges.values()) if (!valid(record)) dropChallenge(record);
    for (const record of grants.values()) if (!valid(record)) dropGrant(record);
  }
  function schedule() {
    // Abort callbacks only remove deadlines; they must not re-arm from stale mono.
    clearTimeout(timer);
    timer = undefined;
    if (closed || fault) return;
    let deadline = Infinity;
    for (const record of bootstraps.values()) deadline = Math.min(deadline, record.deadline);
    for (const mac of macs.values()) {
      if (!mac.account) deadline = Math.min(deadline, mac.deadline);
      if (mac.pending) deadline = Math.min(deadline, mac.pending.deadline);
    }
    for (const record of challenges.values()) deadline = Math.min(deadline, record.deadline);
    for (const record of grants.values()) deadline = Math.min(deadline, record.deadline);
    if (deadline === Infinity) return;
    timer = setTimeout(() => {
      try { check(); } catch { /* A clock fault has already revoked all authority. */ }
    }, Math.max(1, deadline - mono));
    timer.unref();
  }
  function check() { time(); prune(); schedule(); }
  function host(credential) {
    decode(credential, 32);
    const mac = [...macs.values()].find(record => record.credential === credential);
    if (!mac) fail(401, 'Mac authorization required.');
    return mac;
  }
  function target(mac, deviceID) {
    if (!uuid(deviceID)) fail(400, 'Invalid device identifier.');
    const device = mac.devices.get(deviceID) ??
      (mac.pending?.deviceID === deviceID ? mac.pending : null);
    if (!device || !current(mac, device)) fail(401, 'Device enrollment required.');
    return device;
  }
  function challenge(purpose, fields) {
    return JSON.stringify({ purpose, origin, ...fields, challenge: secret() });
  }
  function flow(purpose, fields, publicKey, ttl) {
    return { id: secret(), challenge: challenge(purpose, fields),
      key: publicKey, deadline: mono + ttl, expiresAt: Math.floor(wall + ttl) };
  }
  function publicFlow(record) {
    return { id: record.id, challenge: record.challenge, expiresAt: record.expiresAt };
  }
  function checkedProof(result) {
    if (!identity(result?.issuer) || !identity(result?.subject) ||
      !(result?.signal instanceof AbortSignal) || result.signal.aborted)
      fail(401, 'Account authorization required.');
    return Object.freeze({ issuer: result.issuer, subject: result.subject, signal: result.signal });
  }
  async function proof(req, requireFresh) {
    const result = await accounts.authorize(req, { requireFresh });
    check();
    return checkedProof(result);
  }
  async function accountOperation(operation) {
    check();
    if (active >= 128) fail(429, 'Remote authorization capacity reached.');
    active++;
    try { return await operation(); } finally { active--; }
  }

  function beginMac(input) {
    check();
    shape(input, ['macID', 'publicKey']);
    const { macID, publicKey } = input;
    if (!uuid(macID)) fail(400, 'Invalid Mac identifier.');
    const publicKeyObject = key(publicKey);
    if (macs.has(macID) || [...bootstraps.values()].some(record => record.macID === macID))
      fail(409, 'Mac enrollment already exists.');
    if (bootstraps.size >= 128 || macs.size >= 64) fail(429, 'Mac enrollment capacity reached.');
    const record = { ...flow('bootstrap', { macID }, publicKeyObject, ENROLL_TTL), macID, publicKey };
    bootstraps.set(record.id, record);
    schedule();
    return publicFlow(record);
  }
  function registerMac(input) {
    check();
    shape(input, ['id', 'signature']);
    decode(input.id, 32);
    const record = bootstraps.get(input.id);
    if (!record) fail(401, 'Mac challenge unavailable.');
    bootstraps.delete(input.id);
    signed(record, input.signature);
    if (macs.size >= 64) fail(429, 'Mac enrollment capacity reached.');
    const mac = { macID: record.macID, publicKey: record.publicKey, key: record.key,
      credential: secret(), setupID: secret(), deadline: mono + ENROLL_TTL,
      expiresAt: wall + ENROLL_TTL, account: null, pending: null, devices: new Map() };
    macs.set(mac.macID, mac);
    schedule();
    return { macID: mac.macID, credential: mac.credential, setupID: mac.setupID, expiresAt: mac.expiresAt };
  }
  async function requestPair(req, input) {
    return accountOperation(async () => {
      shape(input, ['setupID', 'deviceID', 'publicKey', 'name']);
      const { setupID, deviceID, publicKey, name } = input;
      decode(setupID, 32);
      if (!uuid(deviceID) || typeof name !== 'string' || !name.trim() ||
        name.length > 128 || /[\0-\x1f\x7f]/.test(name)) fail(400, 'Invalid device enrollment.');
      const publicKeyObject = key(publicKey), accountProof = await proof(req, true);
      const mac = [...macs.values()].find(record => record.setupID === setupID);
      if (!mac) fail(401, 'Mac enrollment unavailable.');
      if (mac.account && !sameAccount(mac.account, accountProof)) fail(403, 'Account does not own this Mac.');
      if (mac.pending || mac.devices.has(deviceID)) fail(409, 'Device enrollment already exists.');
      if (mac.devices.size >= 8 || [...macs.values()].filter(record => record.pending).length >= 128)
        fail(429, 'Device enrollment capacity reached.');
      const ttl = Math.min(ENROLL_TTL, mac.account ? ENROLL_TTL : mac.deadline - mono);
      const device = { id: secret(), deviceID, publicKey, key: publicKeyObject, name: name.trim(),
        account: accountCopy(accountProof), proof: accountProof, approved: false,
        deadline: mono + ttl, expiresAt: Math.floor(wall + ttl) };
      mac.pending = device;
      watch(device, accountProof.signal, () => dropDevice(mac, device));
      schedule();
      return { id: device.id, macID: mac.macID, macPublicKey: mac.publicKey,
        account: accountCopy(device.account), expiresAt: device.expiresAt };
    });
  }
  function macStatus(credential) {
    check();
    const mac = host(credential), pending = mac.pending;
    return { macID: mac.macID, account: accountCopy(mac.account),
      pending: pending ? { id: pending.id, name: pending.name, deviceID: pending.deviceID,
        publicKey: pending.publicKey, account: accountCopy(pending.account), expiresAt: pending.expiresAt } : null,
      devices: [...mac.devices.values()].map(({ deviceID, publicKey, name }) => ({ deviceID, publicKey, name })) };
  }
  function decidePair(credential, input) {
    check();
    shape(input, ['id', 'allow']);
    decode(input.id, 32);
    if (typeof input.allow !== 'boolean') fail(400, 'Invalid enrollment decision.');
    const mac = host(credential), device = mac.pending;
    if (!device || device.id !== input.id) fail(401, 'Device enrollment unavailable.');
    if (input.allow) {
      unwatch(device);
      device.approved = true;
      mac.account ??= accountCopy(device.account);
      mac.devices.set(device.deviceID, device);
      mac.pending = null;
    } else dropDevice(mac, device);
    schedule();
    return { id: device.id, deviceID: device.deviceID, approved: input.allow };
  }
  async function beginGrant(req, input) {
    return accountOperation(async () => {
      shape(input, ['role', 'deviceID'], ['macID', 'credential']);
      const { role, deviceID, macID, credential } = input;
      if (!['mac', 'phone'].includes(role)) fail(400, 'Invalid routing role.');
      let mac, accountProof;
      if (role === 'mac') {
        if (!credential) fail(401, 'Mac authorization required.');
        mac = host(credential);
        if (macID !== undefined && macID !== mac.macID) fail(403, 'Mac identity mismatch.');
      } else {
        if (credential !== undefined) fail(400, 'Invalid phone authorization.');
        if (!uuid(macID)) fail(400, 'Invalid Mac identifier.');
        accountProof = await proof(req, false);
        mac = macs.get(macID);
        if (!mac) fail(401, 'Mac enrollment unavailable.');
      }
      const device = target(mac, deviceID);
      accountProof ??= device.proof;
      if (accountProof.signal.aborted) fail(401, 'Account authorization required.');
      if (!sameAccount(accountProof, mac.account ?? device.account)) fail(403, 'Account does not own this device.');
      if (challenges.size >= 128 || grants.size >= 256) fail(429, 'Routing grant capacity reached.');
      if (role === 'phone' && device.approved) device.proof = accountProof;
      const ttl = Math.min(GRANT_TTL, device.approved ? GRANT_TTL : device.deadline - mono);
      const record = { ...flow('grant', { role, macID: mac.macID, deviceID },
        role === 'mac' ? mac.key : device.key, ttl), role, mac, device, proof: accountProof };
      challenges.set(record.id, record);
      watch(record, accountProof.signal, () => dropChallenge(record));
      schedule();
      return publicFlow(record);
    });
  }
  function finishGrant(input, req) {
    check();
    shape(input, ['id', 'signature']);
    decode(input.id, 32);
    const record = challenges.get(input.id);
    if (!record) fail(401, 'Routing challenge unavailable.');
    let finishProof;
    if (record.role === 'phone') {
      if (req?.headers?.origin !== origin) fail(403, 'Authorization origin rejected.');
      finishProof = checkedProof(accounts.authorize(req, { requireFresh: false }));
      check();
      if (!sameAccount(finishProof, record.proof)) fail(403, 'Account does not own this challenge.');
    }
    dropChallenge(record);
    signed(record, input.signature);
    if (!valid(record)) fail(401, 'Routing authorization expired.');
    if (grants.size >= 256) fail(429, 'Routing grant capacity reached.');
    const ttl = Math.min(GRANT_TTL, record.device.approved ? GRANT_TTL : record.device.deadline - mono);
    const grant = { ...record, finishProof, unwatch: [], credential: secret(), deadline: mono + ttl,
      expiresAt: Math.floor(wall + ttl), controller: new AbortController(), connected: false };
    grant.renewalChallenge = nextRenewal(grant);
    grants.set(grant.credential, grant);
    watchGrant(grant);
    schedule();
    return { credential: grant.credential, ...publicLease(grant) };
  }
  function nextRenewal(grant) {
    return challenge('renew', { role: grant.role, macID: grant.mac.macID,
      deviceID: grant.device.deviceID, connectionID: grant.id });
  }
  function publicLease(grant) {
    return { expiresAt: grant.expiresAt, role: grant.role,
      macID: grant.mac.macID, deviceID: grant.device.deviceID, approved: grant.device.approved,
      renewal: { id: grant.id, challenge: grant.renewalChallenge } };
  }
  function watchGrant(grant) {
    watch(grant, grant.proof.signal, () => dropGrant(grant));
    if (grant.finishProof && grant.finishProof.signal !== grant.proof.signal)
      watch(grant, grant.finishProof.signal, () => dropGrant(grant));
    if (grant.relaySignal) watch(grant, grant.relaySignal, () => dropGrant(grant));
  }
  async function renewGrant(req, input, credential) {
    return accountOperation(async () => {
      shape(input, ['id', 'signature']);
      decode(input.id, 32);
      const grant = [...grants.values()].find(value => value.id === input.id);
      if (!grant?.connected || !valid(grant)) fail(401, 'Connected routing authorization required.');
      let accountProof;
      if (grant.role === 'phone') {
        if (req?.headers?.origin !== origin || credential !== undefined)
          fail(403, 'Authorization origin rejected.');
        accountProof = await proof(req, false);
      } else {
        if (req?.headers?.origin !== undefined || host(credential) !== grant.mac)
          fail(403, 'Mac authorization rejected.');
        accountProof = checkedProof(grant.device.proof);
      }
      if (grants.get(grant.credential) !== grant || !valid(grant))
        fail(401, 'Routing authorization expired.');
      if (!sameAccount(accountProof, grant.proof))
        fail(403, 'Account does not own this connection.');
      signed({ key: grant.key, challenge: grant.renewalChallenge }, input.signature);
      check();
      if (grants.get(grant.credential) !== grant || !valid(grant))
        fail(401, 'Routing authorization expired.');
      const ttl = Math.min(GRANT_TTL, grant.device.approved ? GRANT_TTL : grant.device.deadline - mono);
      unwatch(grant);
      if (grant.role === 'phone') grant.device.proof = accountProof;
      grant.proof = accountProof;
      grant.finishProof = undefined;
      grant.deadline = mono + ttl;
      grant.expiresAt = Math.floor(wall + ttl);
      grant.renewalChallenge = nextRenewal(grant);
      watchGrant(grant);
      schedule();
      return publicLease(grant);
    });
  }
  function authorizeRelay(req, { signal } = {}) {
    check();
    const headers = req?.headers;
    if (!headers || (signal !== undefined && !(signal instanceof AbortSignal)))
      fail(400, 'Invalid relay request.');
    for (const name of ['origin', 'authorization', 'cookie']) {
      if (headers[name] !== undefined && typeof headers[name] !== 'string')
        fail(400, 'Invalid relay credentials.');
      const raw = req.rawHeaders ?? [];
      if (!Array.isArray(raw) || raw.filter((value, i) => i % 2 === 0 &&
        typeof value === 'string' && value.toLowerCase() === name).length > 1)
        fail(400, 'Duplicate relay credentials.');
    }
    let credential, role;
    if (headers.origin === undefined) {
      role = 'mac';
      if (headers.cookie !== undefined) fail(400, 'Invalid Mac relay credentials.');
      const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(headers.authorization ?? '');
      if (!match) fail(headers.authorization === undefined ? 401 : 400, 'Mac relay credential required.');
      credential = match[1];
    } else {
      role = 'phone';
      if (headers.origin !== origin) fail(403, 'Relay origin rejected.');
      if (headers.authorization !== undefined) fail(400, 'Invalid phone relay credentials.');
      const cookie = headers.cookie ?? '';
      if (cookie.length > 4096) fail(400, 'Invalid relay cookies.');
      for (const part of cookie.split(';')) {
        const index = part.indexOf('=');
        const name = (index < 0 ? part : part.slice(0, index)).trim();
        if (name !== COOKIE) continue;
        if (credential !== undefined || index < 0) fail(400, 'Invalid relay cookies.');
        credential = part.slice(index + 1).trim();
      }
      if (credential === undefined) fail(401, 'Phone relay credential required.');
    }
    decode(credential, 32);
    const grant = grants.get(credential);
    if (!grant || !valid(grant)) fail(401, 'Relay authorization unavailable.');
    if (grant.role !== role) fail(403, 'Relay role rejected.');
    if (signal?.aborted) fail(401, 'Relay connection unavailable.');
    // One connection per lease bounds cancellation listeners and prevents reuse.
    if (grant.connected) fail(409, 'Relay credential already in use.');
    grant.connected = true;
    grant.relaySignal = signal;
    if (signal) watch(grant, signal, () => dropGrant(grant));
    return Object.freeze({ issuer: grant.proof.issuer, subject: grant.proof.subject,
      macID: grant.mac.macID, deviceID: grant.device.deviceID, role: grant.role,
      get expiresAt() { return grant.expiresAt; }, signal: grant.controller.signal });
  }
  function revokeDevice(credential, input) {
    check();
    shape(input, ['deviceID']);
    const mac = host(credential), device = target(mac, input.deviceID);
    dropDevice(mac, device);
    schedule();
    return { deviceID: device.deviceID, revoked: true };
  }
  time();
  return Object.freeze({ beginMac, registerMac, requestPair, macStatus, decidePair,
    beginGrant, finishGrant, renewGrant, authorizeRelay, revokeDevice, close });
}
