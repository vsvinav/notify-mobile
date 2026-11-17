import { isIP } from 'node:net';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { decodeAttestationObject, decodeClientDataJSON, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { object } from './validation.mjs';
import { createIngressPolicy } from './managed-ingress.mjs';

const FLOW = '__Host-notify-account-flow', SESSION = '__Host-notify-account';
const FLOW_TTL = 180000, SESSION_TTL = 3600000, ALGORITHMS = [-7, -257, -8];
const hash = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const shape = (value, fields) => object(value) && Object.keys(value).length === fields.length &&
  fields.every(field => Object.hasOwn(value, field));
const encoded = (value, limit) => typeof value === 'string' && value.length > 0 &&
  value.length <= Math.ceil(limit * 4 / 3) && /^[\w-]+$/.test(value) &&
  Buffer.from(value, 'base64url').length <= limit && Buffer.from(value, 'base64url').toString('base64url') === value;
export class AccountServiceError extends Error {
  constructor(status, message) { super(message); this.name = 'AccountServiceError'; this.status = status; }
}
const fail = (status, message) => { throw new AccountServiceError(status, message); };

function cookies(req) {
  const header = req.headers.cookie ?? '';
  if (header.length > 4096) fail(400, 'Invalid account cookies.');
  const result = {};
  for (const entry of header.split(';')) {
    const index = entry.indexOf('='), name = entry.slice(0, index).trim();
    if (![FLOW, SESSION].includes(name)) continue;
    const value = entry.slice(index + 1).trim();
    if (Object.hasOwn(result, name) || !/^[\w-]{43}$/.test(value)) fail(400, 'Invalid account cookies.');
    result[name] = value;
  }
  return result;
}

function cookie(res, name, value, age) {
  res.appendHeader('Set-Cookie', `${name}=${value}; Path=/; Max-Age=${age}; Secure; HttpOnly; SameSite=Strict`);
}

async function body(req) {
  if (req.headers['content-type'] !== 'application/json') fail(415, 'Use application/json.');
  if (Number(req.headers['content-length'] ?? 0) > 32768) fail(413, 'Account request is too large.');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 32768) fail(413, 'Account request is too large.');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!object(value)) throw new Error();
    return value;
  } catch {
    fail(400, 'Invalid account JSON.');
  }
}

function validAccount(account) {
  if (!shape(account, ['id', 'userID', 'credential']) ||
    typeof account.id !== 'string' || !/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/.test(account.id) ||
    !encoded(account.userID, 32)) return false;
  const c = account.credential;
  if (!shape(c, ['id', 'publicKey', 'counter', 'deviceType', 'backedUp']) ||
    !encoded(c.id, 1024) || !encoded(c.publicKey, 2048) ||
    !Number.isSafeInteger(c.counter) || c.counter < 0 || c.counter > 0xffffffff ||
    !['singleDevice', 'multiDevice'].includes(c.deviceType) || typeof c.backedUp !== 'boolean' ||
    (c.deviceType === 'singleDevice' && c.backedUp)) return false;
  try {
    const key = decodeCredentialPublicKey(Buffer.from(c.publicKey, 'base64url'));
    return key instanceof Map && ALGORITHMS.includes(key.get(3));
  } catch {
    return false;
  }
}

// Account identity only, never device trust or relay authority. One private store
// has one authoritative service writer; restart invalidates every cookie session.
export async function createAccountService({ server, origin, store, reportError, now = () => performance.now(), managedIngress }) {
  const ingress = createIngressPolicy({ server, publicOrigin: origin, managedIngress });
  if (server.listening || server.listenerCount('request') ||
    server.listenerCount('upgrade')) throw new Error('Accounts require a dedicated unstarted HTTPS server.');
  const endpoint = new URL(origin);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.pathname !== '/' ||
    endpoint.search || endpoint.hash || isIP(endpoint.hostname)) throw new Error('Invalid account HTTPS origin.');
  origin = endpoint.origin;
  if (typeof store?.read !== 'function' || typeof store?.write !== 'function' ||
    typeof reportError !== 'function' || typeof now !== 'function') throw new Error('Invalid account service dependencies.');
  let state;
  try { state = await store.read(); }
  catch {
    reportError(new Error('Account storage could not be read.'));
    throw new Error('Account storage unavailable.');
  }
  if (state !== null && (!shape(state, ['version', 'origin', 'accounts']) || state.version !== 1 ||
    state.origin !== origin || !Array.isArray(state.accounts) || state.accounts.length > 256 ||
    !state.accounts.every(validAccount) || ['id', 'userID'].some(field =>
      new Set(state.accounts.map(account => account[field])).size !== state.accounts.length) ||
    new Set(state.accounts.map(account => account.credential.id)).size !== state.accounts.length))
    throw new Error('Invalid account storage. Inspect it before starting the service.');
  state = structuredClone(state ?? { version: 1, origin, accounts: [] });
  const flows = new Map(), sessions = new Map(), rates = new Map();
  let closed = false, fault = false, clock = -Infinity, active = 0, serial = Promise.resolve();
  function revokeSession(key) {
    const session = sessions.get(key);
    if (!session) return;
    sessions.delete(key);
    clearTimeout(session.timer);
    session.controller.abort();
  }
  function clearSessions() {
    for (const key of sessions.keys()) revokeSession(key);
  }
  const close = () => { closed = true; flows.clear(); clearSessions(); rates.clear(); };
  function time() {
    const value = now();
    if (!Number.isFinite(value) || value < 0 || value < clock) {
      fault = true; flows.clear(); clearSessions();
      fail(503, 'Account authorization clock is invalid.');
    }
    clock = value;
    return value;
  }
  time();
  server.maxConnections = 64; server.maxHeadersCount = 32;
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.keepAliveTimeout = 1000;
  server.once('close', close);

  function prune() {
    const current = time();
    for (const entries of [flows, rates])
      for (const [key, value] of entries) if (value.expires <= current) entries.delete(key);
    for (const [key, session] of sessions) if (session.expires <= current) revokeSession(key);
    return current;
  }

  async function save(next) {
    if (Buffer.byteLength(JSON.stringify(next)) > 2_097_152) fail(429, 'Account storage limit reached.');
    try { await store.write(structuredClone(next)); }
    catch {
      fault = true; flows.clear(); clearSessions();
      reportError(new Error('Account storage write failed.'));
      fail(503, 'Account storage unavailable.');
    }
    state = next;
  }

  function accountReply(session) {
    return { account: { issuer: origin, subject: session.accountID }, scope: 'account',
      fresh: time() - session.authenticatedAt <= 300000 };
  }

  // Account identity only. Callers must separately authorize devices and actions;
  // retain this session signal to fence authority issued from the returned proof.
  function authorize(req, { requireFresh = false } = {}) {
    if (closed || fault) fail(401, 'Account sign-in required.');
    if (!req?.headers || !req.socket || !Array.isArray(req.rawHeaders) ||
      !ingress.accepts(req) || req.headers.origin !== origin)
      fail(403, 'Account origin rejected.');
    let current, tokens;
    try { current = prune(); }
    catch {
      fault = true; flows.clear(); clearSessions();
      fail(401, 'Account sign-in required.');
    }
    try { tokens = cookies(req); }
    catch { fail(401, 'Account sign-in required.'); }
    const session = sessions.get(tokens[SESSION] && hash(tokens[SESSION]));
    if (closed || fault || !session) fail(401, 'Account sign-in required.');
    if (requireFresh && current - session.authenticatedAt > 300000)
      fail(403, 'Fresh account verification required.');
    return Object.freeze({ issuer: origin, subject: session.accountID, signal: session.controller.signal });
  }

  server.on('request', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    let reserved = false, usedFlow;
    const ensureLive = expires => {
      if (closed || fault || res.destroyed) fail(503, 'Account service unavailable.');
      if (expires !== undefined && time() >= expires) fail(401, 'Passkey ceremony expired. Start again.');
    };
    const respond = (status, value) => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(status); res.end(JSON.stringify(value));
    };
    try {
      ensureLive(); prune();
      if (ingress.health(req, res)) return;
      if (!ingress.accepts(req) || req.headers.origin !== origin)
        fail(403, 'Account origin rejected.');
      if (req.method !== 'POST') fail(405, 'Use POST for account requests.');
      if (!['register/options', 'register/verify', 'login/options', 'login/verify', 'session', 'logout']
        .some(path => req.url === `/v1/account/${path}`)) fail(404, 'Account endpoint not found.');
      if (active >= 16) fail(503, 'Account service is busy.');
      const address = req.socket.remoteAddress;
      if (!address) fail(403, 'Account peer unavailable.');
      let rate = rates.get(address);
      if (!rate) {
        if (rates.size >= 128) fail(503, 'Account service is busy.');
        rates.set(address, rate = { count: 0, expires: time() + 60000 });
      }
      if (++rate.count > 60) fail(429, 'Too many account requests. Try again later.');
      active++; reserved = true;
      res.setTimeout(5000, () => res.destroy());
      const tokens = cookies(req), data = await body(req);
      const kind = req.url.slice('/v1/account/'.length);
      if (kind === 'logout') {
        ensureLive(); prune();
        if (!shape(data, [])) fail(400, 'Unexpected account request fields.');
        const key = tokens[SESSION] && hash(tokens[SESSION]);
        if (!sessions.has(key)) fail(401, 'Account sign-in required.');
        revokeSession(key);
        const browserFlow = tokens[FLOW] && hash(tokens[FLOW]);
        for (const [id, flow] of flows)
          if (id === browserFlow || flow.sessionKey === key) flows.delete(id);
        cookie(res, SESSION, '', 0); cookie(res, FLOW, '', 0);
        respond(200, { signedOut: true });
        return;
      }
      const operation = serial.then(async () => {
        ensureLive(); prune();
        if (kind === 'session') {
          if (!shape(data, [])) fail(400, 'Unexpected account request fields.');
          const key = tokens[SESSION] && hash(tokens[SESSION]), session = sessions.get(key);
          if (!session) fail(401, 'Account sign-in required.');
          return accountReply(session);
        }
        const registration = kind.startsWith('register/');
        if (kind.endsWith('/options')) {
          if (registration ? !shape(data, ['name']) || typeof data.name !== 'string' ||
            !data.name.trim() || data.name.length > 64 : !shape(data, []))
            fail(400, 'Invalid passkey options request.');
          if (tokens[FLOW]) flows.delete(hash(tokens[FLOW]));
          if (flows.size >= 128 || (registration && state.accounts.length >= 256))
            fail(429, 'Account or ceremony limit reached.');
          const accountID = registration ? randomUUID() : undefined;
          const created = time(), userID = registration ? randomBytes(32) : undefined;
          const options = registration ? await generateRegistrationOptions({
            rpName: 'Notify', rpID: endpoint.hostname, userID, userName: data.name, userDisplayName: data.name,
            timeout: FLOW_TTL, attestationType: 'none', supportedAlgorithmIDs: ALGORITHMS,
            authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
          }) : await generateAuthenticationOptions({
            rpID: endpoint.hostname, timeout: FLOW_TTL, userVerification: 'required', allowCredentials: []
          });
          ensureLive(created + FLOW_TTL);
          const token = secret();
          const parentSession = tokens[SESSION] && hash(tokens[SESSION]);
          flows.set(hash(token), { registration, accountID, userID: userID?.toString('base64url'),
            created, expires: created + FLOW_TTL, challenge: options.challenge,
            sessionKey: sessions.has(parentSession) ? parentSession : undefined });
          cookie(res, FLOW, token, FLOW_TTL / 1000);
          return options;
        }
        const flowKey = tokens[FLOW] && hash(tokens[FLOW]), flow = flows.get(flowKey);
        cookie(res, FLOW, '', 0);
        if (!flow || flow.used) fail(401, 'Passkey ceremony unavailable. Start again.');
        flow.used = true; usedFlow = { key: flowKey, flow };
        if (flow.registration !== registration) fail(401, 'Passkey ceremony unavailable. Start again.');
        const ensureFlow = () => {
          ensureLive(flow.expires);
          if (flows.get(flowKey) !== flow || (flow.sessionKey && !sessions.has(flow.sessionKey)))
            fail(401, 'Passkey ceremony cancelled. Start again.');
        };
        ensureFlow();
        if (!shape(data, ['response']) || !object(data.response)) fail(400, 'Invalid passkey response.');
        if (sessions.size >= 256) fail(429, 'Account session limit reached.');
        if (registration && state.accounts.length >= 256) fail(429, 'Account limit reached.');
        let account, info;
        try {
          const response = data.response;
          const clientData = decodeClientDataJSON(response.response.clientDataJSON);
          if ((clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) ||
            clientData.topOrigin !== undefined) throw new Error();
          const common = { response, expectedChallenge: flow.challenge, expectedOrigin: origin,
            expectedRPID: endpoint.hostname, requireUserVerification: true };
          if (registration) {
            const attestation = decodeAttestationObject(Buffer.from(response.response.attestationObject, 'base64url'));
            if (!(attestation instanceof Map) || attestation.get('fmt') !== 'none') throw new Error();
            const verification = await verifyRegistrationResponse({
              ...common, requireUserPresence: true, supportedAlgorithmIDs: ALGORITHMS
            });
            if (!verification.verified || !verification.registrationInfo.userVerified) throw new Error();
            info = verification.registrationInfo;
            if (state.accounts.some(value => value.credential.id === info.credential.id)) throw new Error();
            account = { id: flow.accountID, userID: flow.userID, credential: {
              id: info.credential.id, publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
              counter: info.credential.counter, deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp
            } };
          } else {
            account = state.accounts.find(value => value.credential.id === response.id);
            if (!account || response.response.userHandle !== account.userID) throw new Error();
            const verification = await verifyAuthenticationResponse({ ...common, credential: {
              id: account.credential.id, counter: account.credential.counter,
              publicKey: new Uint8Array(Buffer.from(account.credential.publicKey, 'base64url'))
            } });
            info = verification.authenticationInfo;
            if (!verification.verified || !info.userVerified || info.credentialDeviceType !== account.credential.deviceType)
              throw new Error();
            account = { ...account, credential: { ...account.credential,
              counter: info.newCounter, backedUp: info.credentialBackedUp } };
          }
          if (!validAccount(account)) throw new Error();
        } catch {
          fail(401, 'Passkey verification failed.');
        }
        ensureFlow();
        const accounts = registration ? [...state.accounts, account]
          : state.accounts.map(value => value.id === account.id ? account : value);
        await save({ ...state, accounts });
        ensureFlow();
        if (tokens[SESSION]) revokeSession(hash(tokens[SESSION]));
        ensureLive(flow.expires);
        const token = secret(), session = { accountID: account.id, authenticatedAt: flow.created,
          expires: time() + SESSION_TTL, controller: new AbortController() };
        const key = hash(token);
        session.timer = setTimeout(() => revokeSession(key), SESSION_TTL);
        session.timer.unref();
        sessions.set(key, session);
        cookie(res, SESSION, token, SESSION_TTL / 1000);
        return accountReply(session);
      });
      // Keep one authority for counters and durable account writes after failures.
      serial = operation.then(() => undefined, () => undefined);
      respond(200, await operation);
    } catch (error) {
      if (!(error instanceof AccountServiceError)) reportError(new Error('Account request failed.'));
      respond(error instanceof AccountServiceError ? error.status : 503,
        { error: error instanceof AccountServiceError ? error.message : 'Account request failed.' });
    } finally {
      if (usedFlow && flows.get(usedFlow.key) === usedFlow.flow) flows.delete(usedFlow.key);
      if (reserved) active--;
    }
  });
  return Object.freeze({ close, authorize });
}
