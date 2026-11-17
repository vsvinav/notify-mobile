import { createPrivateKey, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, sep } from 'node:path';
import { performance } from 'node:perf_hooks';

const LIMIT = 900000;
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/.test(value);
class StorageError extends Error {
  constructor(kind = 'permanent', retryAfter = 1000) {
    super('Notify durable storage unavailable or fenced.');
    this.kind = kind;
    this.retryAfter = retryAfter;
  }
}
const unavailable = kind => new StorageError(kind);

function envelope(snapshot) {
  if (!snapshot.exists) throw unavailable('corrupt');
  const value = snapshot.data();
  if (!fields(value, ['version', 'revision', 'json']) || value.version !== 1 ||
    !Number.isSafeInteger(value.revision) || value.revision < 0 ||
    typeof value.json !== 'string' || Buffer.byteLength(value.json) > LIMIT) throw unavailable('corrupt');
  let state;
  try { state = JSON.parse(value.json); } catch { throw unavailable('corrupt'); }
  if (state === null && value.revision !== 0) throw unavailable('corrupt');
  return { ...value, state };
}

// One active writer for both services. A startup transaction takes ownership;
// old processes may finish already-issued 30s leases, but cannot renew or save.
export async function createFirestoreStores({ firestore, origin, now = () => performance.now() }) {
  const endpoint = new URL(origin);
  if (endpoint.protocol !== 'https:' || endpoint.origin !== origin) throw unavailable();
  const fence = firestore.doc('notifyState/fence');
  const records = ['accounts', 'trust'].map(name => firestore.doc(`notifyState/${name}`));
  const generation = randomUUID();
  let incarnation = randomUUID(), pendingIncarnation;
  let fault = null, view = 0, active = 0, drained, releaseDrain, recovery;
  let lastVerified = -Infinity, lastTime = -Infinity;
  const listeners = new Set();
  function clock() {
    const value = now();
    if (!Number.isFinite(value) || value < 0 || value < lastTime) throw unavailable('clock');
    lastTime = value;
    return value;
  }
  function failed(error) {
    const transient = [4, 8, 14, 'DEADLINE_EXCEEDED', 'RESOURCE_EXHAUSTED', 'UNAVAILABLE',
      'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN'].includes(error?.code);
    const failure = error instanceof StorageError ? error
      : new StorageError(transient ? 'transient' : 'permanent',
        [8, 'RESOURCE_EXHAUSTED'].includes(error?.code) ? 60000 : 1000);
    if (!fault || fault.kind === 'transient') fault = failure;
    lastVerified = -Infinity;
    for (const listener of listeners) { try { listener(); } catch {} }
    return fault;
  }
  const validFence = snapshot => {
    const value = snapshot.exists && snapshot.data();
    if ((!fields(value, ['version', 'origin', 'generation']) &&
      !fields(value, ['version', 'origin', 'generation', 'incarnation'])) || value.version !== 1 ||
      value.origin !== origin || !uuid(value.generation) ||
      (Object.hasOwn(value, 'incarnation') && !uuid(value.incarnation))) throw unavailable('corrupt');
    return { ...value, incarnation: value.incarnation ?? value.generation };
  };
  const owned = snapshot => {
    const value = validFence(snapshot);
    if (value.generation !== generation) throw unavailable('fenced');
    if (value.incarnation !== incarnation) throw unavailable('conflict');
  };
  async function guard(operation, expectedView = view) {
    if (expectedView !== view) throw unavailable('obsolete');
    if (fault) throw fault;
    active++;
    try {
      const value = await operation();
      if (fault) throw fault;
      return value;
    } catch (error) {
      throw failed(error);
    } finally {
      if (--active === 0) { releaseDrain?.(); drained = releaseDrain = undefined; }
    }
  }

  await guard(() => firestore.runTransaction(async tx => {
    const snapshots = await Promise.all([fence, ...records].map(ref => tx.get(ref)));
    if (snapshots[0].exists) {
      validFence(snapshots[0]);
      snapshots.slice(1).forEach(envelope);
    } else {
      if (snapshots.some(snapshot => snapshot.exists)) throw unavailable('corrupt');
      for (const ref of records) tx.set(ref, { version: 1, revision: 0, json: 'null' });
    }
    tx.set(fence, { version: 1, origin, generation, incarnation });
  }));
  function store(ref) {
    let revision;
    const expectedView = view;
    const run = operation => guard(operation, expectedView);
    const fresh = async () => {
      const began = clock();
      owned(await fence.get());
      if (!fault) lastVerified = began;
    };
    return Object.freeze({
      check: () => run(fresh),
      checkStatus: () => run(async () => {
        if (clock() - lastVerified >= 30000) await fresh();
      }),
      read: () => run(async () => {
        const began = clock();
        const value = await firestore.runTransaction(async tx => {
          const [owner, record] = await Promise.all([tx.get(fence), tx.get(ref)]);
          owned(owner);
          return envelope(record);
        });
        revision = value.revision;
        if (!fault) lastVerified = began;
        return value.state;
      }),
      write: state => run(async () => {
        const json = JSON.stringify(state);
        if (state === null || typeof json !== 'string' || Buffer.byteLength(json) > LIMIT ||
          !Number.isSafeInteger(revision) || revision >= Number.MAX_SAFE_INTEGER) throw unavailable();
        const expected = revision, began = clock();
        await firestore.runTransaction(async tx => {
          const [owner, record] = await Promise.all([tx.get(fence), tx.get(ref)]);
          owned(owner);
          if (envelope(record).revision !== expected) throw unavailable('conflict');
          if (fault) throw fault;
          tx.set(ref, { version: 1, revision: expected + 1, json });
        });
        revision = expected + 1;
        if (!fault) lastVerified = began;
      })
    });
  }
  const bundle = () => ({ accounts: store(records[0]), trust: store(records[1]) });
  function recover() {
    if (recovery) return recovery;
    recovery = (async () => {
      if (fault?.kind !== 'transient') throw fault ?? unavailable();
      if (active) await (drained ??= new Promise(resolve => { releaseDrain = resolve; }));
      if (fault?.kind !== 'transient') throw fault ?? unavailable();
      pendingIncarnation ??= randomUUID();
      try {
        await firestore.runTransaction(async tx => {
          const snapshots = await Promise.all([fence, ...records].map(ref => tx.get(ref)));
          const owner = validFence(snapshots[0]);
          if (owner.generation !== generation) throw unavailable('fenced');
          if (![incarnation, pendingIncarnation].includes(owner.incarnation)) throw unavailable('conflict');
          snapshots.slice(1).forEach(envelope);
          // Same owner, new document version: serialize against a commit whose
          // reply was lost. No old transaction can commit past this read barrier.
          tx.set(fence, { ...owner, incarnation: pendingIncarnation });
        });
        incarnation = pendingIncarnation;
        pendingIncarnation = undefined;
        view++;
        fault = null;
        lastVerified = -Infinity;
        return bundle();
      } catch (error) { throw failed(error); }
    })().finally(() => { recovery = undefined; });
    return recovery;
  }
  return Object.freeze({ ...bundle(), recover,
    get failure() { return fault?.kind ?? null; },
    get retryAfter() { return fault?.retryAfter ?? 1000; },
    block: () => failed(unavailable('corrupt')),
    onFailure(listener) { listeners.add(listener); return () => listeners.delete(listener); }
  });
}

export async function firebaseConfiguration(env = process.env, files = { open, realpath }) {
  const projectId = env.NOTIFY_FIREBASE_PROJECT_ID, file = env.NOTIFY_FIREBASE_CREDENTIALS_FILE;
  if (projectId === undefined && file === undefined) return null;
  let handle, credentials;
  try {
    if (typeof projectId !== 'string' || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId) ||
      typeof file !== 'string' || !isAbsolute(file) ||
      env.FIRESTORE_EMULATOR_HOST !== undefined || process.env.FIRESTORE_EMULATOR_HOST !== undefined ||
      [env, process.env].some(config => config.GOOGLE_API_USE_CLIENT_CERTIFICATE === 'true' ||
        config.GOOGLE_API_USE_MTLS_ENDPOINT === 'always') ||
      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '1') throw new Error();
    try {
      handle = await files.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (error.code !== 'ELOOP' || env.RENDER !== 'true' || dirname(file) !== '/etc/secrets') throw error;
      // Render projects secret files through links; never follow one outside its managed mount.
      const root = await files.realpath('/etc/secrets'), target = await files.realpath(file);
      if (!target.startsWith(`${root}${sep}`)) throw new Error();
      handle = await files.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    }
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 32768) throw new Error();
    const value = JSON.parse(await handle.readFile('utf8'));
    if (value.type !== 'service_account' || value.project_id !== projectId ||
      typeof value.client_email !== 'string' ||
      !/^[a-z][a-z0-9-]{4,62}@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(value.client_email) ||
      !value.client_email.endsWith(`@${projectId}.iam.gserviceaccount.com`) ||
      value.token_uri !== 'https://oauth2.googleapis.com/token' ||
      (value.universe_domain !== undefined && value.universe_domain !== 'googleapis.com') ||
      (value.auth_uri !== undefined && value.auth_uri !== 'https://accounts.google.com/o/oauth2/auth') ||
      typeof value.private_key !== 'string' || !value.private_key.startsWith('-----BEGIN PRIVATE KEY-----'))
      throw new Error();
    const key = createPrivateKey(value.private_key);
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error();
    // Never pass credential-supplied URLs or discover application-default credentials.
    credentials = { client_email: value.client_email, private_key: value.private_key };
  } catch (error) {
    const startupCode = error.code === 'ENOENT' ? 'firebase-file-missing' :
      error.code === 'ELOOP' ? 'firebase-file-symlink' :
      error.code === 'EACCES' ? 'firebase-file-permission' : 'firebase-config-invalid';
    throw Object.assign(new Error('Invalid Firebase configuration. Supply an explicit Notify-only project and matching service-account file.'),
      { startupCode });
  } finally {
    await handle?.close();
  }
  return { projectId, credentials };
}

export async function createFirebaseStores({ origin, env = process.env, Firestore } = {}) {
  const config = await firebaseConfiguration(env);
  if (!config) return null;
  const { projectId, credentials } = config;
  let firestore;
  try {
    Firestore ??= (await import('@google-cloud/firestore')).Firestore;
    firestore = new Firestore({ projectId, credentials, apiEndpoint: 'firestore.googleapis.com',
      universeDomain: 'googleapis.com', ssl: true, preferRest: true });
    const stores = await createFirestoreStores({ firestore, origin });
    let closing;
    return Object.freeze({ ...stores,
      get failure() { return stores.failure; }, get retryAfter() { return stores.retryAfter; },
      close: () => closing ??= firestore.terminate() });
  } catch {
    try { await firestore?.terminate(); } catch {}
    throw Object.assign(unavailable(), { startupCode: 'firebase-storage-unavailable' });
  }
}
