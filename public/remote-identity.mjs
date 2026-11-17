/**
 * Browser software channel identities, not account credentials.
 * createIdentity(scope, { publicKey, secret }) and deleteIdentity(scope) resolve
 * only after commit; delete is idempotent. loadIdentity(scope, expectedPublicKey?)
 * returns fresh Uint8Arrays. No operation implicitly replaces an identity.
 *
 * Scope: exactly { origin, accountID, macID }; origin is a canonical HTTPS origin
 * (HTTP only for loopback), <=2048 characters; IDs match [A-Za-z0-9_-]{1,128}.
 * Secret is opaque, 1..256 bytes; public key is 65-byte uncompressed P-256.
 * The caller must verify their pairing via MLS restore and separately authorize
 * the account/Mac relationship on every use. expectedPublicKey pins that identity.
 *
 * AES-GCM plus a non-extractable IndexedDB CryptoKey is NOT hardware-backed or
 * protection against same-origin malicious JS, profile access, or storage loss.
 * No transcript, MLS ratchet state, login state, or cloud synchronization is stored.
 */

const DATABASE = 'notify-remote-identities';
const STORE = 'identities';
const VERSION = 1;

export class IdentityStorageError extends Error {
  constructor(code, cause) {
    super(`Remote identity: ${code}`, cause === undefined ? undefined : { cause });
    this.name = 'IdentityStorageError';
    this.code = code;
  }
}

function fail(code, cause) { return new IdentityStorageError(code, cause); }

function exactObject(value, fields) {
  return value !== null && typeof value === 'object'
    && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).length === fields.length
    && fields.every(field => Object.getOwnPropertyDescriptor(value, field)?.value !== undefined);
}

function scopeParts(scope) {
  if (!exactObject(scope, ['origin', 'accountID', 'macID'])
    || typeof scope.origin !== 'string' || scope.origin.length > 2048
    || ![scope.accountID, scope.macID].every(id => typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id))) {
    throw fail('invalid');
  }
  let url;
  try { url = new URL(scope.origin); } catch (cause) { throw fail('invalid', cause); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.origin !== scope.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw fail('invalid');
  }
  return [scope.origin, scope.accountID, scope.macID];
}

function bytes(value, minimum, maximum) {
  return value instanceof Uint8Array && value.buffer instanceof ArrayBuffer
    && value.byteLength >= minimum && value.byteLength <= maximum;
}

function publicKeyBytes(value) {
  return bytes(value, 65, 65) && value[0] === 4;
}

function associatedData(scope, publicKey) {
  return new TextEncoder().encode(JSON.stringify(['notify-remote-identity', VERSION, scope, [...publicKey]]));
}

function storageError(cause) {
  return cause instanceof IdentityStorageError ? cause : fail('storage', cause);
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    let request, abandoned = false;
    const rejectOpen = cause => { abandoned = true; reject(storageError(cause)); };
    try { request = indexedDB.open(DATABASE, VERSION); }
    catch (cause) { rejectOpen(cause); return; }
    request.onblocked = () => rejectOpen(fail('storage'));
    request.onerror = () => rejectOpen(request.error);
    request.onupgradeneeded = event => {
      if (abandoned || event.oldVersion !== 0) {
        request.transaction.abort();
        return;
      }
      try { request.result.createObjectStore(STORE); }
      catch (cause) { request.transaction.abort(); rejectOpen(cause); }
    };
    request.onsuccess = () => {
      const db = request.result;
      if (abandoned) { db.close(); return; }
      if (db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains(STORE)) {
        db.close(); rejectOpen(fail('corrupt')); return;
      }
      db.onversionchange = () => db.close();
      resolve(db);
    };
  });
}

async function transact(mode, operation) {
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode, mode === 'readwrite' ? { durability: 'strict' } : {});
      let request, operationError;
      tx.oncomplete = () => resolve(request?.result);
      tx.onabort = () => {
        const cause = operationError ?? tx.error;
        reject(cause?.name === 'ConstraintError' ? fail('exists', cause) : storageError(cause));
      };
      try {
        const store = tx.objectStore(STORE);
        if (store.keyPath !== null || store.autoIncrement) throw fail('corrupt');
        request = operation(store);
      } catch (cause) {
        operationError = cause;
        tx.abort();
      }
    });
  } catch (cause) {
    throw storageError(cause);
  } finally {
    db.close();
  }
}

function validateRecord(record, scope) {
  if (!exactObject(record, ['version', 'scope', 'publicKey', 'iv', 'ciphertext', 'key'])
    || record.version !== VERSION || !Array.isArray(record.scope) || record.scope.length !== 3
    || !publicKeyBytes(record.publicKey) || !bytes(record.iv, 12, 12) || !bytes(record.ciphertext, 17, 272)) {
    throw fail('corrupt');
  }
  try {
    scopeParts({ origin: record.scope[0], accountID: record.scope[1], macID: record.scope[2] });
  } catch (cause) { throw fail('corrupt', cause); }
  if (JSON.stringify(record.scope) !== JSON.stringify(scope)) throw fail('mismatch');
  const key = record.key;
  if (!(key instanceof CryptoKey) || key.type !== 'secret' || key.extractable
    || key.algorithm.name !== 'AES-GCM' || key.algorithm.length !== 256
    || key.usages.length !== 2 || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
    throw fail('corrupt');
  }
}

/** Create only: rejects "exists" even when the existing record is corrupt. */
export async function createIdentity(scope, identity) {
  const parts = scopeParts(scope);
  if (!exactObject(identity, ['publicKey', 'secret'])
    || !publicKeyBytes(identity.publicKey) || !bytes(identity.secret, 1, 256)) throw fail('invalid');
  const publicKey = identity.publicKey.slice();
  const secret = identity.secret.slice();
  try {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM', iv, additionalData: associatedData(parts, publicKey), tagLength: 128
    }, key, secret));
    // One add stores both ciphertext and key atomically; concurrent creates cannot replace it.
    await transact('readwrite', store => store.add({
      version: VERSION, scope: parts, publicKey, iv, ciphertext, key
    }, JSON.stringify(parts)));
  } catch (cause) {
    throw storageError(cause);
  } finally {
    secret.fill(0);
  }
}

/** Load only: errors have code invalid, missing, mismatch, corrupt, or storage. */
export async function loadIdentity(scope, expectedPublicKey) {
  const parts = scopeParts(scope);
  if (expectedPublicKey !== undefined && !publicKeyBytes(expectedPublicKey)) throw fail('invalid');
  const expected = expectedPublicKey?.slice();
  const records = await transact('readonly', store => store.getAll(JSON.stringify(parts), 1));
  if (records.length === 0) throw fail('missing');
  const [record] = records;
  validateRecord(record, parts);
  if (expected && !expected.every((value, index) => record.publicKey[index] === value)) throw fail('mismatch');
  let secret;
  try {
    secret = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: record.iv, additionalData: associatedData(parts, record.publicKey), tagLength: 128
    }, record.key, record.ciphertext));
  } catch (cause) { throw fail('corrupt', cause); }
  if (!bytes(secret, 1, 256)) { secret.fill(0); throw fail('corrupt'); }
  return { publicKey: record.publicKey.slice(), secret };
}

/** Forget exactly this relationship, including corrupt records. Never deletes a database. */
export async function deleteIdentity(scope) {
  const parts = scopeParts(scope);
  await transact('readwrite', store => store.delete(JSON.stringify(parts)));
}
