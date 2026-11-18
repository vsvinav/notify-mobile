import { test, expect, chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFile, mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const runtime = resolve('.test-data/remote-identity-runtime');
await mkdir(runtime, { recursive: true });
const launchOptions = { env: { ...process.env, HOME: runtime, TMPDIR: runtime,
  XDG_CACHE_HOME: runtime, XDG_CONFIG_HOME: runtime } };
test.use({ launchOptions });

let server, origin;
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    if (request.url === '/remote-identity.mjs') {
      try {
        const source = await readFile(new URL('../../public/remote-identity.mjs', import.meta.url));
        response.writeHead(200, { 'Content-Type': 'text/javascript' }).end(source);
      } catch {
        response.writeHead(404).end();
      }
    } else {
      response.writeHead(200, { 'Content-Type': 'text/html' }).end('<!doctype html><title>Identity storage test</title>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

test.beforeEach(async ({ page }) => {
  await page.goto(origin);
  expect((await page.request.get(`${origin}/remote-identity.mjs`)).ok()).toBe(true);
  await page.evaluate(async () => {
    window.identities = await import('/remote-identity.mjs');
    window.scope = { origin: location.origin, accountID: 'account-1', macID: 'mac-1' };
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    window.identity = {
      publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)),
      secret: crypto.getRandomValues(new Uint8Array(128))
    };
    window.errorCode = async operation => {
      try { await operation(); return 'success'; } catch (error) { return error.code; }
    };
    window.recordKey = value => JSON.stringify([value.origin, value.accountID, value.macID]);
    window.withStore = (operation, version = 1) => new Promise((resolve, reject) => {
      const request = indexedDB.open('notify-remote-identities', version);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction('identities', 'readwrite');
        let value;
        tx.oncomplete = () => { db.close(); resolve(value); };
        tx.onabort = () => { db.close(); reject(tx.error); };
        operation(tx.objectStore('identities'), result => { value = result; });
      };
    });
    window.readRecord = () => withStore((store, done) => {
      store.get(recordKey(scope)).onsuccess = event => done(event.target.result);
    });
    window.mutateRecord = mutate => withStore(store => {
      store.get(recordKey(scope)).onsuccess = event => {
        const record = event.target.result;
        mutate(record);
        store.put(record, recordKey(scope));
      };
    });
  });
});

test('explicit missing, durable reload, copy isolation, and exact deletion', async ({ page }) => {
  const original = await page.evaluate(async () => {
    const missing = await errorCode(() => identities.loadIdentity(scope));
    await identities.createIdentity(scope, identity);
    const other = { ...scope, macID: 'mac-2' };
    await identities.createIdentity(other, identity);
    const loaded = await identities.loadIdentity(scope, identity.publicKey);
    loaded.secret.fill(0); loaded.publicKey.fill(0);
    return { missing, publicKey: [...identity.publicKey], secret: [...identity.secret] };
  });
  expect(original.missing).toBe('missing');
  await page.reload();
  const result = await page.evaluate(async () => {
    const { loadIdentity, deleteIdentity } = await import('/remote-identity.mjs');
    const scope = { origin: location.origin, accountID: 'account-1', macID: 'mac-1' };
    const loaded = await loadIdentity(scope);
    await deleteIdentity(scope);
    let missing;
    try { await loadIdentity(scope); } catch (error) { missing = error.code; }
    await deleteIdentity(scope);
    const other = await loadIdentity({ ...scope, macID: 'mac-2' });
    return { publicKey: [...loaded.publicKey], secret: [...loaded.secret], missing, other: [...other.secret] };
  });
  expect(result).toEqual({ ...original, other: original.secret });
});

test('concurrent tabs cannot overwrite the winning identity', async ({ page, context }) => {
  const other = await context.newPage();
  await other.goto(origin);
  const attempt = (target, byte) => target.evaluate(async byte => {
    const { createIdentity, loadIdentity } = await import('/remote-identity.mjs');
    const scope = { origin: location.origin, accountID: 'race', macID: 'mac' };
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    let status = 'created';
    try { await createIdentity(scope, { publicKey, secret: new Uint8Array([byte]) }); }
    catch (error) { status = error.code; }
    return { status, secret: [...(await loadIdentity(scope)).secret] };
  }, byte);
  const results = await Promise.all([attempt(page, 1), attempt(other, 2)]);
  expect(results.map(result => result.status).sort()).toEqual(['created', 'exists']);
  expect(results[0].secret).toEqual(results[1].secret);
  expect(results[0].secret).toEqual([results[0].status === 'created' ? 1 : 2]);
});

test('survives a full browser restart with the stored nonextractable key', async () => {
  const profile = resolve(runtime, `profile-${randomUUID()}`);
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, launchOptions);
    let page = await context.newPage();
    await page.goto(origin);
    const original = await page.evaluate(async () => {
      const { createIdentity } = await import('/remote-identity.mjs');
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
      const secret = crypto.getRandomValues(new Uint8Array(256));
      await createIdentity({ origin: location.origin, accountID: 'restart', macID: 'mac' }, { publicKey, secret });
      return { publicKey: [...publicKey], secret: [...secret] };
    });
    await context.close();
    context = await chromium.launchPersistentContext(profile, launchOptions);
    page = await context.newPage();
    await page.goto(origin);
    const restored = await page.evaluate(async () => {
      const { loadIdentity } = await import('/remote-identity.mjs');
      const value = await loadIdentity({ origin: location.origin, accountID: 'restart', macID: 'mac' });
      return { publicKey: [...value.publicKey], secret: [...value.secret] };
    });
    expect(restored).toEqual(original);
  } finally {
    await context?.close();
    await rm(profile, { recursive: true, force: true });
  }
});

test('at-rest AES-GCM uses nonextractable AES-256 keys, fresh IVs and authenticated metadata', async ({ page }) => {
  const result = await page.evaluate(async () => {
    await identities.createIdentity(scope, identity);
    const first = await readRecord();
    let exportFailed = false;
    try { await crypto.subtle.exportKey('raw', first.key); } catch { exportFailed = true; }
    const additionalData = new TextEncoder().encode(JSON.stringify([
      'notify-remote-identity', 1, [scope.origin, scope.accountID, scope.macID], [...identity.publicKey]
    ]));
    const decrypted = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: first.iv, additionalData, tagLength: 128 }, first.key, first.ciphertext));
    await identities.deleteIdentity(scope);
    await identities.createIdentity(scope, identity);
    const second = await readRecord();
    return {
      exportFailed, algorithm: first.key.algorithm, extractable: first.key.extractable,
      usages: first.key.usages, ivLength: first.iv.length, ciphertextLength: first.ciphertext.length,
      plaintextLength: identity.secret.length, sameIV: first.iv.every((value, index) => value === second.iv[index]),
      plaintextMatches: decrypted.every((value, index) => value === identity.secret[index]),
      fields: Object.keys(first).sort()
    };
  });
  expect(result).toEqual({
    exportFailed: true, algorithm: { name: 'AES-GCM', length: 256 }, extractable: false,
    usages: ['encrypt', 'decrypt'], ivLength: 12, ciphertextLength: 144, plaintextLength: 128,
    sameIV: false, plaintextMatches: true,
    fields: ['ciphertext', 'iv', 'key', 'publicKey', 'scope', 'version']
  });
});

for (const corruption of ['ciphertext', 'publicKey', 'iv', 'version', 'extra', 'key', 'length']) {
  test(`rejects ${corruption} corruption without replacing stored data`, async ({ page }) => {
    const result = await page.evaluate(async corruption => {
      await identities.createIdentity(scope, identity);
      await mutateRecord(record => {
        if (corruption === 'ciphertext' || corruption === 'publicKey') record[corruption][10] ^= 1;
        if (corruption === 'iv') record.iv = new Uint8Array(11);
        if (corruption === 'version') record.version = 2;
        if (corruption === 'extra') record.secret = identity.secret;
        if (corruption === 'key') record.key = null;
        if (corruption === 'length') record.ciphertext = new Uint8Array(273);
      });
      return {
        load: await errorCode(() => identities.loadIdentity(scope)),
        create: await errorCode(() => identities.createIdentity(scope, identity)),
        stillCorrupt: await errorCode(() => identities.loadIdentity(scope))
      };
    }, corruption);
    expect(result).toEqual({ load: 'corrupt', create: 'exists', stillCorrupt: 'corrupt' });
  });
}

test('scope transplant and expected-key mismatch are explicit', async ({ page }) => {
  const result = await page.evaluate(async () => {
    await identities.createIdentity(scope, identity);
    const wrongKey = identity.publicKey.slice(); wrongKey[10] ^= 1;
    const expected = await errorCode(() => identities.loadIdentity(scope, wrongKey));
    const different = { ...scope, accountID: 'another-account' };
    await withStore(store => {
      store.get(recordKey(scope)).onsuccess = event => store.add(event.target.result, recordKey(different));
    });
    const transplant = await errorCode(() => identities.loadIdentity(different));
    await withStore(store => {
      store.get(recordKey(different)).onsuccess = event => {
        const record = event.target.result;
        record.scope = [different.origin, different.accountID, different.macID];
        store.put(record, recordKey(different));
      };
    });
    return { expected, transplant, authenticatedScope: await errorCode(() => identities.loadIdentity(different)) };
  });
  expect(result).toEqual({ expected: 'mismatch', transplant: 'mismatch', authenticatedScope: 'corrupt' });
});

test('undefined stored value is corrupt, not absent', async ({ page }) => {
  const result = await page.evaluate(async () => {
    await identities.createIdentity(scope, identity);
    await withStore(store => store.put(undefined, recordKey(scope)));
    return {
      load: await errorCode(() => identities.loadIdentity(scope)),
      create: await errorCode(() => identities.createIdentity(scope, identity))
    };
  });
  expect(result).toEqual({ load: 'corrupt', create: 'exists' });
});

test('validates bounded canonical scope and opaque identity bytes before storage', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const invalidScopes = [
      null, 'account/mac', {}, { ...scope, extra: true }, { ...scope, accountID: '' },
      { ...scope, accountID: 'a'.repeat(129) }, { ...scope, macID: '../mac' },
      { ...scope, macID: 'hello world' }, { ...scope, origin: 'null' },
      { ...scope, origin: `${scope.origin}/` }, { ...scope, origin: 'https://example.com/path' },
      { ...scope, origin: 'https://user@example.com' }, { ...scope, origin: 'http://example.com' },
      { ...scope, origin: 'HTTPS://EXAMPLE.COM' }, { ...scope, origin: `https://${'x'.repeat(2049)}.com` }
    ];
    const invalidIdentities = [
      null, { ...identity, extra: true }, { ...identity, secret: [] },
      { ...identity, secret: new Uint8Array() }, { ...identity, secret: new Uint8Array(257) },
      { ...identity, publicKey: new Uint8Array(64) }, { ...identity, publicKey: new Uint8Array(65) }
    ];
    return {
      scopes: await Promise.all(invalidScopes.flatMap(value => [
        errorCode(() => identities.createIdentity(value, identity)),
        errorCode(() => identities.loadIdentity(value)),
        errorCode(() => identities.deleteIdentity(value))
      ])),
      identities: await Promise.all(invalidIdentities.map(value => errorCode(() => identities.createIdentity(scope, value)))),
      expected: await errorCode(() => identities.loadIdentity(scope, new Uint8Array(64)))
    };
  });
  expect(result.scopes.every(code => code === 'invalid')).toBe(true);
  expect(result.identities.every(code => code === 'invalid')).toBe(true);
  expect(result.expected).toBe('invalid');
});

test('aborted writes never report success or leave partial keys', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const add = IDBObjectStore.prototype.add;
    IDBObjectStore.prototype.add = function (...args) {
      const request = add.apply(this, args);
      request.onsuccess = () => this.transaction.abort();
      return request;
    };
    let failed;
    try { failed = await errorCode(() => identities.createIdentity(scope, identity)); }
    finally { IDBObjectStore.prototype.add = add; }
    const missing = await errorCode(() => identities.loadIdentity(scope));
    const rows = await withStore((store, done) => { store.count().onsuccess = event => done(event.target.result); });
    await identities.createIdentity(scope, identity);
    return { failed, missing, rows, secret: [...(await identities.loadIdentity(scope)).secret], original: [...identity.secret] };
  });
  expect(result.failed).toBe('storage');
  expect(result.missing).toBe('missing');
  expect(result.rows).toBe(0);
  expect(result.secret).toEqual(result.original);
});

test('closes connections and rejects a newer database version without resetting it', async ({ page }) => {
  const result = await page.evaluate(async () => {
    await identities.createIdentity(scope, identity);
    await identities.loadIdentity(scope);
    await new Promise((resolve, reject) => {
      const request = indexedDB.open('notify-remote-identities', 2);
      request.onblocked = () => reject(new Error('Storage leaked an open connection'));
      request.onerror = () => reject(request.error);
      request.onsuccess = () => { request.result.close(); resolve(); };
    });
    return {
      load: await errorCode(() => identities.loadIdentity(scope)),
      create: await errorCode(() => identities.createIdentity(scope, identity)),
      delete: await errorCode(() => identities.deleteIdentity(scope)),
      count: await withStore((store, done) => { store.count().onsuccess = event => done(event.target.result); }, 2)
    };
  });
  expect(result).toEqual({ load: 'storage', create: 'storage', delete: 'storage', count: 1 });
});

test('quota and open failures reject explicitly without authorizing or replacing anything', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const add = IDBObjectStore.prototype.add;
    IDBObjectStore.prototype.add = function () { throw new DOMException('Test quota', 'QuotaExceededError'); };
    let quota;
    try { quota = await errorCode(() => identities.createIdentity(scope, identity)); }
    finally { IDBObjectStore.prototype.add = add; }
    const missing = await errorCode(() => identities.loadIdentity(scope));
    await identities.createIdentity(scope, identity);
    const open = IDBFactory.prototype.open;
    IDBFactory.prototype.open = function () { throw new DOMException('Test denied', 'SecurityError'); };
    let denied;
    try {
      denied = await Promise.all([
        errorCode(() => identities.createIdentity(scope, identity)),
        errorCode(() => identities.loadIdentity(scope)),
        errorCode(() => identities.deleteIdentity(scope))
      ]);
    } finally { IDBFactory.prototype.open = open; }
    return { quota, missing, denied, unchanged: [...(await identities.loadIdentity(scope)).secret],
      original: [...identity.secret] };
  });
  expect(result.quota).toBe('storage');
  expect(result.missing).toBe('missing');
  expect(result.denied).toEqual(['storage', 'storage', 'storage']);
  expect(result.unchanged).toEqual(result.original);
});
