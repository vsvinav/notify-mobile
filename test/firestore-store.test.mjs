import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { firestoreFixture } from './fixtures/firestore.mjs';

const origin = 'https://notify.example';
const module = () => import('../src/firestore-store.mjs');

test('durable stores preserve state and fence an overlapping previous writer', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const first = await createFirestoreStores({ firestore: db.firestore, origin });
  assert.equal(await first.accounts.read(), null);
  assert.equal(await first.trust.read(), null);
  await first.accounts.write({ fixture: 'public accounts' });
  await first.trust.write({ fixture: 'public trust' });
  const second = await createFirestoreStores({ firestore: db.firestore, origin });
  assert.deepEqual(await second.accounts.read(), { fixture: 'public accounts' });
  assert.deepEqual(await second.trust.read(), { fixture: 'public trust' });
  await assert.rejects(first.trust.check(), /storage/i);
  await assert.rejects(first.accounts.write({ fixture: 'stale' }), /storage/i);
  await assert.rejects(first.trust.write({ fixture: 'stale' }), /storage/i);
  assert.deepEqual(await second.trust.read(), { fixture: 'public trust' });
  const writes = db.metrics.writes, reads = db.metrics.reads;
  for (let i = 0; i < 20; i++) await second.trust.check();
  assert.equal(db.metrics.writes, writes);
  assert.equal(db.metrics.reads - reads, 20);
});

test('missing, oversized, corrupt and conflicting records fail closed instead of resetting', async () => {
  const { createFirestoreStores } = await module();
  for (const corrupt of [
    db => db.documents.delete('notifyState/accounts'),
    db => { db.documents.get('notifyState/accounts').json = '{'; },
    db => { db.documents.get('notifyState/accounts').extra = true; },
    db => { db.documents.get('notifyState/accounts').json = JSON.stringify('x'.repeat(900001)); },
    db => { db.documents.get('notifyState/fence').origin = 'https://other.example'; }
  ]) {
    const db = firestoreFixture();
    const stores = await createFirestoreStores({ firestore: db.firestore, origin });
    await stores.accounts.read();
    corrupt(db);
    const before = structuredClone([...db.documents]);
    await assert.rejects(createFirestoreStores({ firestore: db.firestore, origin }), /storage/i);
    assert.deepEqual([...db.documents], before);
  }
  const db = firestoreFixture(), stores = await createFirestoreStores({ firestore: db.firestore, origin });
  await stores.accounts.read();
  await assert.rejects(stores.accounts.write({ value: 'x'.repeat(900001) }), /storage|limit/i);
  const next = await createFirestoreStores({ firestore: db.firestore, origin });
  await next.accounts.read();
  db.documents.get('notifyState/accounts').revision++;
  await assert.rejects(next.accounts.write({ stale: true }), /storage/i);
});

test('write failures neither acknowledge nor erase durable data', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const stores = await createFirestoreStores({ firestore: db.firestore, origin });
  await stores.trust.read();
  await stores.trust.write({ approved: true });
  db.fail(true);
  await assert.rejects(stores.trust.write({ approved: false }), /storage/i);
  db.fail(false);
  await assert.rejects(stores.trust.check(), /storage/i);
  const fresh = await createFirestoreStores({ firestore: db.firestore, origin });
  assert.deepEqual(await fresh.trust.read(), { approved: true });
});

test('simultaneous writes use revision CAS, and a stale generation cannot commit without a prior check', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const first = await createFirestoreStores({ firestore: db.firestore, origin });
  await first.trust.read();
  const results = await Promise.allSettled([
    first.trust.write({ record: 'first' }), first.trust.write({ record: 'conflicting' })
  ]);
  assert.equal(results.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(results.filter(value => value.status === 'rejected').length, 1);
  const second = await createFirestoreStores({ firestore: db.firestore, origin });
  assert.deepEqual(await second.trust.read(), { record: 'first' });
  const third = await createFirestoreStores({ firestore: db.firestore, origin });
  await assert.rejects(second.trust.write({ record: 'stale generation' }), /storage/i);
  assert.deepEqual(await third.trust.read(), { record: 'first' });
});

test('a concurrent storage fault cannot produce a late successful mutation reply', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const stores = await createFirestoreStores({ firestore: db.firestore, origin });
  await stores.trust.read();
  let enter, release;
  const entered = new Promise(resolve => { enter = resolve; });
  db.beforeCommit(async () => { enter(); await new Promise(resolve => { release = resolve; }); });
  const write = stores.trust.write({ approved: true });
  await entered;
  db.fail(true);
  await assert.rejects(stores.accounts.check(), /storage/i);
  db.fail(false);
  release();
  await assert.rejects(write, /storage/i);
});

test('status alone samples a positive fence for at most 30 monotonic seconds', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  let now = 0;
  const stores = await createFirestoreStores({ firestore: db.firestore, origin, now: () => now });
  assert.equal(typeof stores.trust.checkStatus, 'function');
  await stores.trust.read();
  const before = db.metrics.reads;
  await stores.trust.checkStatus();
  now = 29999;
  await stores.trust.checkStatus();
  assert.equal(db.metrics.reads, before);
  now = 30000;
  await stores.trust.checkStatus();
  assert.equal(db.metrics.reads, before + 1);
  await stores.trust.check();
  assert.equal(db.metrics.reads, before + 2, 'Authorization never uses the status sample');
  db.fail(true);
  await assert.rejects(stores.accounts.check(), /storage/i);
  await assert.rejects(stores.trust.checkStatus(), /storage/i);
});

test('one and two phones stay within the daily read budget without sampling their renewal checks', async () => {
  const { createFirestoreStores } = await module();
  for (const phones of [1, 2]) {
    const db = firestoreFixture();
    let now = 0;
    const stores = await createFirestoreStores({ firestore: db.firestore, origin, now: () => now });
    await stores.trust.read();
    const reads = db.metrics.reads, writes = db.metrics.writes;
    for (let second = 1; second <= 86400; second++) {
      now = second * 1000;
      if (second % 10 === 0)
        for (let endpoint = 0; endpoint < phones * 2; endpoint++) await stores.trust.check();
      if (second % 3 === 0) await stores.trust.checkStatus();
    }
    assert.equal(db.metrics.reads - reads, phones * 17280);
    assert.equal(db.metrics.writes, writes);
  }
});

test('status sampling includes RPC time and fails closed on monotonic rollback', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  let now = 0;
  const stores = await createFirestoreStores({ firestore: db.firestore, origin, now: () => now });
  db.beforeCommit(() => { now = 31000; });
  await stores.trust.read();
  db.beforeCommit(undefined);
  const reads = db.metrics.reads;
  await stores.trust.checkStatus();
  assert.equal(db.metrics.reads, reads + 1, 'A slow read cannot extend the positive sample lifetime');
  now--;
  await assert.rejects(stores.trust.checkStatus(), /storage/i);
  assert.equal(stores.failure, 'clock');
  await assert.rejects(stores.recover(), /storage/i);
});

test('transient recovery drains uncertain writes, reloads committed state and retains its owned generation', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const stores = await createFirestoreStores({ firestore: db.firestore, origin });
  await stores.trust.read();
  const generation = db.documents.get('notifyState/fence').generation;
  const incarnation = db.documents.get('notifyState/fence').incarnation;
  let entered, release;
  const waiting = new Promise(resolve => { entered = resolve; });
  db.beforeCommit(async () => { entered(); await new Promise(resolve => { release = resolve; }); });
  const write = stores.trust.write({ value: 'committed despite lost reply' });
  await waiting;
  db.fail(true, 14);
  await assert.rejects(stores.accounts.check(), /storage/i);
  assert.equal(stores.failure, 'transient');
  let recovered = false;
  const recovery = stores.recover().then(value => { recovered = true; return value; });
  await Promise.resolve();
  assert.equal(recovered, false);
  db.fail(false);
  db.beforeCommit(undefined);
  release();
  await assert.rejects(write, /storage/i);
  const fresh = await recovery;
  assert.deepEqual(await fresh.trust.read(), { value: 'committed despite lost reply' });
  assert.equal(db.documents.get('notifyState/fence').generation, generation);
  assert.notEqual(db.documents.get('notifyState/fence').incarnation, incarnation,
    'Recovery must change the fence document, not rely on a potentially optimized no-op write');
  await assert.rejects(stores.trust.write({ value: 'old callback' }), /storage/i);
  assert.equal(stores.failure, null, 'An obsolete handle cannot poison the recovered generation');
});

test('an unknown recovery-barrier outcome can resume only its own pending incarnation', async () => {
  const { createFirestoreStores } = await module(), db = firestoreFixture();
  const stores = await createFirestoreStores({ firestore: db.firestore, origin });
  db.fail(true, 14);
  await assert.rejects(stores.trust.check(), /storage/i);
  db.fail(false);
  db.afterCommit(writes => {
    if (!writes.some(([path]) => path === 'notifyState/fence')) return;
    db.afterCommit(undefined);
    throw Object.assign(new Error('Synthetic lost barrier response'), { code: 4 });
  });
  await assert.rejects(stores.recover(), /storage/i);
  const incarnation = db.documents.get('notifyState/fence').incarnation;
  const recovered = await stores.recover();
  assert.equal(await recovered.trust.read(), null);
  assert.equal(db.documents.get('notifyState/fence').incarnation, incarnation);
  db.fail(true, 14);
  await assert.rejects(recovered.trust.check(), /storage/i);
  db.fail(false);
  db.documents.get('notifyState/fence').incarnation = randomUUID();
  await assert.rejects(stores.recover(), /storage/i);
  assert.equal(stores.failure, 'conflict');
});

test('recovery refuses successor ownership, corrupt records, and non-transient storage failures', async () => {
  const { createFirestoreStores } = await module();
  for (const reason of ['successor', 'corrupt', 'permission', 'revision']) {
    const db = firestoreFixture();
    const stores = await createFirestoreStores({ firestore: db.firestore, origin });
    await stores.trust.read();
    if (reason === 'revision') {
      db.documents.get('notifyState/trust').revision++;
      await assert.rejects(stores.trust.write({ wrong: true }), /storage/i);
    } else {
      db.fail(true, reason === 'permission' ? 7 : 14);
      await assert.rejects(stores.trust.check(), /storage/i);
      db.fail(false);
    }
    if (reason === 'successor') await createFirestoreStores({ firestore: db.firestore, origin });
    if (reason === 'corrupt') db.documents.get('notifyState/trust').json = '{';
    const before = structuredClone([...db.documents]);
    await assert.rejects(stores.recover(), /storage/i);
    assert.notEqual(stores.failure, 'transient');
    assert.deepEqual([...db.documents], before);
  }
});

test('Firebase configuration requires explicit project-matched credentials and pins Google endpoints', async t => {
  const { createFirebaseStores } = await module();
  assert.equal(typeof createFirebaseStores, 'function');
  assert.equal(await createFirebaseStores({ origin, env: {} }), null);
  for (const env of [
    { NOTIFY_FIREBASE_PROJECT_ID: 'notify-fixture' },
    { NOTIFY_FIREBASE_CREDENTIALS_FILE: '/nonexistent-fixture' },
    { NOTIFY_FIREBASE_PROJECT_ID: '', NOTIFY_FIREBASE_CREDENTIALS_FILE: '' }
  ]) await assert.rejects(createFirebaseStores({ origin, env }), /Firebase configuration/);
  const directory = resolve('.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = resolve(directory, 'synthetic-service-account.json');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const credential = { type: 'service_account', project_id: 'notify-fixture',
    client_email: 'notify-backend@notify-fixture.iam.gserviceaccount.com',
    private_key_id: 'a'.repeat(40), private_key: privateKey.export({ format: 'pem', type: 'pkcs8' }),
    token_uri: 'https://oauth2.googleapis.com/token', universe_domain: 'googleapis.com' };
  const env = { NOTIFY_FIREBASE_PROJECT_ID: 'notify-fixture', NOTIFY_FIREBASE_CREDENTIALS_FILE: file };
  let constructed = 0, options, terminated = 0;
  class SyntheticFirestore {
    constructor(config) {
      constructed++; options = config;
      Object.assign(this, firestoreFixture().firestore);
    }
    async terminate() { terminated++; }
  }
  for (const patch of [
    { project_id: 'other-project' }, { type: 'authorized_user' },
    { token_uri: 'https://attacker.invalid/token' }, { token_uri: 'http://oauth2.googleapis.com/token' },
    { universe_domain: 'attacker.invalid' }, { private_key: 'not a private key' },
    { client_email: 'notify-backend@other-project.iam.gserviceaccount.com' }
  ]) {
    await writeFile(file, JSON.stringify({ ...credential, ...patch }));
    await assert.rejects(createFirebaseStores({ origin, env, Firestore: SyntheticFirestore }), /Firebase configuration/);
  }
  assert.equal(constructed, 0);
  await writeFile(file, JSON.stringify(credential));
  for (const overrides of [
    { FIRESTORE_EMULATOR_HOST: 'localhost:8080' },
    { GOOGLE_API_USE_CLIENT_CERTIFICATE: 'true' },
    { GOOGLE_API_USE_MTLS_ENDPOINT: 'always' }
  ]) await assert.rejects(createFirebaseStores({ origin, env: { ...env, ...overrides },
    Firestore: SyntheticFirestore }), /Firebase configuration/);
  const stores = await createFirebaseStores({ origin, env, Firestore: SyntheticFirestore });
  assert.equal(await stores.accounts.read(), null);
  assert.equal(options.projectId, 'notify-fixture');
  assert.equal(options.apiEndpoint, 'firestore.googleapis.com');
  assert.equal(options.universeDomain, 'googleapis.com');
  assert.deepEqual(Object.keys(options.credentials).sort(), ['client_email', 'private_key']);
  assert.equal(options.ssl, true);
  await stores.close();
  assert.equal(terminated, 1);
});

test('Firebase configured but unavailable fails startup with sanitized errors and no local fallback', async t => {
  const { createFirebaseStores } = await module();
  const directory = resolve('.test-data', randomUUID());
  await mkdir(directory, { recursive: true });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = resolve(directory, 'synthetic.json');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await writeFile(file, JSON.stringify({ type: 'service_account', project_id: 'notify-fixture',
    client_email: 'notify-backend@notify-fixture.iam.gserviceaccount.com',
    token_uri: 'https://oauth2.googleapis.com/token',
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  let terminated = false;
  class UnavailableFirestore {
    doc(path) { return { path }; }
    async runTransaction() { throw new Error('Synthetic credential contents must never appear in errors'); }
    async terminate() { terminated = true; }
  }
  await assert.rejects(createFirebaseStores({ origin,
    env: { NOTIFY_FIREBASE_PROJECT_ID: 'notify-fixture', NOTIFY_FIREBASE_CREDENTIALS_FILE: file },
    Firestore: UnavailableFirestore }), error =>
    /durable storage unavailable/.test(error.message) && !/Synthetic credential/.test(error.message));
  assert.equal(terminated, true);
});
