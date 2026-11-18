import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { rm, readFile } from 'node:fs/promises';
import { RemoteAccess } from '../src/remote-access.mjs';
import { privateDirectory, stateStore } from '../src/storage.mjs';

const owner = { issuer: 'https://accounts.notify.invalid', subject: 'account-a', macID: 'mac-a' };
const peer = { ...owner, deviceID: 'phone-a', keyHash: 'a'.repeat(64) };
const device = { deviceID: peer.deviceID, keyHash: peer.keyHash };
const command = (access, extra = {}) => ({
  id: randomUUID(), epoch: access.epoch, payload: Buffer.from('synthetic exact target and action'), ...extra
});
function memoryStore() {
  let state = null;
  return { read: async () => structuredClone(state), write: async next => { state = structuredClone(next); } };
}
async function fixture(store = memoryStore()) {
  let clock = 1000;
  const access = await RemoteAccess.open({ owner, store, now: () => clock });
  await access.approveDevice(device);
  access.enable();
  return { access, store, setClock: value => { clock = value; } };
}

test('account identity alone, different Mac/key and copied handles cannot authorize access', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  for (const input of [null, owner, { ...peer, subject: 'account-b' }, { ...peer, macID: 'mac-b' },
    { ...peer, issuer: 'https://other.invalid' }, { ...peer, deviceID: 'other' }, { ...peer, keyHash: 'b'.repeat(64) }]) {
    assert.throws(() => access.connect(input, 30000), { status: 403 });
  }
  const handle = access.connect(peer, 30000);
  assert.deepEqual(access.authorize(handle), peer);
  assert.throws(() => access.authorize({ ...handle }), { status: 403 });
  const mutable = { ...peer };
  const other = access.connect(mutable, 30000);
  mutable.keyHash = 'b'.repeat(64);
  assert.deepEqual(access.authorize(other), peer);
  access.disable();
  assert.equal(handle.signal.aborted, true);
  assert.throws(() => access.connect(peer, 30000), { status: 503 });
});

test('authorization expires at the exact deadline and clock rollback fails closed', async t => {
  const { access, setClock } = await fixture(); t.after(() => access.disable());
  for (const duration of [0, -1, 30001, NaN, Infinity, 1.5])
    assert.throws(() => access.connect(peer, duration), { status: 400 });
  const handle = access.connect(peer, 30);
  setClock(1029); access.authorize(handle);
  setClock(1030);
  assert.throws(() => access.authorize(handle), { status: 403 });
  assert.equal(handle.signal.aborted, true);
  const next = access.connect(peer, 30000);
  setClock(1000);
  assert.throws(() => access.authorize(next), { status: 503 });
  assert.equal(next.signal.aborted, true);
  assert.throws(() => access.enable(), { status: 503 });
});

test('renewal retains the live handle, pending mutation and replay history beyond the original lease', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { access, setClock } = await fixture(); t.after(() => access.disable());
  const handle = access.connect(peer, 30000), epoch = access.epoch, input = command(access);
  let release, sends = 0;
  const pending = access.dispatch(handle, input, () => {
    sends++;
    return new Promise(resolve => { release = resolve; });
  });
  setClock(21000); t.mock.timers.tick(20000);
  access.renew(handle, 30000);
  setClock(32000); t.mock.timers.tick(11000);
  assert.equal(handle.signal.aborted, false);
  assert.equal(access.epoch, epoch);
  assert.deepEqual(access.authorize(handle), peer);
  await assert.rejects(access.dispatch(handle, input, () => sends++), { status: 409 });
  release({ acknowledged: true });
  assert.deepEqual(await pending, { acknowledged: true });
  assert.equal(sends, 1);
  setClock(51000); t.mock.timers.tick(19000);
  assert.equal(handle.signal.aborted, true);
});

test('renewal rejects invalid lifetimes, copied, expired and revoked handles', async t => {
  const { access, setClock } = await fixture(); t.after(() => access.disable());
  const handle = access.connect(peer, 30000);
  for (const duration of [0, -1, 30001, NaN, Infinity, 1.5])
    assert.throws(() => access.renew(handle, duration), { status: 400 });
  assert.throws(() => access.renew({ ...handle }, 30000), { status: 403 });
  setClock(31000);
  assert.throws(() => access.renew(handle, 30000), { status: 403 });
  const next = access.connect(peer, 30000);
  await access.revokeDevice(peer.deviceID);
  assert.throws(() => access.renew(next, 30000), { status: 403 });
});

test('revocation closes channels before persistence completes and cannot be undone by reconnect', async t => {
  const store = memoryStore();
  const { access } = await fixture(store); t.after(() => access.disable());
  const handle = access.connect(peer, 30000);
  const save = store.write;
  let release;
  store.write = state => new Promise(resolve => { release = async () => { await save(state); resolve(); }; });
  const pending = access.revokeDevice(peer.deviceID);
  assert.equal(handle.signal.aborted, true);
  assert.throws(() => access.connect(peer, 30000), { status: 503 });
  await new Promise(resolve => setImmediate(resolve));
  await release(); await pending;
  assert.throws(() => access.connect(peer, 30000), { status: 403 });
  assert.deepEqual((await store.read()).devices, []);
});

test('concurrent local approvals preserve both devices; failed persistence disables all access', async t => {
  const store = memoryStore();
  const { access } = await fixture(store); t.after(() => access.disable());
  await Promise.all([
    access.approveDevice({ deviceID: 'phone-b', keyHash: 'b'.repeat(64) }),
    access.approveDevice({ deviceID: 'phone-c', keyHash: 'c'.repeat(64) })
  ]);
  assert.equal((await store.read()).devices.length, 3);
  const handle = access.connect(peer, 30000);
  store.write = async () => { throw new Error('Disk unavailable'); };
  await assert.rejects(access.revokeDevice(peer.deviceID), /Disk unavailable/);
  assert.equal(handle.signal.aborted, true);
  assert.throws(() => access.enable(), { status: 503 });
  assert.throws(() => access.connect(peer, 30000), { status: 503 });
});

test('private allowlist survives restart, but enablement and connection authority never do', async t => {
  const directory = join(process.cwd(), '.test-data', randomUUID());
  await privateDirectory(directory);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = stateStore(directory);
  const { access } = await fixture(store); t.after(() => access.disable());
  const previous = access.connect(peer, 30000);
  const oldCommand = command(access);
  const next = await RemoteAccess.open({ owner, store }); t.after(() => next.disable());
  assert.throws(() => next.connect(peer, 30000), { status: 503 });
  next.enable();
  const current = next.connect(peer, 30000);
  assert.throws(() => next.authorize(previous), { status: 403 });
  await assert.rejects(next.dispatch(current, oldCommand, () => assert.fail('Old epoch dispatched')), { status: 409 });
  await next.revokeDevice(peer.deviceID);
  assert.doesNotMatch(await readFile(join(directory, 'state.json'), 'utf8'), /synthetic|payload|epoch/);
  const final = await RemoteAccess.open({ owner, store }); t.after(() => final.disable());
  final.enable();
  assert.throws(() => final.connect(peer, 30000), { status: 403 });
  await assert.rejects(RemoteAccess.open({ owner: { ...owner, subject: 'account-b' }, store }), /owner/i);
});

test('same UUID cannot dispatch twice across reconnect, even after a lost response', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  let calls = 0;
  const input = command(access);
  const first = access.connect(peer, 30000);
  await assert.rejects(access.dispatch(first, input, () => { calls++; throw new Error('Response lost'); }), /Response lost/);
  access.disconnect(first);
  const second = access.connect(peer, 30000);
  await assert.rejects(access.dispatch(second, input, () => calls++), { status: 409 });
  await assert.rejects(access.dispatch(second, { ...input, payload: Buffer.from('another target') }, () => calls++), { status: 409 });
  assert.equal(calls, 1);
  const receipt = { ok: true, status: 'queued', detail: 'Not completed' };
  assert.equal(await access.dispatch(second, command(access), () => receipt), receipt);
});

test('dispatch copies authenticated bytes and revocation cannot claim rollback of sent work', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  const handle = access.connect(peer, 30000);
  const input = command(access);
  const original = Buffer.from(input.payload);
  let release, captured;
  const pending = access.dispatch(handle, input, bytes => {
    captured = bytes;
    return new Promise(resolve => { release = resolve; });
  });
  input.payload.fill(0);
  assert.deepEqual(captured, original);
  await access.revokeDevice(peer.deviceID);
  await assert.rejects(access.dispatch(handle, command(access), () => assert.fail('Revoked dispatch')), { status: 403 });
  release({ status: 'unknown' });
  assert.deepEqual(await pending, { status: 'unknown' });
});

test('device, connection, command size, pending and replay-history limits reject excess work', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  for (let i = 1; i < 8; i++) await access.approveDevice({ deviceID: `phone-${i}`, keyHash: 'b'.repeat(64) });
  await assert.rejects(access.approveDevice({ deviceID: 'one-too-many', keyHash: 'b'.repeat(64) }), { status: 429 });
  const handles = Array.from({ length: 48 }, () => access.connect(peer, 30000));
  assert.throws(() => access.connect(peer, 30000), { status: 429 });
  const handle = handles[0];
  await assert.rejects(access.dispatch(handle, command(access, { payload: Buffer.alloc(131073) }), assert.fail), { status: 400 });
  await assert.rejects(access.dispatch(handle, command(access, { id: 'not-a-uuid' }), assert.fail), { status: 400 });
  const releases = [];
  const pending = Array.from({ length: 8 }, () =>
    access.dispatch(handle, command(access), () => new Promise(resolve => releases.push(resolve))));
  await assert.rejects(access.dispatch(handle, command(access), assert.fail), { status: 429 });
  releases.forEach(resolve => resolve({ status: 'unknown' }));
  await Promise.all(pending);
  for (let i = 8; i < 256; i++) await access.dispatch(handle, command(access), () => ({ status: 'received' }));
  await assert.rejects(access.dispatch(handle, command(access), assert.fail), { status: 429 });
});

test('malformed device keys and stored policies are rejected rather than coerced or reset', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  for (const keyHash of [[peer.keyHash], {}, null, 123, 'A'.repeat(64)])
    await assert.rejects(access.approveDevice({ deviceID: 'bad', keyHash }), { status: 400 });
  for (const state of [
    { version: 2, owner, devices: [] },
    { version: 1, owner, devices: [device, device] },
    { version: 1, owner, devices: [{ ...device, keyHash: [peer.keyHash] }] }
  ]) {
    await assert.rejects(RemoteAccess.open({ owner, store: { read: async () => state } }), { status: 503 });
  }
});

test('key replacement invalidates old authority and lifetime timer aborts idle channels', async t => {
  const { access } = await fixture(); t.after(() => access.disable());
  const old = access.connect(peer, 30000);
  await access.approveDevice({ ...device, keyHash: 'b'.repeat(64) });
  assert.equal(old.signal.aborted, true);
  assert.throws(() => access.connect(peer, 30000), { status: 403 });
  const next = access.connect({ ...peer, keyHash: 'b'.repeat(64) }, 10);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(next.signal.aborted, true);
  assert.throws(() => access.authorize(next), { status: 403 });
});

test('owner input is captured before asynchronous loading and deadline rechecked before dispatch', async t => {
  const supplied = { ...owner };
  let reads = 0;
  const opening = RemoteAccess.open({ owner: supplied, store: memoryStore(), now: () => ++reads >= 5 ? 1030 : 1000 });
  supplied.subject = 'changed-account';
  const access = await opening; t.after(() => access.disable());
  await access.approveDevice(device);
  access.enable();
  const handle = access.connect(peer, 30);
  await assert.rejects(access.dispatch(handle, command(access), () => assert.fail('Expired command dispatched')), { status: 403 });
});
