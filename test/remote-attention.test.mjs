import test from 'node:test';
import assert from 'node:assert/strict';
import { RemoteActions } from '../src/remote-actions.mjs';
import { permission } from './fixtures.mjs';
import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { RemoteAccess } from '../src/remote-access.mjs';

const current = { sessionID: 'session-1', requestID: 'request-1',
  sessionName: 'Website release', requestTitle: 'Open the release preview?' };
const projection = (changes = {}) => ({ version: 1, epoch: '11111111-1111-4111-8111-111111111111',
  revision: 1, current, additionalCount: 2, ...changes });
const device = { id: 'synthetic-phone', name: 'Synthetic' };
const snapshot = (attention, requests = [permission()]) =>
  ({ type: 'snapshot', requests, total: requests.length, ...(attention === undefined ? {} : { attention }) });

test('canonical projection survives observation loss, sending, selection and explicit empty', async t => {
  const emitted = [];
  const actions = new RemoteActions({ emit: e => emitted.push(e), devices: () => [device] });
  t.after(() => actions.close());
  for (const [attention, rows] of [
    [projection(), [permission()]],
    [projection(), [{ ...permission(), sending: true }]],
    [projection({ additionalCount: 0, revision: 2 }), []],
    [projection({ current: { ...current, requestID: 'second' }, revision: 3 }), []],
    [projection({ current: null, additionalCount: 0, revision: 4 }), []]
  ]) {
    actions.command(snapshot(attention, rows));
    assert.deepEqual((await actions.request('state', {}, device)).data.attention, attention);
  }
  assert.deepEqual(emitted, [], 'Display projection never dispatches a reply');
});

test('private projection expires with native freshness and is not retained after close', async t => {
  let now = 0;
  const actions = new RemoteActions({ emit() {}, devices: () => [device], now: () => now });
  t.after(() => actions.close());
  actions.command(snapshot(projection()));
  assert.deepEqual((await actions.request('state', {}, device)).data.attention, projection());
  now = 12000;
  const stale = (await actions.request('state', {}, device)).data;
  assert.equal(stale.connected, false);
  assert.equal(stale.attention, undefined);
  actions.close();
  assert.equal((await actions.request('state', {}, device)).data.attention, undefined);
});

test('unsupported or malformed optional metadata is unknown without breaking legacy request authority', async t => {
  const actions = new RemoteActions({ emit() {}, devices: () => [device] });
  t.after(() => actions.close());
  for (const invalid of [undefined, null, {}, projection({ version: 2 }),
    projection({ revision: 0 }), projection({ revision: '1' }),
    projection({ epoch: 'not-an-epoch' }), projection({ additionalCount: 257 }),
    projection({ current: null }), projection({ current: { ...current, sessionID: 'x'.repeat(129) } }),
    projection({ current: { ...current, requestID: 'bad\0id' } }),
    projection({ current: { ...current, requestTitle: 'x'.repeat(301) } }),
    projection({ current: { ...current, sessionName: 'x'.repeat(257) } })]) {
    actions.command(snapshot(projection()));
    actions.command(snapshot(invalid));
    const state = (await actions.request('state', {}, device)).data;
    assert.equal(state.attention, undefined);
    assert.equal(state.connected, true);
    assert.equal(state.requests[0].ticket, 'ticket-1');
  }
});

test('projection contains only its bounded display allowlist, not native private extras', async t => {
  const actions = new RemoteActions({ emit() {}, devices: () => [device] });
  t.after(() => actions.close());
  actions.command(snapshot({ ...projection(), secret: 'not projected',
    current: { ...current, answers: ['not projected'], ticket: 'not projected' } }));
  assert.deepEqual((await actions.request('state', {}, device)).data.attention, projection());
});

test('revoked authenticated channel cannot read private projection and push stays generic', async t => {
  const owner = { issuer: 'https://synthetic.invalid', subject: 'synthetic', macID: 'synthetic' };
  const peer = { ...owner, deviceID: device.id, keyHash: 'a'.repeat(64) };
  const generic = [];
  let saved = null, reads = 0;
  const access = await RemoteAccess.open({ owner, now: () => 0,
    store: { read: async () => saved, write: async value => { saved = value; } } });
  await access.approveDevice({ deviceID: peer.deviceID, keyHash: peer.keyHash });
  access.enable();
  const handle = access.connect(peer, 30000);
  const actions = new RemoteActions({ emit() {}, devices: () => [device], attention: (...args) => generic.push(args) });
  t.after(() => { actions.close(); access.disable(); });
  actions.command(snapshot(projection()));
  const read = () => access.dispatch(handle, { id: randomUUID(), epoch: access.epoch,
    payload: Buffer.from(JSON.stringify({ path: 'state', data: {} })) }, bytes => {
    reads++;
    const request = JSON.parse(bytes);
    return actions.request(request.path, request.data, device);
  });
  assert.deepEqual((await read()).data.attention, projection());
  assert.deepEqual(generic, [[]], 'Generic attention callback receives no projection text');
  access.disable();
  await assert.rejects(read());
  assert.equal(reads, 1, 'Retired channel cannot reach private state projection');
});

test('real synthetic Swift snapshot passes through encrypted-state projection', {
  skip: !process.env.NOTIFY_ATTENTION_FIXTURE
}, async t => {
  const native = JSON.parse(await readFile(process.env.NOTIFY_ATTENTION_FIXTURE, 'utf8'));
  const actions = new RemoteActions({ emit() { assert.fail('Projection must not dispatch'); }, devices: () => [device] });
  t.after(() => actions.close());
  actions.command(native);
  const state = (await actions.request('state', {}, device)).data;
  assert.deepEqual(state.attention, native.attention);
  assert.equal(state.attention.current.requestID, 'first');
  assert.equal(state.attention.additionalCount, 2);
  assert.equal(state.requests.length, 3);
  if (process.env.NOTIFY_ATTENTION_STATE_FIXTURE)
    await writeFile(process.env.NOTIFY_ATTENTION_STATE_FIXTURE, JSON.stringify(state));
});
