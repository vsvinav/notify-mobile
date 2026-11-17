import test from 'node:test';
import assert from 'node:assert/strict';
import { permission } from './fixtures.mjs';
import { RemoteActions } from '../src/remote-actions.mjs';

test('attention observes only new validated waiting requests, not snapshot polling or replies', () => {
  let attention = 0;
  const actions = new RemoteActions({ emit() {}, devices: () => [], attention: () => attention++ });
  const item = permission();
  const snapshot = requests => ({ type: 'snapshot', total: requests.length, requests });
  actions.command(snapshot([item]));
  actions.command(snapshot([item]));
  actions.command(snapshot([{ ...item, sending: true }]));
  actions.command(snapshot([item]));
  assert.equal(attention, 1);
  actions.close();
  actions.command(snapshot([item]));
  assert.equal(attention, 1, 'transient disconnect must not replay attention');
  actions.command(snapshot([{ ...item, ticket: 'new-ticket' }]));
  assert.equal(attention, 2);
  assert.throws(() => actions.command({ type: 'snapshot', requests: [{}] }));
  assert.equal(attention, 2);
  actions.close();
});

test('remote replies wait for native ACK and cannot be resent in the same generation', async () => {
  const events = [];
  const device = { id: 'phone', name: 'Phone', expires: Date.now() + 30000 };
  const actions = new RemoteActions({ emit: event => events.push(event), devices: () => [device] });
  const input = { sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {} };
  actions.command({ type: 'snapshot', total: 1, requests: [permission()] });
  const reply = actions.request('reply', input, device);
  assert.equal(events.at(-1).type, 'reply');
  await assert.rejects(actions.request('reply', input, device), /already|awaiting/i);
  actions.command({ type: 'result', id: events.at(-1).id, ok: true });
  assert.deepEqual(await reply, { status: 200, data: { ok: true } });
  await assert.rejects(actions.request('reply', input, device), /already|awaiting/i);
  actions.close();
});

test('channel loss makes pending replies uncertain and stale snapshots cannot authorize', async () => {
  let clock = 0;
  const device = { id: 'phone', name: 'Phone', expires: 30000 };
  const actions = new RemoteActions({ emit() {}, now: () => clock, devices: () => [device] });
  actions.command({ type: 'snapshot', total: 1, requests: [permission()] });
  const input = { sessionID: 'session-1', requestID: 'request-1', ticket: 'ticket-1', decision: 'deny', answers: {} };
  const reply = actions.request('reply', input, device);
  actions.disconnect(device.id);
  assert.match((await reply).data.error, /unknown|uncertain/i);
  clock = 12001;
  assert.equal((await actions.request('state', {}, device)).data.connected, false);
  actions.close();
});
