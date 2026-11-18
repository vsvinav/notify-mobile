import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, pair } from './fixtures.mjs';
import { Workspace } from '../src/workspace.mjs';
import { EventEmitter } from 'node:events';
import { readFile } from 'node:fs/promises';

const pause = () => new Promise(resolve => setTimeout(resolve, 40));
const session = (id = 'one', ticket = 'generation-1') => ({
  id, ticket, name: id, project: 'project', agent: 'copilot', color: '#123456',
  state: 'working', connected: true, capabilities: { steering: true, subagentChat: true, subagentStop: true },
  runningCount: 0, idleCount: 1
});
const overview = (...sessions) => ({ type: 'workspace', sessions, total: sessions.length, truncated: false });
const detail = (id = 'one', ticket = 'generation-1') => ({
  type: 'workspace_detail', sessionID: id, ticket, team: {
    agents: [{ id: 'child', name: 'Child', task: 'Task', status: 'idle', parentKnown: true }],
    runningCount: 0, idleCount: 1, truncated: false
  }, activity: [], controls: [], truncated: false
});
const control = (extra = {}) => ({ id: randomUUID(), sessionID: 'one', ticket: 'generation-1', action: 'queue', text: 'exact text', ...extra });
const managedSession = () => ({ ...session(), managementTicket: 'management-1',
  capabilities: { ...session().capabilities, subagentCreate: true, subagentRemove: true, subagentCleanup: true },
  subagentTypes: ['reviewer'], subagentModels: ['live-model'] });
const creationControl = (extra = {}) => control({ action: 'create_subagent', text: '', managementTicket: 'management-1',
  creation: { name: 'Reviewer', agentType: 'reviewer', prompt: '  Review exactly\n', model: 'live-model' }, ...extra });

test('immediate Send requires advertised main support and preserves submitted ACK identity', async () => {
  const { w, devices, events } = memoryWorkspace();
  await assert.rejects(w.control(control({ action: 'send' }), devices[0]), { status: 409 });
  const capable = { ...session(), capabilities: { ...session().capabilities, steeringImmediate: true } };
  w.command(overview(capable));
  assert.equal(w.payload(devices[0].id).steeringImmediateControl, true);
  for (const extra of [{ agentID: 'child' }, { ticket: 'stale' }]) {
    await assert.rejects(w.control(control({ action: 'send', ...extra }), devices[0]), { status: 409 });
  }
  const input = control({ action: 'send' });
  const pending = w.control(input, devices[0]);
  const sent = events.at(-1);
  assert.equal(sent.action, 'send');
  w.command({ type: 'control_result', id: sent.id, ok: true, commandID: 'send-receipt',
    status: 'submitted', detail: 'Waiting for next model request' });
  assert.equal((await pending).data.status, 'submitted');
  assert.equal((await w.control(input, devices[0])).data.commandID, 'send-receipt');
  assert.equal(events.at(-1), sent, 'Replaying a submitted command must not emit another send');
  await assert.rejects(w.control({ ...input, action: 'queue' }, devices[0]), { status: 409 });
  await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  const saved = detail();
  saved.controls.push({ id: 'send-receipt', action: 'send', message: input.text, status: 'submitted',
    detail: 'Waiting for next model request', createdAt: '2026-01-01T00:00:00Z' });
  w.command(saved);
  assert.equal(w.payload(devices[0].id).detail.controls[0].status, 'submitted');
  for (const [action, status] of [['send', 'queued'], ['queue', 'submitted'], ['interrupt', 'submitted']]) {
    const wrong = w.control(control({ action }), devices[0]);
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'wrong', status, detail: '' });
    assert.equal((await wrong).data.status, 'unknown', 'ACK mode cannot change the requested delivery mode');
  }
  w.command(overview(session()));
  await assert.rejects(w.control(control({ action: 'send' }), devices[0]), { status: 409 });
});

test('phone management dispatch uses live catalogs and action-specific runtime ACK, not chat acceptance', async t => {
  const f = await fixture(); t.after(f.close);
  const auth = await pair(f);
  await f.app.command(overview(managedSession()));
  const snapshot = await f.call('/api/workspace', { sessionID: 'one' }, auth);
  assert.equal(snapshot.data.subagentManagementControl, true);
  await f.app.command(detail());
  for (const [action, status, extra] of [
    ['create_subagent', 'created', { creation: creationControl().creation }],
    ['stop_idle_subagents', 'cleaned', {}],
  ]) {
    const input = control({ action, text: '', managementTicket: 'management-1', ...extra });
    const pending = f.call('/api/control', input, auth);
    await pause();
    const sent = f.events.findLast(e => e.type === 'control');
    assert.equal(sent.action, action);
    assert.equal(sent.agentID, undefined);
    assert.deepEqual(sent.creation, extra.creation);
    assert.equal((await f.call('/api/control', { ...input, sessionID: 'other' }, auth)).status, 409);
    await f.app.command({ type: 'control_result', id: sent.id, ok: true, commandID: 'receipt', status,
      detail: 'Stopped 2; skipped 1; failed 0; uncertain 0' });
    assert.equal((await pending).data.status, status);
    assert.equal((await f.call('/api/control', input, auth)).data.status, status);
  }
  assert.equal((await f.call('/api/control', control({ action: 'remove_subagent', text: '',
    managementTicket: 'management-1', agentID: 'child' }), auth)).data.status, 'failed');
  const ended = detail(); ended.team.agents[0].status = 'completed'; ended.team.idleCount = 0;
  await f.app.command(ended);
  const remove = control({ action: 'remove_subagent', text: '', managementTicket: 'management-1', agentID: 'child' });
  const pending = f.call('/api/control', remove, auth); await pause();
  const sent = f.events.findLast(e => e.type === 'control');
  assert.equal(sent.agentID, 'child');
  await f.app.command({ type: 'control_result', id: sent.id, ok: true, commandID: 'receipt', status: 'removed', detail: 'Removed Child' });
  assert.equal((await pending).data.status, 'removed');
});

test('management rejects stale catalogs, invalid fields and unknown creation never replays', async () => {
  const { w, devices, events } = memoryWorkspace();
  assert.equal((await w.control(creationControl(), devices[0])).data.status, 'failed');
  w.command(overview(managedSession()));
  for (const extra of [
    { creation: { ...creationControl().creation, model: 'missing' } },
    { creation: { ...creationControl().creation, agentType: 'missing' } },
    { managementTicket: 'old' },
  ]) assert.equal((await w.control(creationControl(extra), devices[0])).data.status, 'failed');
  for (const extra of [
    { agentID: 'child' }, { text: 'main prompt' }, { creation: { ...creationControl().creation, name: 'x'.repeat(161) } },
    { creation: { ...creationControl().creation, extra: true } }, { enabled: false },
    { creation: { ...creationControl().creation, prompt: '😀'.repeat(8001) } },
  ]) await assert.rejects(w.control(creationControl(extra), devices[0]), { status: 400 });
  const input = creationControl();
  const unknown = await w.control(input, devices[0]);
  assert.equal(unknown.data.status, 'unknown');
  const sent = events.length;
  assert.equal((await w.control(input, devices[0])).data.status, 'unknown');
  assert.equal(events.length, sent);
  await assert.rejects(w.control({ ...input, creation: { ...input.creation, model: undefined } }, devices[0]), { status: 409 });
  for (const status of ['queued', 'received', 'stopped', 'removed', 'cleaned']) {
    const pending = w.control(creationControl(), devices[0]);
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'cmd', status, detail: '' });
    assert.equal((await pending).data.status, 'unknown');
  }
  w.command(overview({ ...managedSession(), subagentModels: [] }));
  const fallback = w.control(creationControl({ creation: { name: 'Default', agentType: 'reviewer', prompt: 'Review' } }), devices[0]);
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'cmd', status: 'created', detail: 'Created' });
  assert.equal((await fallback).data.status, 'created');
});

test('native uncertain cleanup retains its actual partial counts in a correlated response', async () => {
  const { w, devices, events } = memoryWorkspace();
  w.command(overview(managedSession()));
  await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  w.command(detail());
  const pending = w.control(control({ action: 'stop_idle_subagents', text: '', managementTicket: 'management-1' }), devices[0]);
  w.command({ type: 'control_result', id: events.at(-1).id, ok: false, commandID: 'cleanup-receipt',
    status: 'unknown', detail: 'Cancelled 2; skipped 3; failed 1; uncertain 1', error: 'Some outcomes are uncertain.' });
  const result = await pending;
  assert.equal(result.status, 200, 'The caller must be able to inspect an actual partial runtime result');
  assert.equal(result.data.status, 'unknown');
  assert.equal(result.data.ok, false);
  assert.equal(result.data.detail, 'Cancelled 2; skipped 3; failed 1; uncertain 1');
});

test('management admission rejection preserves an actionable failed result without reserving or replaying a command', async () => {
  const { w, devices, events, advance } = memoryWorkspace();
  w.command(overview(managedSession()));
  const input = creationControl();
  advance(12000);
  const rejected = await w.control(input, devices[0]);
  assert.equal(rejected.data.status, 'failed');
  assert.equal(rejected.data.ok, false);
  assert.equal(w.controls.size, 0);
  assert.equal(events.filter(e => e.type === 'control').length, 0);
  w.command(overview(managedSession()));
  const freshExplicitCommand = creationControl();
  const pending = w.control(freshExplicitCommand, devices[0]);
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'new', status: 'created', detail: 'Created' });
  assert.equal((await pending).data.status, 'created');
});

test('workspace authenticated long poll, exact selection and ticket isolation', async t => {
  const f = await fixture(); t.after(f.close);
  assert.equal((await f.call('/api/workspace', { sessionID: null })).status, 401);
  const a = await pair(f), b = await pair(f);
  assert.equal((await f.call('/api/workspace', { sessionID: null }, a)).data.connected, false);
  await f.app.command(overview(session(), session('two')));
  const first = await f.call('/api/workspace', { sessionID: 'one' }, a);
  assert.equal(first.data.sessions.length, 2);
  assert.deepEqual(f.events.findLast(e => e.type === 'workspace_watch').sessionIDs, ['one']);
  let settled = false;
  const waiting = f.call('/api/workspace', { sessionID: 'one', revision: first.data.revision }, a).then(r => { settled = true; return r; });
  await pause(); assert.equal(settled, false);
  await f.app.command(detail());
  assert.equal((await waiting).data.detail.sessionID, 'one');
  const other = await f.call('/api/workspace', { sessionID: 'two' }, b);
  assert.equal(other.data.detail, null);
  assert.deepEqual(f.events.findLast(e => e.type === 'workspace_watch').sessionIDs.sort(), ['one', 'two']);
  await f.app.command(overview(session('one', 'new'), session('two')));
  assert.equal((await f.call('/api/workspace', { sessionID: 'one' }, a)).data.detail, null);
  await f.app.command({ type: 'revoke', id: a.id });
  assert.deepEqual(f.events.findLast(e => e.type === 'workspace_watch').sessionIDs, ['two']);
});

test('controls wait for exact native result, deduplicate full payload, preserve queued status', async t => {
  const f = await fixture(); t.after(f.close);
  const auth = await pair(f);
  await f.app.command(overview(session()));
  const input = control();
  let settled = false;
  const pending = f.call('/api/control', input, auth).then(r => { settled = true; return r; });
  await pause(); assert.equal(settled, false);
  const sent = f.events.findLast(e => e.type === 'control');
  assert.ok(sent); assert.notEqual(sent.id, input.id);
  assert.equal((await f.call('/api/control', { ...input, text: 'changed' }, auth)).status, 409);
  assert.equal((await f.call('/api/control', input, auth)).status, 409);
  await f.app.command({ type: 'control_result', id: 'wrong', ok: true, commandID: 'cmd', status: 'received', detail: 'Received' });
  assert.equal(settled, false);
  await f.app.command({ type: 'control_result', id: sent.id, ok: true, commandID: 'cmd', status: 'queued', detail: 'Queued, not consumed' });
  assert.deepEqual((await pending).data, { ok: true, commandID: 'cmd', status: 'queued', detail: 'Queued, not consumed' });
  assert.equal((await f.call('/api/control', input, auth)).data.status, 'queued');
  assert.equal(f.events.filter(e => e.type === 'control').length, 1);
  assert.doesNotMatch(await readFile(`${f.directory}/state.json`, 'utf8'), /exact text|generation-1|cmd/);
});

function memoryWorkspace() {
  let clock = Date.now();
  const events = [], devices = [{ id: 'phone', expires: clock + 900000 }];
  const w = new Workspace({ emit: e => events.push(e), now: () => clock, ackTimeout: 40, devices: () => devices,
    fail: (status, message) => { throw Object.assign(new Error(message), { status }); } });
  w.command(overview(session()));
  return { w, events, devices, advance: value => { clock += value; } };
}

const offEpoch = n => `00000000-0000-8000-8000-${String(n).padStart(12, '0')}`;
const policySession = (enabled = false, policyTicket = 'policy-1', offTicket = offEpoch(1)) => ({
  ...session(), capabilities: { ...session().capabilities, steering: false, dangerousAutoYes: true },
  dangerousAutoYes: { ticket: policyTicket, offTicket, revision: policyTicket === 'policy-1' ? 1 : 2, enabled, normalEnabled: false }
});
const policyControl = (extra = {}) => control({ action: 'dangerous_auto_yes', text: '', enabled: true, policyTicket: 'policy-1',
  offTicket: offEpoch(1),
  ...(extra.enabled === false ? { id: extra.offTicket ?? offEpoch(1), offTicket: offEpoch(1) } : {}), ...extra });

test('dangerous policy uses native capability, exact policy revision and full payload dedup without steering', async () => {
  const { w, devices, events } = memoryWorkspace();
  w.command(overview(policySession()));
  const input = policyControl();
  const pending = w.control(input, devices[0]);
  assert.equal(events.at(-1).action, 'dangerous_auto_yes');
  await assert.rejects(w.control({ ...input, enabled: false, offTicket: offEpoch(1) }, devices[0]), { status: 400 });
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'policy-command', status: 'applied',
    detail: 'Enabled', dangerousAutoYes: policySession(true, 'policy-2').dangerousAutoYes });
  assert.equal((await pending).data.dangerousAutoYes.enabled, true);
  assert.equal((await w.control(input, devices[0])).data.status, 'applied');
  w.command(overview(policySession(false, 'newer-off')));
  await assert.rejects(w.control(policyControl(), devices[0]), { status: 409 });
  await assert.rejects(w.control(policyControl({ policyTicket: 'newer-off', agentID: 'child' }), devices[0]), { status: 400 });
  await assert.rejects(w.control(policyControl({ policyTicket: 'newer-off', sessionID: 'other' }), devices[0]), { status: 409 });
});

test('dangerous policy never fabricates legacy support or replays uncertain controls', async () => {
  const { w, devices, events } = memoryWorkspace();
  assert.equal(w.payload(devices[0].id).dangerousAutoYesControl, true, 'New helper explicitly advertises its typed policy dispatcher');
  await assert.rejects(w.control(policyControl(), devices[0]), { status: 409 });
  w.command(overview(policySession()));
  const input = policyControl();
  const pending = w.control(input, devices[0]);
  w.invalidate('Phone disconnected');
  assert.equal((await pending).data.status, 'unknown');
  w.command(overview(policySession()));
  const count = events.length;
  assert.equal((await w.control(input, devices[0])).data.status, 'unknown');
  assert.equal(events.length, count);
});

test('dangerous ACK must match requested policy, not queued steering or invented Off', async () => {
  for (const ack of [
    { status: 'queued' }, { status: 'applied' },
    { status: 'applied', dangerousAutoYes: { ...policySession(true, 'different').dangerousAutoYes, revision: 1 } },
    { status: 'applied', dangerousAutoYes: policySession(false, 'new').dangerousAutoYes }
  ]) {
    const { w, devices, events } = memoryWorkspace();
    w.command(overview(policySession()));
    const pending = w.control(policyControl(), devices[0]);
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'cmd', detail: '', ...ack });
    assert.equal((await pending).data.status, 'unknown');
  }
});

test('policy ACK refreshes exact policy without extending the native lease; failed Off is authoritative', async () => {
  const { w, devices, events, advance } = memoryWorkspace();
  w.command(overview(policySession()));
  const enabling = w.control(policyControl(), devices[0]);
  const on = { ...policySession(true, 'on').dangerousAutoYes, revision: 2 };
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'on', status: 'applied', detail: '', dangerousAutoYes: on });
  await enabling;
  assert.deepEqual(w.sessions[0].dangerousAutoYes, on);
  const disabling = w.control(policyControl({ enabled: false, policyTicket: 'on' }), devices[0]);
  const off = { ...on, ticket: 'off', offTicket: offEpoch(2), revision: 3, enabled: false };
  w.command({ type: 'control_result', id: events.at(-1).id, ok: false, commandID: 'off', status: 'failed',
    detail: 'Off', error: 'Off, but audit could not be saved', dangerousAutoYes: off });
  const result = await disabling;
  assert.equal(result.status, 200);
  assert.equal(result.data.ok, false);
  assert.deepEqual(result.data.dangerousAutoYes, off);
  w.command(overview(policySession(true, 'older')));
  assert.deepEqual(w.sessions[0].dangerousAutoYes, off, 'Older snapshot cannot undo authoritative Off');
  advance(12000);
  await assert.rejects(w.control(policyControl({ policyTicket: 'off' }), devices[0]), { status: 503 });
});

test('policy payload and advertised state are strict and cannot bypass ordinary controls', async () => {
  const { w, devices } = memoryWorkspace();
  w.command(overview(policySession()));
  for (const extra of [{ enabled: 'true' }, { enabled: undefined }, { text: 'extra' }, { policyTicket: '' },
    { action: 'queue', text: 'message' }, { agentID: 'child' }])
    await assert.rejects(w.control(policyControl(extra), devices[0]), { status: 400 });
  for (const value of [
    { ...policySession(), dangerousAutoYes: undefined },
    { ...policySession(), dangerousAutoYes: { ...policySession().dangerousAutoYes, enabled: 'false' } },
    { ...policySession(), dangerousAutoYes: { ...policySession().dangerousAutoYes, enabled: true, normalEnabled: true } }
  ]) assert.throws(() => w.command(overview(value)), /Invalid workspace/);
});

test('explicit Off supersedes an in-flight enable even if its reviewed policy ticket is older', async () => {
  const { w, devices, events } = memoryWorkspace();
  w.command(overview(policySession()));
  const on = w.control(policyControl(), devices[0]);
  const onID = events.at(-1).id;
  w.command({ type: 'control_result', id: onID, ok: true, commandID: 'on', status: 'applied', detail: '',
    dangerousAutoYes: policySession(true, 'on').dangerousAutoYes });
  await on;
  const off = w.control(policyControl({ enabled: false }), devices[0]);
  assert.equal(events.at(-1).enabled, false, 'Off must not wait for a watch refresh after On');
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: 'off', status: 'applied', detail: '',
    dangerousAutoYes: { ...policySession(false, 'off', offEpoch(2)).dangerousAutoYes, revision: 3 } });
  assert.equal((await off).data.dangerousAutoYes.enabled, false);
  await assert.rejects(w.control(policyControl(), devices[0]), { status: 409 });
});

test('bounded UUID safety history retains uncertain records until their generation is invalid', async () => {
  const { w, events, devices } = memoryWorkspace();
  const timedOut = control();
  assert.equal((await w.control(timedOut, devices[0])).status, 504);
  for (let i = 1; i < 256; i++) {
    const result = w.control(control(), devices[0]);
    const sent = events.at(-1);
    w.command({ type: 'control_result', id: sent.id, ok: true, commandID: randomUUID(), status: 'queued', detail: 'Queued' });
    assert.equal((await result).status, 200);
  }
  await assert.rejects(w.control(control(), devices[0]), { status: 429 });
  assert.equal((await w.control(timedOut, devices[0])).status, 504);
  assert.equal(w.controls.size, 256);
  w.command(overview(session('one', 'new-generation')));
  assert.equal(w.controls.size, 0);
  await assert.rejects(w.control(timedOut, devices[0]), { status: 409 });
});

test('urgent Off remains available after 255 ordinary controls and the enabling control fill history', async () => {
  const { w, devices, events } = memoryWorkspace();
  const supported = policySession();
  supported.capabilities.steering = true;
  w.command(overview(supported));
  for (let i = 0; i < 255; i++) {
    const pending = w.control(control(), devices[0]);
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: randomUUID(), status: 'queued', detail: '' });
    assert.equal((await pending).status, 200);
  }
  const enabling = w.control(policyControl(), devices[0]);
  w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: randomUUID(), status: 'applied', detail: '',
    dangerousAutoYes: policySession(true, 'on').dangerousAutoYes });
  assert.equal((await enabling).status, 200);
  assert.equal(w.controls.size, 256);
  const before = events.length;
  const disabling = w.control(policyControl({ enabled: false, policyTicket: 'on' }), devices[0])
    .catch(error => ({ status: error.status }));
  if (events.length > before) {
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: randomUUID(), status: 'applied', detail: '',
      dangerousAutoYes: { ...policySession(false, 'off', offEpoch(2)).dangerousAutoYes, revision: 3 } });
  }
  assert.equal((await disabling).status, 200, 'Full ordinary history must not strand enabled policy');
  const firstOff = policyControl({ enabled: false, policyTicket: 'on' });
  for (let cycle = 0; cycle < 300; cycle++) {
    const live = { ...supported, dangerousAutoYes: { ...supported.dangerousAutoYes,
      enabled: true, ticket: `manual-on-${cycle}`, offTicket: offEpoch(3 + cycle * 2), revision: 4 + cycle * 2 } };
    w.command(overview(live));
    const input = policyControl({ enabled: false, policyTicket: live.dangerousAutoYes.ticket, offTicket: live.dangerousAutoYes.offTicket });
    const pending = w.control(input, devices[0]);
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: randomUUID(), status: 'applied', detail: '',
      dangerousAutoYes: { ...live.dangerousAutoYes, enabled: false, ticket: `off-${cycle}`,
        offTicket: offEpoch(4 + cycle * 2), revision: live.dangerousAutoYes.revision + 1 } });
    assert.equal((await pending).status, 200);
    assert.equal(w.controls.size, 256);
    assert.equal(w.offControls.size, 1, 'One retained Off record per session, not 300 extra UUID records');
    const beforeDuplicate = events.length;
    assert.equal((await w.control(input, devices[0])).status, 200);
    await assert.rejects(w.control({ ...input, policyTicket: 'changed-payload' }, devices[0]), { status: 409 });
    assert.equal(events.length, beforeDuplicate);
  }
  await assert.rejects(w.control(firstOff, devices[0]), { status: 409 }, 'Retired Off payload cannot replay');
  await assert.rejects(w.control(policyControl({ enabled: false, id: firstOff.id, offTicket: offEpoch(602) }), devices[0]), { status: 400 });
  await assert.rejects(w.control(control({ id: firstOff.id }), devices[0]), { status: 400 }, 'Retired Off UUID cannot change into an ordinary command');
  await assert.rejects(w.control(control(), devices[0]), { status: 429 }, 'Ordinary safety history is never evicted to make room for Off');
});

test('Off epoch slot retains uncertain dispatch and rejects reuse until native authority retires it', async () => {
  const { w, devices, events } = memoryWorkspace();
  w.command(overview(policySession(true)));
  const off = policyControl({ enabled: false });
  assert.equal((await w.control(off, devices[0])).status, 504);
  const count = events.length;
  assert.equal((await w.control(off, devices[0])).status, 504);
  await assert.rejects(w.control(policyControl({ enabled: false, id: randomUUID() }), devices[0]), { status: 400 });
  await assert.rejects(w.control(policyControl({ enabled: false, policyTicket: 'changed' }), devices[0]), { status: 409 });
  w.invalidate('Phone disconnected');
  w.command(overview(policySession(true)));
  assert.equal((await w.control(off, devices[0])).status, 504);
  assert.equal(events.length, count);
  assert.equal(w.offControls.size, 1);
});

test('dedicated Off still requires fresh exact session authority and native capability', async () => {
  const { w, devices, events, advance } = memoryWorkspace();
  const supported = policySession(true);
  w.command(overview(supported));
  for (const extra of [{ ticket: 'stale' }, { sessionID: 'other' }, { offTicket: offEpoch(2) }])
    await assert.rejects(w.control(policyControl({ enabled: false, ...extra }), devices[0]), { status: 409 });
  await assert.rejects(w.control(policyControl({ enabled: false, agentID: 'child' }), devices[0]), { status: 400 });
  w.command(overview({ ...supported, capabilities: { ...supported.capabilities, dangerousAutoYes: false } }));
  await assert.rejects(w.control(policyControl({ enabled: false }), devices[0]), { status: 409 });
  w.command(overview(supported));
  advance(12000);
  await assert.rejects(w.control(policyControl({ enabled: false }), devices[0]), { status: 503 });
  assert.equal(events.filter(e => e.type === 'control').length, 0);
  assert.equal(w.offControls.size, 0);
});

test('legacy policy clients cannot enable without knowing the bounded Off epoch', async () => {
  const { w, devices, events } = memoryWorkspace();
  w.command(overview(policySession()));
  const legacy = policyControl();
  delete legacy.offTicket;
  const result = w.control(legacy, devices[0]).catch(error => ({ status: error.status }));
  if (events.at(-1)?.type === 'control')
    w.command({ type: 'control_result', id: events.at(-1).id, ok: true, commandID: randomUUID(), status: 'applied', detail: '',
      dangerousAutoYes: policySession(true, 'on').dangerousAutoYes });
  assert.equal((await result).status, 400, 'An older client must not enable a mode it cannot turn off');
});

test('workspace read bounds and HTTP disconnect release; watched selections expire and revoked waiters fail', async () => {
  const { w, devices, events, advance } = memoryWorkspace();
  const first = await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  const response = new EventEmitter();
  const waiting = w.read({ sessionID: 'one', revision: first.data.revision }, devices[0], response);
  await assert.rejects(w.read({ sessionID: 'one', revision: first.data.revision }, devices[0], new EventEmitter()), { status: 409 });
  response.emit('close');
  assert.equal((await waiting).status, 499);
  assert.equal(w.waiters.size, 0);
  advance(30001); w.tick();
  assert.deepEqual(events.at(-1).sessionIDs, []);
  w.command(overview(session()));
  const renewed = await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  const pending = w.read({ sessionID: 'one', revision: renewed.data.revision }, devices[0], new EventEmitter());
  w.revoke(devices[0].id);
  assert.equal((await pending).status, 401);
});

test('selection change responds immediately even before details arrive', async () => {
  const { w, devices } = memoryWorkspace();
  const first = await w.read({ sessionID: null }, devices[0], new EventEmitter());
  let settled = false;
  const response = new EventEmitter();
  const next = w.read({ sessionID: 'one', revision: first.data.revision }, devices[0], response).then(r => { settled = true; return r; });
  await pause();
  response.emit('close');
  await next;
  assert.equal(settled, true);
  assert.equal((await next).status, 200);
});

test('a changed selection supersedes its device waiter before HTTP abort close is processed', async () => {
  const { w, devices } = memoryWorkspace();
  w.command(overview(session(), session('two')));
  const first = await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  const oldResponse = new EventEmitter();
  const oldRead = w.read({ sessionID: 'one', revision: first.data.revision }, devices[0], oldResponse);
  const next = await w.read({ sessionID: 'two', revision: first.data.revision }, devices[0], new EventEmitter());
  assert.equal(next.status, 200);
  assert.equal((await oldRead).status, 409);
  const newRead = w.read({ sessionID: 'two', revision: next.data.revision }, devices[0], new EventEmitter());
  oldResponse.emit('close');
  assert.equal(w.waiters.size, 1, 'Old HTTP close must not clear the new waiter');
  w.revoke(devices[0].id);
  await newRead;
});

test('event-driven workspace reads do not exhaust three-second Requests polling budget', async t => {
  const f = await fixture(); t.after(f.close);
  const auth = await pair(f);
  await f.app.command(overview(session()));
  for (let i = 0; i < 245; i++) {
    assert.equal((await f.call('/api/workspace', { sessionID: null }, auth)).status, 200, `Workspace update ${i}`);
    if (i % 10 === 0) assert.equal((await f.call('/api/state', {}, auth)).status, 200);
  }
});

test('malformed details and ended child fail closed; expiry while pending never succeeds', async () => {
  const { w, devices, advance, events } = memoryWorkspace();
  await w.read({ sessionID: 'one' }, devices[0], new EventEmitter());
  const ended = detail(); ended.team.agents[0].status = 'cancelled'; ended.team.idleCount = 0;
  w.command(ended);
  await assert.rejects(w.control(control({ agentID: 'child' }), devices[0]), { status: 409 });
  const invalid = detail(); invalid.team.agents[0].parentAgentID = 'child';
  assert.throws(() => w.command(invalid), /workspace/i);
  assert.equal(w.fresh(), false);
  w.command(overview(session()));
  const pending = w.control(control(), devices[0]);
  const sent = events.at(-1);
  devices[0].expires = Date.now() - 1;
  advance(1); w.tick();
  w.command({ type: 'control_result', id: sent.id, ok: true, commandID: 'real', status: 'received', detail: '' });
  assert.equal((await pending).status, 401);
});

test('controls reject stale, unsupported and missing child without fallback; timeout and revoke are uncertain', async t => {
  const f = await fixture({ ackTimeout: 150 }); t.after(f.close);
  const auth = await pair(f);
  await f.app.command(overview(session()));
  assert.equal((await f.call('/api/control', control({ ticket: 'old' }), auth)).status, 409);
  assert.equal((await f.call('/api/control', control({ agentID: 'missing' }), auth)).status, 409);
  await f.call('/api/workspace', { sessionID: 'one' }, auth);
  await f.app.command(detail());
  assert.equal((await f.call('/api/control', control({ agentID: 'child', action: 'interrupt' }), auth)).status, 409);
  const input = control({ agentID: 'child' });
  assert.equal((await f.call('/api/control', input, auth)).status, 504);
  assert.equal((await f.call('/api/control', input, auth)).status, 504);
  const pending = f.call('/api/control', control(), auth);
  await pause();
  await f.app.command({ type: 'revoke', id: auth.id });
  assert.equal((await pending).status, 401);
  assert.equal((await f.call('/api/control', control(), auth)).status, 401);
});

test('invalid workspace disables reads/actions and lease expiry clears details', async t => {
  let clock = Date.now();
  const f = await fixture({ now: () => clock }); t.after(f.close);
  const auth = await pair(f);
  await f.app.command(overview(session()));
  await assert.rejects(f.app.command(overview({ ...session(), capabilities: {} })), /workspace/i);
  assert.equal((await f.call('/api/workspace', { sessionID: null }, auth)).data.connected, false);
  await f.app.command(overview(session()));
  clock += 12001;
  assert.equal((await f.call('/api/control', control(), auth)).status, 503);
  assert.equal((await f.call('/api/workspace', { sessionID: null }, auth)).data.connected, false);
});

test('old native Requests remain usable without unsupported workspace_watch commands', async t => {
  const f = await fixture(); t.after(f.close);
  const auth = await pair(f);
  await f.app.command({ type: 'snapshot', requests: [], total: 0 });
  assert.equal((await f.call('/api/workspace', { sessionID: null }, auth)).data.connected, false);
  await pause();
  assert.equal(f.events.some(e => e.type === 'workspace_watch'), false);
  assert.equal((await f.call('/api/state', {}, auth)).data.connected, true);
});
