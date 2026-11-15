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
