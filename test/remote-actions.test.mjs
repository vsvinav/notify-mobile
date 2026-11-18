import test from 'node:test';
import assert from 'node:assert/strict';
import { permission } from './fixtures.mjs';
import { RemoteActions } from '../src/remote-actions.mjs';
import { randomUUID } from 'node:crypto';
import { RemoteAccess } from '../src/remote-access.mjs';

async function linkedPolicy(t, options = {}) {
  let now = 0;
  const owner = { issuer: 'https://synthetic.invalid', subject: 'synthetic', macID: 'synthetic' };
  const peer = { ...owner, deviceID: 'phone', keyHash: 'a'.repeat(64) };
  let saved = null;
  const access = await RemoteAccess.open({ owner, now: () => now,
    store: { read: async () => saved, write: async value => { saved = value; } } });
  await access.approveDevice({ deviceID: peer.deviceID, keyHash: peer.keyHash });
  access.enable();
  const handle = access.connect(peer, 30000);
  const device = { id: peer.deviceID, name: 'Synthetic', expires: 30000 };
  const events = [];
  const actions = new RemoteActions({ emit: event => events.push(event), devices: () => [device], now: () => now, ...options });
  t.after(() => { actions.close(); access.disable(); });
  const token = () => randomUUID().replace(/^(.{14})./, '$18');
  let policy = { ticket: randomUUID(), offTicket: token(), revision: 1, enabled: false, normalEnabled: false };
  function snapshot() {
    actions.command({ type: 'workspace', total: 1, truncated: false, sessions: [{
      id: 's', ticket: 't', name: 'Synthetic', project: '', agent: 'copilot', color: '#123456', state: 'working',
      connected: true, runningCount: 0, idleCount: 0,
      capabilities: { steering: true, subagentChat: false, subagentStop: false, dangerousAutoYes: true, subagentCreate: true },
      managementTicket: 'm', subagentTypes: ['reviewer'], subagentModels: [],
      dangerousAutoYes: { ...policy }
    }] });
  }

  snapshot();
  const control = (enabled) => enabled === undefined
    ? { id: randomUUID(), sessionID: 's', ticket: 't', action: 'queue', text: 'synthetic' }
    : { id: enabled ? randomUUID() : policy.offTicket, sessionID: 's', ticket: 't',
      action: 'dangerous_auto_yes', text: '', enabled, policyTicket: policy.ticket, offTicket: policy.offTicket };
  const send = input => access.dispatch(handle, {
    id: input.id, epoch: access.epoch, payload: Buffer.from(JSON.stringify({ path: 'control', data: input }))
  }, bytes => {
    const value = JSON.parse(bytes);
    return actions.request(value.path, value.data, device, handle.signal);
  });
  function ack(event = events.at(-1)) {
    if (event.action === 'dangerous_auto_yes') policy = { ...policy, enabled: event.enabled,
      ticket: randomUUID(), revision: policy.revision + 1, offTicket: event.enabled ? policy.offTicket : token() };
    actions.command({ type: 'control_result', id: event.id, commandID: randomUUID(), ok: true,
      status: event.action === 'dangerous_auto_yes' ? 'applied' : event.action === 'create_subagent' ? 'created' : 'queued', detail: '',
      ...(event.action === 'dangerous_auto_yes' ? { dangerousAutoYes: { ...policy } } : {}) });
  }

  return { access, handle, actions, events, device, control, send, ack, snapshot, setClock: value => { now = value; },
    macEnable() { policy = { ...policy, ticket: randomUUID(), revision: policy.revision + 1, enabled: true }; snapshot(); } };
}

test('authorized session metadata actions retain exact ACK after authoritative snapshot changes', async t => {
  const f = await linkedPolicy(t);
  const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
  const sessionActions = { ticket: 'metadata', sourceID: 'canonical', group: 'saved', rgb: 0x123456,
    overridden: true, colors: [{ name: 'Sky', rgb: 0xA6C8FF }], editable: true, removable: true,
    resumable: true, resumeStatus: 'available', resumeDetail: '', moveUp: null, moveDown: null };
  const publish = sessions => f.actions.command({ type: 'workspace', total: sessions.length, truncated: false, sessions });
  for (const [action, status, extra] of [
    ['set_session_color', 'color_saved', { rgb: 0x010203 }], ['reset_session_color', 'color_reset', {}],
    ['remove_session', 'session_removed', {}], ['resume_session', 'launched', {}]
  ]) {
    publish([{ ...row, connected: false, sessionActions }]);
    const input = { id: randomUUID(), sessionID: 's', ticket: 't', action, text: '', sessionTicket: 'metadata', ...extra };
    const pending = f.send(input);
    const sent = f.events.at(-1);
    assert.equal(sent.action, action);
    publish(action === 'remove_session' ? [] : [{ ...row, ticket: 'after', sessionActions: { ...sessionActions, ticket: 'after' } }]);
    f.actions.command({ type: 'control_result', id: sent.id, commandID: sent.id, ok: true, status, detail: 'Native result',
      sessionID: sent.sessionID, action: sent.action, sessionTicket: sent.sessionTicket });
    assert.equal((await pending).data.status, status);
    await assert.rejects(f.send(input), { status: 409 });
  }
});

test('authorized stale session admission returns exact failed receipt and needs a fresh UUID', async t => {
  const f = await linkedPolicy(t);
  const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
  const metadata = { ticket: 'before', sourceID: 'original', group: 'saved', rgb: 1, overridden: false,
    colors: [], editable: true, removable: true, resumable: true, resumeStatus: 'available', resumeDetail: '',
    resumeAuthority: { epoch: 'source-epoch', retired: 2 } };
  const publish = ticket => f.actions.command({ type: 'workspace', total: 1, truncated: false,
    sessions: [{ ...row, connected: false, sessionActions: { ...metadata, ticket } }] });
  for (const action of ['resume_session', 'reset_session_color', 'set_session_color', 'remove_session']) {
    publish('before');
    const original = { id: randomUUID(), sessionID: 's', ticket: 't', sessionTicket: 'before', action, text: '',
      ...(action === 'set_session_color' ? { rgb: 0x123456 } : {}) };
    publish('after');
    assert.deepEqual((await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0].sessionActions.resumeAuthority,
      { epoch: 'source-epoch', retired: 2 });
    const before = f.events.filter(e => e.type === 'control').length;
    const receipt = await f.send(original);
    assert.equal(receipt.status, 200);
    assert.equal(receipt.data.ok, false);
    assert.equal(receipt.data.status, 'failed');
    for (const field of ['sessionID', 'action', 'sessionTicket']) assert.equal(receipt.data[field], original[field]);
    assert.match(receipt.data.detail, /nothing was dispatched/i);
    assert.equal(receipt.data.notDispatched, undefined, 'No urgent-Off marker or same-ID release');
    assert.equal(f.events.filter(e => e.type === 'control').length, before);
    await assert.rejects(f.send(original), { status: 409 });
    await assert.rejects(f.send({ ...original, sessionTicket: 'after' }), { status: 409 });
    const fresh = { ...original, id: randomUUID(), sessionTicket: 'after' };
    const pending = f.send(fresh);
    const emitted = f.events.at(-1);
    assert.equal(emitted.action, action);
    const status = { resume_session: 'launched', reset_session_color: 'color_reset', set_session_color: 'color_saved', remove_session: 'session_removed' }[action];
    f.actions.command({ type: 'control_result', id: emitted.id, commandID: emitted.id, sessionID: emitted.sessionID,
      sessionTicket: emitted.sessionTicket, action, ok: true, status, detail: 'Native completed result' });
    assert.equal((await pending).data.status, status);
  }
});

test('session action offline and replaced-work admission failures remain definite and consume their UUID', async t => {
  for (const reason of ['offline', 'replaced', 'missing']) {
    const f = await linkedPolicy(t);
    const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
    if (reason === 'offline') f.setClock(13000);
    else f.actions.command({ type: 'workspace', total: reason === 'missing' ? 0 : 1, truncated: false,
      sessions: reason === 'missing' ? [] : [{ ...row, ticket: 'different-work' }] });
    const input = { id: randomUUID(), sessionID: 's', ticket: 't', sessionTicket: 'm', action: 'reset_session_color', text: '' };
    const receipt = await f.send(input);
    assert.equal(receipt.status, 200);
    assert.equal(receipt.data.status, 'failed');
    assert.equal(receipt.data.ok, false);
    for (const field of ['sessionID', 'action', 'sessionTicket']) assert.equal(receipt.data[field], input[field]);
    assert.equal(f.events.filter(e => e.type === 'control').length, 0);
    await assert.rejects(f.send(input), { status: 409 });
  }
});

test('native resume authority is bounded typed metadata and never a client retirement assertion', async t => {
  for (const authority of [
    { epoch: '', retired: 0 }, { epoch: 123, retired: 0 }, { epoch: 'scope', retired: -1 },
    { epoch: 'scope', retired: '1' }, { epoch: 'scope', retired: 0.5 }, { epoch: 'scope', retired: Number.MAX_SAFE_INTEGER + 1 }
  ]) {
    const f = await linkedPolicy(t);
    const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
    assert.throws(() => f.actions.command({ type: 'workspace', total: 1, truncated: false, sessions: [{ ...row,
      sessionActions: { ticket: 'm', sourceID: 'original', group: 'saved', rgb: 1, overridden: false,
        colors: [], editable: true, removable: true, resumable: true, resumeStatus: 'available', resumeDetail: '',
        resumeAuthority: authority } }] }), /Invalid workspace snapshot/);
    assert.equal((await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.connected, false);
    assert.equal(f.events.filter(e => e.type === 'control').length, 0);
  }
});

test('session actions reject malformed colors stale targets cross-group moves and reconnected removal', async t => {
  const f = await linkedPolicy(t);
  const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
  const a = { ticket: 'meta', sourceID: 'original', group: 'saved', rgb: 0x010203, overridden: true,
    colors: [], editable: true, removable: true, resumable: true, resumeStatus: 'available', resumeDetail: '', moveDown: 'peer' };
  const peer = { ...row, id: 'peer', ticket: 'tp', connected: false, sessionActions: { ...a, sourceID: 'other', ticket: 'mp', moveDown: null, moveUp: 's' } };
  const publish = (changes = {}, target = peer) => f.actions.command({ type: 'workspace', total: 2, truncated: false,
    sessions: [{ ...row, connected: false, sessionActions: a, ...changes }, target] });
  const command = (action, extra = {}) => ({ id: randomUUID(), sessionID: 's', ticket: 't', action, text: '', sessionTicket: 'meta', ...extra });
  publish();
  for (const rgb of ['1', true, -1, 0x1000000, 1.1, null]) await assert.rejects(f.send(command('set_session_color', { rgb })), { status: 400 });
  for (const extra of [{ cwd: '/synthetic' }, { argv: ['--resume'] }, { sourceID: 'other' }, { agentID: 'child' },
    { resumeAuthority: { epoch: 'client-guess', retired: 999 } }])
    await assert.rejects(f.send(command('resume_session', extra)), { status: 400 });
  const move = () => command('move_session', { targetID: 'peer', targetTicket: 'mp' });
  for (const target of [
    { ...peer, sessionActions: { ...peer.sessionActions, group: 'monitoring' } },
    { ...peer, sessionActions: { ...peer.sessionActions, ticket: 'changed' } },
    { ...peer, sessionActions: { ...peer.sessionActions, sourceID: 'original' } }
  ]) {
   publish({}, target);
   const input = move();
   const before = f.events.filter(e => e.type === 'control').length;
   const rejected = await f.send(input);
   assert.equal(rejected.data.status, 'failed');
   for (const field of ['sessionID', 'action', 'sessionTicket']) assert.equal(rejected.data[field], input[field]);
   assert.equal(f.events.filter(e => e.type === 'control').length, before);
   await assert.rejects(f.send(input), { status: 409 });
  }
  publish({ connected: true });
  assert.equal((await f.send(command('remove_session'))).data.status, 'failed');
  assert.equal((await f.send(command('resume_session'))).data.status, 'failed');
  publish({ sessionActions: undefined });
  assert.equal((await f.send(command('reset_session_color'))).data.status, 'failed');
  publish();
  const pending = f.send(move());
  const sent = f.events.at(-1);
  assert.equal(sent.targetID, 'peer');
  f.actions.command({ type: 'control_result', id: sent.id, commandID: sent.id, ok: true, status: 'session_moved',
    sessionID: sent.sessionID, action: sent.action, sessionTicket: sent.sessionTicket, detail: 'Order saved' });
  assert.equal((await pending).data.status, 'session_moved');
});

test('session action unknown deadline late ACK and mismatched correlation never become launch success', async t => {
  for (const failure of ['deadline', 'correlation', 'connected-status', 'native-failure', 'revoked']) {
    const f = await linkedPolicy(t, { ackTimeout: 15 });
    const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
    f.actions.command({ type: 'workspace', total: 1, truncated: false, sessions: [{ ...row, connected: false,
      sessionActions: { ticket: 'm', sourceID: 'original', group: 'saved', rgb: 1, overridden: false, colors: [],
        editable: true, removable: true, resumable: true, resumeStatus: 'available', resumeDetail: '' } }] });
    const input = { id: randomUUID(), sessionID: 's', ticket: 't', sessionTicket: 'm', action: 'resume_session', text: '' };
    const pending = f.send(input);
    const sent = f.events.at(-1);
    const ack = { type: 'control_result', id: sent.id, commandID: sent.id, ok: true, status: 'launched',
      sessionID: sent.sessionID, action: sent.action, sessionTicket: sent.sessionTicket, detail: 'Launch only' };
    if (failure === 'revoked') f.actions.disconnect(f.device.id);
    else if (failure === 'correlation') f.actions.command({ ...ack, sessionID: 'other' });
    else if (failure === 'connected-status') f.actions.command({ ...ack, status: 'connected' });
    else if (failure === 'native-failure') f.actions.command({ ...ack, ok: false, status: 'failed', detail: 'Original CLI is missing' });
    const result = await pending;
    assert.equal(result.data.status, failure === 'native-failure' ? 'failed' : 'unknown', failure);
    f.actions.command(ack);
    await assert.rejects(f.send(input), { status: 409 });
    assert.equal((await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0].connected, false);
  }
});

test('session actions share eight ordinary pending slots without consuming the urgent Off ninth', async t => {
  const f = await linkedPolicy(t);
  const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
  f.actions.command({ type: 'workspace', total: 1, truncated: false, sessions: [{ ...row,
    sessionActions: { ticket: 'm', sourceID: 'original', group: 'monitoring', rgb: 1, overridden: false, colors: [],
      editable: true, removable: false, resumable: false, resumeStatus: 'connected', resumeDetail: '' } }] });
  const pending = [];
  for (let i = 0; i < 8; i++) pending.push(f.send({ id: randomUUID(), sessionID: 's', ticket: 't',
    sessionTicket: 'm', action: 'reset_session_color', text: '' }));
  const events = f.events.filter(e => e.type === 'control');
  assert.equal(events.length, 8);
  await assert.rejects(f.send({ id: randomUUID(), sessionID: 's', ticket: 't',
    sessionTicket: 'm', action: 'reset_session_color', text: '' }), { status: 429 });
  const off = f.send(f.control(false)); f.ack();
  assert.equal((await off).data.status, 'applied');
  for (const e of events) f.actions.command({ type: 'control_result', id: e.id, commandID: e.id, ok: true,
    status: 'color_reset', sessionID: e.sessionID, action: e.action, sessionTicket: e.sessionTicket, detail: '' });
  assert.equal((await Promise.all(pending)).filter(r => r.data.status === 'color_reset').length, 8);
});

test('authorized management retains exact runtime results after capability, catalog or helper-row changes', async t => {
  const f = await linkedPolicy(t);
  const row = {
    id: 's', ticket: 't', name: 'Synthetic', project: '', agent: 'copilot', color: '#123456', state: 'working',
    connected: true, runningCount: 0, idleCount: 0, managementTicket: 'before',
    capabilities: { steering: true, subagentChat: false, subagentStop: false,
      subagentCreate: true, subagentRemove: true, subagentCleanup: true },
    subagentTypes: ['reviewer'], subagentModels: ['live-model']
  };
  const overview = session => ({ type: 'workspace', total: 1, truncated: false, sessions: [session] });
  const detail = agents => ({ type: 'workspace_detail', sessionID: 's', ticket: 't', activity: [], controls: [],
    truncated: false, team: { agents, runningCount: 0, idleCount: 0, truncated: false } });
  for (const [action, status] of [
    ['stop_idle_subagents', 'failed'], ['stop_idle_subagents', 'unknown'],
    ['create_subagent', 'failed'], ['create_subagent', 'created'], ['remove_subagent', 'removed']
  ]) {
    f.actions.command(overview(row));
    await f.actions.request('workspace', { sessionID: 's' }, f.device);
    f.actions.command(detail([{ id: 'ended', name: 'Ended', task: '', status: 'completed', parentKnown: true }]));
    const input = { id: randomUUID(), sessionID: 's', ticket: 't', managementTicket: 'before', action, text: '',
      ...(action === 'create_subagent' ? { creation: { name: 'Synthetic', agentType: 'reviewer', model: 'live-model', prompt: 'Synthetic' } } : {}),
      ...(action === 'remove_subagent' ? { agentID: 'ended' } : {}) };
    let settled = false;
    const pending = f.send(input).then(result => { settled = true; return result; });
    const sent = f.events.at(-1);
    assert.equal(sent.action, action);
    // The runtime publishes availability/catalog/team changes before returning its operation result.
    f.actions.command(overview({ ...row, managementTicket: 'after', subagentModels: [],
      capabilities: { ...row.capabilities, subagentCleanup: false, subagentRemove: false } }));
    f.actions.command(detail([]));
    await new Promise(setImmediate);
    assert.equal(settled, false, `${action}: admission changes must not discard the original pending runtime result`);
    const rejected = await f.send({ ...input, id: randomUUID() });
    assert.equal(rejected.data.status, 'failed', 'The old reviewed management ticket still cannot admit new work');
    const counts = action === 'stop_idle_subagents'
      ? `Cancelled 2; skipped 3; failed 0; uncertain ${status === 'unknown' ? 1 : 0}. Later runtime observation failed. Main agent was not targeted.`
      : action === 'create_subagent'
        ? status === 'created' ? 'Created subagent “Synthetic”. Requested model: live-model.' : 'This model is no longer available in the live session catalog.'
        : 'Ended subagent removed from the list. No files were deleted.';
    f.actions.command({ type: 'control_result', id: sent.id, commandID: 'native-receipt', status,
      ok: ['created', 'removed'].includes(status), detail: counts });
    const result = await pending;
    assert.equal(result.status, 200);
    assert.equal(result.data.status, status);
    assert.equal(result.data.detail, counts);
    assert.equal(result.data.ok, ['created', 'removed'].includes(status));
    await assert.rejects(f.send(input), { status: 409 });
  }
});

test('management result correlation still ends on replacement, disconnect, missing session or expired lease', async t => {
  for (const fence of ['replacement', 'disconnected', 'missing', 'provider', 'channel', 'lease']) {
    const f = await linkedPolicy(t);
    const row = (await f.actions.request('workspace', { sessionID: 's' }, f.device)).data.sessions[0];
    const input = { id: randomUUID(), sessionID: 's', ticket: 't', managementTicket: 'm',
      action: 'create_subagent', text: '', creation: { name: 'Synthetic', agentType: 'reviewer', prompt: 'Synthetic' } };
    const pending = f.send(input);
    const sent = f.events.at(-1);
    if (fence === 'channel') f.actions.disconnect(f.device.id);
    else if (fence === 'lease') f.setClock(12000);
    else {
      const sessions = fence === 'missing' ? [] : [{
        ...row, ...(fence === 'replacement' ? { ticket: 'replaced' } :
          fence === 'disconnected' ? { connected: false } : { agent: 'claude' })
      }];
      f.actions.command({ type: 'workspace', sessions, total: sessions.length, truncated: false });
    }
    f.actions.command({ type: 'control_result', id: sent.id, commandID: 'late', ok: true, status: 'created', detail: 'Late result' });
    const result = await pending;
    assert.equal(result.data.status, 'unknown', fence);
    assert.equal(result.data.ok, false, fence);
    assert.notEqual(result.data.detail, 'Late result', fence);
  }
});

test('authorized management fills only ordinary history and never consumes urgent Off capacity', async t => {
  const f = await linkedPolicy(t);
  const create = () => ({ id: randomUUID(), sessionID: 's', ticket: 't', managementTicket: 'm',
    action: 'create_subagent', text: '', creation: { name: 'Synthetic', agentType: 'reviewer', prompt: 'Synthetic instructions' } });
  const first = create();
  for (let i = 0; i < 256; i++) {
    const pending = f.send(i === 0 ? first : create());
    assert.equal(f.events.at(-1).action, 'create_subagent');
    f.ack(); assert.equal((await pending).data.status, 'created');
  }
  await assert.rejects(f.send({ ...first, creation: { ...first.creation, name: 'Changed' } }), { status: 409 });
  await assert.rejects(f.send(create()), { status: 429 });
  const off = f.send(f.control(false));
  f.ack(); assert.equal((await off).data.status, 'applied');
});

test('authorized full history retains urgent Off through 300 Mac re-enables without evicting ordinary UUIDs', async t => {
  const f = await linkedPolicy(t);
  const first = f.control();
  for (let i = 0; i < 256; i++) {
    const pending = f.send(i === 0 ? first : i === 255 ? f.control(true) : f.control());
    f.ack(); assert.equal((await pending).status, 200);
  }
  for (let i = 0; i < 300; i++) {
    const pending = f.send(f.control(false));
    f.ack(); assert.equal((await pending).status, 200);
    f.macEnable();
  }
  await assert.rejects(f.send(first), { status: 409 });
  await assert.rejects(f.send(f.control()), { status: 429 });
});

test('authorized urgent Off has a ninth pending slot but never an unbounded pending bypass', async t => {
  const f = await linkedPolicy(t);
  const pending = Array.from({ length: 8 }, () => f.send(f.control()));
  const ordinary = f.events.filter(event => event.type === 'control');
  const offCommand = f.control(false);
  const off = f.send(offCommand);
  off.catch(() => {});
  assert.equal(f.events.filter(event => event.type === 'control').length, 9);
  await assert.rejects(f.send(offCommand), { status: 409 });
  await assert.rejects(f.send({ ...offCommand, policyTicket: 'mutated' }), { status: 409 });
  await assert.rejects(f.send(f.control()), { status: 429 });
  f.ack();
  assert.equal((await off).status, 200);
  ordinary.forEach(f.ack);
  assert.equal((await Promise.all(pending)).length, 8);
});

test('authorized stale rejection permits fresh explicit Off, while unknown Off and payload mutations never redispatch', async t => {
  const f = await linkedPolicy(t);
  const off = f.control(false);
  f.setClock(12001);
  const stale = await f.send(off).catch(error => ({ status: error.status, data: { error: error.message } }));
  assert.equal(stale.status, 503);
  assert.equal(f.events.filter(event => event.type === 'control').length, 0);
  f.snapshot();
  const wrongTarget = await f.send({ ...off, sessionID: 'different-session' });
  assert.equal(wrongTarget.status, 409);
  assert.equal(wrongTarget.data.notDispatched, true);
  assert.equal(f.events.filter(event => event.type === 'control').length, 0);
  const pending = f.send(off);
  pending.catch(() => {});
  assert.equal(f.events.filter(event => event.type === 'control').length, 1);
  assert.equal(stale.data.notDispatched, true);
  f.actions.disconnect('phone');
  assert.equal((await pending).data.status, 'unknown');
  assert.equal((await f.send(off)).data.status, 'unknown');
  await assert.rejects(f.send({ ...off, policyTicket: 'changed' }), { status: 409 });
  await assert.rejects(f.send({ ...f.control(), id: off.id }), { status: 400 });
  assert.equal(f.events.filter(event => event.type === 'control').length, 1);
});

test('authenticated control RPC delegates native policy and never replays after channel loss', async () => {
  const events = [];
  const device = { id: 'phone', name: 'Phone', expires: Date.now() + 30000 };
  const actions = new RemoteActions({ emit: event => events.push(event), devices: () => [device] });
  actions.command({ type: 'workspace', total: 1, truncated: false, sessions: [{
    id: 's', ticket: 't', name: 'Synthetic', project: '', agent: 'copilot', color: '#123456', state: 'working',
    connected: true, runningCount: 0, idleCount: 0,
    capabilities: { steering: false, subagentChat: false, subagentStop: false, dangerousAutoYes: true },
    dangerousAutoYes: { ticket: 'p', offTicket: '00000000-0000-8000-8000-000000000001', revision: 1, enabled: false, normalEnabled: false }
  }] });
  const input = { id: randomUUID(), sessionID: 's', ticket: 't', action: 'dangerous_auto_yes',
    text: '', enabled: true, policyTicket: 'p', offTicket: '00000000-0000-8000-8000-000000000001' };
  const pending = actions.request('control', input, device);
  assert.equal(events.at(-1).action, 'dangerous_auto_yes');
  actions.disconnect(device.id);
  assert.equal((await pending).data.status, 'unknown');
  const count = events.length;
  assert.equal((await actions.request('control', input, device)).data.status, 'unknown');
  assert.equal(events.length, count);
  actions.close();
});

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
