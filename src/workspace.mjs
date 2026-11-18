import { randomUUID, createHash } from 'node:crypto';
import { object } from './validation.mjs';

const str = (v, max, nonempty = false) => typeof v === 'string' && v.length <= max && (!nonempty || v.length > 0);
const id = v => str(v, 128, true) && !v.includes('\0');
const ticket = v => str(v, 256, true);
// The Off epoch is also its UUIDv8 command ID; retirement cannot turn that UUID into different work.
const offTicket = v => typeof v === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-8[a-f\d]{3}-[a-f\d]{4}-[a-f\d]{12}$/i.test(v);
export const isOffID = offTicket;
export function isPolicyOffRPC(rpcID, payload) {
  const c = payload?.data;
  return object(payload) && Object.keys(payload).length === 2 && payload.path === 'control' &&
    object(c) && Object.keys(c).length === 8 &&
    c.action === 'dangerous_auto_yes' && c.enabled === false && c.text === '' &&
    id(c.sessionID) && ticket(c.ticket) && ticket(c.policyTicket) &&
    offTicket(c.offTicket) && offTicket(c.id) && offTicket(rpcID) &&
    c.id.toLowerCase() === c.offTicket.toLowerCase() && rpcID.toLowerCase() === c.id.toLowerCase();
}
const notDispatched = (status, message) => {
  throw Object.assign(new Error(message), { status, notDispatched: true });
};
const managementRejected = message => ({ status: 200, data: { ok: false, status: 'failed', detail: message } });
const sessionRejected = (input, message) => ({ status: 200, data: { ok: false, status: 'failed', detail: message,
  sessionID: input.sessionID, action: input.action, sessionTicket: input.sessionTicket } });
const bool = v => typeof v === 'boolean';
const count = v => Number.isSafeInteger(v) && v >= 0 && v <= 1000000;
const unique = values => new Set(values).size === values.length;
const bytes = v => Buffer.byteLength(JSON.stringify(v));
const fingerprint = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const allowedStatuses = ['sending', 'submitted', 'queued', 'received', 'stopped', 'cancelled', 'failed', 'unknown'];
const managementStatuses = { create_subagent: 'created', remove_subagent: 'removed', stop_idle_subagents: 'cleaned' };
const sessionStatuses = { set_session_color: 'color_saved', reset_session_color: 'color_reset',
  move_session: 'session_moved', remove_session: 'session_removed', resume_session: 'launched' };
const rgb = v => Number.isInteger(v) && v >= 0 && v <= 0xFFFFFF;
const validSessionActions = a => object(a) && ticket(a.ticket) && id(a.sourceID) &&
  ['saved', 'needs_you', 'monitoring', 'not_connected'].includes(a.group) &&
  rgb(a.rgb) && bool(a.overridden) && ['editable', 'removable', 'resumable'].every(k => bool(a[k])) &&
  ['available', 'unavailable', 'launching', 'awaiting_connection', 'connected', 'owner_detected', 'unconfirmed', 'failed', 'unknown'].includes(a.resumeStatus) &&
  str(a.resumeDetail, 4000) && (a.resumeAuthority == null || object(a.resumeAuthority) &&
    ticket(a.resumeAuthority.epoch) && Number.isSafeInteger(a.resumeAuthority.retired) && a.resumeAuthority.retired >= 0) &&
  (a.moveUp == null || id(a.moveUp)) && (a.moveDown == null || id(a.moveDown)) &&
  Array.isArray(a.colors) && a.colors.length <= 20 && unique(a.colors.map(c => c?.rgb)) &&
  a.colors.every(c => object(c) && str(c.name, 64, true) && rgb(c.rgb));
const catalog = (v, limit, size) => Array.isArray(v) && v.length <= limit && unique(v) &&
  v.every(x => str(x, size, true) && x.trim() && !x.includes('\0'));
const validCreation = c => object(c) && str(c.name, 160, true) && c.name.trim() &&
  str(c.agentType, 128, true) && c.agentType.trim() && str(c.prompt, 16000, true) && c.prompt.trim() &&
  (c.model === undefined || str(c.model, 200, true) && c.model.trim()) &&
  Object.keys(c).every(k => ['name', 'agentType', 'prompt', 'model'].includes(k));
const validPolicy = p => object(p) && ticket(p.ticket) && Number.isSafeInteger(p.revision) && p.revision > 0 &&
  bool(p.enabled) && bool(p.normalEnabled) && !(p.enabled && p.normalEnabled) &&
  (p.offTicket === undefined || ticket(p.offTicket));

export function validWorkspace(m) {
  return Array.isArray(m.sessions) && m.sessions.length <= 256 && count(m.total) && bool(m.truncated) &&
    (m.truncated ? m.total >= m.sessions.length : m.total === m.sessions.length) && unique(m.sessions.map(s => s?.id)) &&
    m.sessions.every(s => object(s) && id(s.id) && ticket(s.ticket) && str(s.name, 65535) && str(s.project, 65535) &&
      str(s.agent, 128) && /^#[a-f\d]{6}$/i.test(s.color) && str(s.state, 128) && bool(s.connected) &&
      object(s.capabilities) && ['steering', 'subagentChat', 'subagentStop'].every(k => bool(s.capabilities[k])) &&
      (s.capabilities.steeringImmediate === undefined || bool(s.capabilities.steeringImmediate)) &&
      (s.capabilities.dangerousAutoYes === undefined || bool(s.capabilities.dangerousAutoYes)) &&
      (s.dangerousAutoYes === undefined || validPolicy(s.dangerousAutoYes)) &&
      (!s.capabilities.dangerousAutoYes || validPolicy(s.dangerousAutoYes)) &&
      ['subagentCreate', 'subagentRemove', 'subagentCleanup'].every(k => s.capabilities[k] === undefined || bool(s.capabilities[k])) &&
      (s.managementTicket === undefined || ticket(s.managementTicket)) &&
      (s.subagentTypes === undefined || catalog(s.subagentTypes, 100, 128)) &&
      (s.subagentModels === undefined || catalog(s.subagentModels, 200, 200)) &&
      (!['subagentCreate', 'subagentRemove', 'subagentCleanup'].some(k => s.capabilities[k]) || ticket(s.managementTicket)) &&
      (!s.capabilities.subagentCreate || catalog(s.subagentTypes, 100, 128) && s.subagentTypes.length > 0 && catalog(s.subagentModels, 200, 200)) &&
      (s.sessionActions === undefined || validSessionActions(s.sessionActions)) &&
      count(s.runningCount) && count(s.idleCount));
}

export function validWorkspaceDetail(m) {
  const team = m.team;
  if (!(team === null || (object(team) && Array.isArray(team.agents) && team.agents.length <= 100 &&
    bool(team.truncated) && count(team.runningCount) && count(team.idleCount) &&
    (team.error == null || str(team.error, 1000)) && unique(team.agents.map(a => a?.id)) &&
    team.agents.every(a => object(a) && id(a.id) && str(a.name, 160, true) && str(a.task, 1000) &&
      ['running', 'idle', 'completed', 'failed', 'cancelled'].includes(a.status) &&
      (a.model == null || str(a.model, 200)) && (a.parentKnown == null || bool(a.parentKnown)) &&
      (a.parentAgentID == null || (id(a.parentAgentID) && a.parentAgentID !== a.id && a.parentKnown === true))) &&
    ['running', 'idle'].every(status => team.truncated
      ? team[`${status}Count`] >= team.agents.filter(a => a.status === status).length
      : team[`${status}Count`] === team.agents.filter(a => a.status === status).length)))) return false;
  return id(m.sessionID) && ticket(m.ticket) && bool(m.truncated) && (m.error == null || str(m.error, 1000)) &&
    Array.isArray(m.activity) && m.activity.length <= 300 && unique(m.activity.map(a => a?.id)) &&
    m.activity.every(a => object(a) && str(a.id, 256, true) && ['user', 'assistant', 'reasoning', 'tool', 'status'].includes(a.kind) &&
      str(a.title, 300, true) && str(a.detail, 65536) && Buffer.byteLength(a.detail) <= 65536 &&
      ['running', 'complete', 'failed', 'info'].includes(a.status) && str(a.timestamp, 64) &&
      (a.agentID == null || id(a.agentID)) && (a.clientTurnID == null || id(a.clientTurnID))) &&
    Array.isArray(m.controls) && m.controls.length <= 100 && unique(m.controls.map(c => c?.id)) &&
    m.controls.every(c => object(c) && id(c.id) && ['send', 'queue', 'interrupt', 'stop'].includes(c.action) &&
      (c.action === 'send' ? c.agentID == null && c.status !== 'queued' : c.status !== 'submitted') &&
      str(c.message, 16000) && allowedStatuses.includes(c.status) && str(c.detail, 4000) &&
      (c.agentID == null || id(c.agentID)) && str(c.createdAt, 64, true) && Number.isFinite(Date.parse(c.createdAt)));
}

export class Workspace {
  constructor({ emit, now, fail, ackTimeout, devices }) {
    Object.assign(this, { emit, now, fail, ackTimeout, devices });
    this.sessions = []; this.total = 0; this.truncated = false; this.available = false;
    this.details = new Map(); this.selections = new Map(); this.waiters = new Map();
    this.controls = new Map(); this.offControls = new Map(); this.pending = new Map(); this.error = 'Workspace unavailable. Update or reconnect Notify on the Mac.';
  }
  fresh() { return this.available && this.now() - this.updated < 12000; }
  live(sid, generation) { return this.fresh() && this.sessions.some(s => s.id === sid && s.ticket === generation); }
  watch(force = false) {
    for (const [device, value] of this.selections) {
      if (value.expires <= this.now() || !this.devices().some(d => d.id === device && d.expires > this.now())) {
        this.selections.delete(device);
        this.waiters.get(device)?.finish(401, { error: 'Phone watch expired or pairing was revoked.' });
      }
    }
    const ids = [...new Set([...this.selections.values()].map(s => s.sessionID).filter(Boolean))].sort();
    const signature = JSON.stringify(ids);
    for (const sid of this.details.keys()) if (!ids.includes(sid)) this.details.delete(sid);
    if (force || this.watching !== signature) {
      this.watching = signature;
      if (this.supported) this.emit({ type: 'workspace_watch', sessionIDs: ids });
    }
  }
  payload(deviceID) {
    const connected = this.fresh();
    const sid = this.selections.get(deviceID)?.sessionID;
    const detail = this.details.get(sid);
    const value = { steeringImmediateControl: true, dangerousAutoYesControl: true, dangerousAutoYesOffEpoch: true, subagentManagementControl: true, sessionActionsControl: true,
      connected, sessions: connected ? this.sessions : [], total: connected ? this.total : 0,
      truncated: connected ? this.truncated : false,
      detail: connected && detail && this.live(sid, detail.ticket) ? detail : null,
      ...(!connected ? { error: this.error ?? 'Workspace snapshot expired. Reconnect to the Mac.' } : {}) };
    return { revision: fingerprint(value), ...value };
  }
  wake() {
    for (const [device, waiter] of this.waiters) {
      const value = this.payload(device);
      if (value.revision !== waiter.revision) waiter.finish(200, value);
    }
  }
  complete(record, status, data) {
    clearTimeout(record.timer); this.pending.delete(record.nativeID);
    record.result = { status, data };
    record.resolve?.(record.result); record.resolve = undefined;
  }
  invalidate(message, status = 503) {
    this.available = false; this.sessions = []; this.details.clear(); this.error = message;
    for (const record of this.pending.values()) this.complete(record, status, { ok: false, status: 'unknown', error: message });
    this.wake();
  }
  revoke(device) {
    this.selections.delete(device); this.watch();
    this.waiters.get(device)?.finish(401, { error: 'Pairing revoked on the Mac.' });
    for (const record of this.pending.values()) if (record.device === device)
      this.complete(record, 401, { ok: false, status: 'unknown', error: 'Pairing revoked. A dispatched control may already have arrived.' });
  }
  tick() {
    this.watch();
    for (const r of this.pending.values()) {
      if (!this.devices().some(d => d.id === r.device && d.expires > this.now()))
        this.complete(r, 401, { ok: false, status: 'unknown', error: 'Pairing expired or was revoked. A dispatched control may already have arrived.' });
    }
    if (this.available && !this.fresh()) this.invalidate('Native workspace lease expired. Reconnect to the Mac.');
    for (const [key, r] of this.controls) {
      // Never evict uncertain safety records while their native generation can still accept work.
      if (!this.pending.has(r.nativeID) && this.available && !this.live(r.sessionID, r.ticket)) this.controls.delete(key);
    }
    for (const [sid, r] of this.offControls) {
      if (!this.pending.has(r.nativeID) && this.available && !this.live(r.sessionID, r.ticket)) this.offControls.delete(sid);
    }
  }
  command(m) {
    if (m.type === 'control_result') {
      this.tick();
      const r = this.pending.get(m.id);
      if (!r) return;
      const policy = r.action === 'dangerous_auto_yes';
      const management = Object.hasOwn(managementStatuses, r.action);
      const sessionAction = Object.hasOwn(sessionStatuses, r.action);
      if (!bool(m.ok) || !str(m.detail ?? '', 4000) || !str(m.error ?? '', 1000) ||
        (sessionAction && (m.sessionID !== r.sessionID || m.action !== r.action || m.sessionTicket !== r.sessionTicket)) ||
        (m.dangerousAutoYes !== undefined && (!policy || !validPolicy(m.dangerousAutoYes) || !offTicket(m.dangerousAutoYes.offTicket))) ||
        (m.ok && (!id(m.commandID) || !(policy
          ? m.status === 'applied' && validPolicy(m.dangerousAutoYes) && m.dangerousAutoYes.enabled === r.enabled &&
            offTicket(m.dangerousAutoYes.offTicket) && m.dangerousAutoYes.ticket !== r.policyTicket &&
            m.dangerousAutoYes.revision > r.policyRevision && (r.enabled || m.dangerousAutoYes.offTicket !== r.offTicket)
          : sessionAction ? m.status === sessionStatuses[r.action] && m.commandID === r.nativeID
          : management ? m.status === managementStatuses[r.action]
          : r.action === 'stop' ? m.status === 'stopped'
          : (r.action === 'send' ? ['submitted', 'received'] : ['queued', 'received']).includes(m.status))))) {
        this.complete(r, 502, { ok: false, status: 'unknown', error: 'Invalid native control acknowledgment. Check the Mac.' }); return;
      }
      if (policy && validPolicy(m.dangerousAutoYes)) {
        this.sessions = this.sessions.map(s => s.id === r.sessionID && s.ticket === r.ticket &&
          s.dangerousAutoYes && m.dangerousAutoYes.revision >= s.dangerousAutoYes.revision
          ? { ...s, dangerousAutoYes: m.dangerousAutoYes } : s);
        this.wake();
      }
      this.complete(r, m.ok || policy && validPolicy(m.dangerousAutoYes) || (management || sessionAction) && ['failed', 'unknown'].includes(m.status) ? 200 : 502, { ok: m.ok, commandID: m.commandID ?? null,
        status: (allowedStatuses.includes(m.status) || policy && m.status === 'applied' || management && m.ok && m.status === managementStatuses[r.action] ||
          sessionAction && m.ok && m.status === sessionStatuses[r.action]) ? m.status : 'unknown', detail: m.detail ?? '',
        ...(sessionAction ? { sessionID: r.sessionID, action: r.action, sessionTicket: r.sessionTicket } : {}),
        ...(policy && validPolicy(m.dangerousAutoYes) ? { dangerousAutoYes: m.dangerousAutoYes } : {}),
        ...(!m.ok ? { error: m.error || 'Control not acknowledged. Check the Mac.' } : {}) });
      return;
    }
    if (bytes(m) > 1048576 || !(m.type === 'workspace' ? validWorkspace(m) : validWorkspaceDetail(m))) {
      this.invalidate('Invalid native workspace snapshot. Workspace controls are disabled.');
      throw new Error('Invalid workspace snapshot or encoded size exceeds 1 MiB.');
    }
    if (m.type === 'workspace') {
      const first = !this.supported;
      this.supported = true;
      this.sessions = m.sessions.map(s => {
        const previous = this.sessions.find(old => old.id === s.id && old.ticket === s.ticket)?.dangerousAutoYes;
        return previous && s.dangerousAutoYes && previous.revision > s.dangerousAutoYes.revision
          ? { ...s, dangerousAutoYes: previous } : s;
      });
      this.total = m.total; this.truncated = m.truncated;
      this.updated = this.now(); this.available = true; this.error = undefined;
      for (const [sid, detail] of this.details) if (!this.live(sid, detail.ticket)) this.details.delete(sid);
      for (const r of this.pending.values()) if (!Object.hasOwn(sessionStatuses, r.action) && (!this.live(r.sessionID, r.ticket) ||
        Object.hasOwn(managementStatuses, r.action) && !this.sessions.some(s => s.id === r.sessionID && s.connected && s.agent === 'copilot'))
        )
        this.complete(r, 409, { ok: false, status: 'unknown', error: 'Native generation changed. Check the Mac before resending.' });
      this.tick();
      if (first) this.watch(true);
    } else if (this.live(m.sessionID, m.ticket) &&
      [...this.selections.values()].some(s => s.sessionID === m.sessionID && s.expires > this.now())) {
      this.details.set(m.sessionID, m);
    }
    this.wake();
  }
  async read(input, device, response) {
    if (!(input.sessionID === null || id(input.sessionID)) || (input.revision !== undefined && !str(input.revision, 128))) this.fail(400, 'Invalid workspace selection.');
    this.tick();
    const previous = this.selections.get(device.id)?.sessionID;
    if (this.waiters.has(device.id)) {
      if (previous === input.sessionID) this.fail(409, 'Only one workspace read per phone may wait at a time.');
      this.waiters.get(device.id).finish(409, { error: 'Workspace selection changed on this phone.' });
    }
    this.selections.set(device.id, { sessionID: input.sessionID, expires: this.now() + 30000 });
    this.watch(previous !== input.sessionID);
    const value = this.payload(device.id);
    if (previous !== input.sessionID || value.revision !== input.revision) return { status: 200, data: value };
    return new Promise(resolve => {
      const finish = (status, data) => {
        clearTimeout(timer); this.waiters.delete(device.id); response.off('close', disconnected);
        resolve({ status, data });
      };
      const disconnected = () => finish(499, { error: 'Workspace read disconnected.' });
      const timer = setTimeout(() => finish(200, this.payload(device.id)), 8000);
      this.waiters.set(device.id, { revision: value.revision, finish });
      response.once('close', disconnected);
    });
  }
  async control(input, device) {
    this.tick();
    const policy = input.action === 'dangerous_auto_yes';
    const off = policy && input.enabled === false;
    const management = Object.hasOwn(managementStatuses, input.action);
    const sessionAction = Object.hasOwn(sessionStatuses, input.action);
    if (!str(input.id, 36) || !/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(input.id) ||
      !id(input.sessionID) || !ticket(input.ticket) || !(['send', 'queue', 'interrupt', 'stop', 'dangerous_auto_yes'].includes(input.action) || management || sessionAction) ||
      !str(input.text, 16000) || (input.action === 'stop' || policy || management || sessionAction ? input.text !== '' : !input.text.trim()) ||
      (sessionAction ? !ticket(input.sessionTicket) || input.id[14] !== '4' || input.agentID !== undefined ||
        (input.action === 'set_session_color' ? !rgb(input.rgb) : input.rgb !== undefined) ||
        (input.action === 'move_session' ? !id(input.targetID) || input.targetID === input.sessionID || !ticket(input.targetTicket) :
          input.targetID !== undefined || input.targetTicket !== undefined) :
        input.sessionTicket !== undefined || input.rgb !== undefined || input.targetID !== undefined || input.targetTicket !== undefined) ||
      (management ? !ticket(input.managementTicket) || input.id[14] !== '4' ||
        (input.action === 'create_subagent' ? !validCreation(input.creation) || input.agentID !== undefined :
          input.creation !== undefined || (input.action === 'remove_subagent' ? !id(input.agentID) : input.agentID !== undefined)) :
        input.managementTicket !== undefined || input.creation !== undefined) ||
      (policy ? !bool(input.enabled) || !ticket(input.policyTicket) || input.agentID !== undefined :
        input.enabled !== undefined || input.policyTicket !== undefined) ||
      (policy ? !offTicket(input.offTicket) || (off ? input.id.toLowerCase() !== input.offTicket.toLowerCase() : offTicket(input.id)) :
        input.offTicket !== undefined || offTicket(input.id)) ||
      (input.agentID !== undefined && !id(input.agentID)) ||
      Object.keys(input).some(k => !['id', 'sessionID', 'ticket', 'action', 'text', 'agentID', 'enabled', 'policyTicket', 'offTicket', 'managementTicket', 'creation',
        'sessionTicket', 'rgb', 'targetID', 'targetTicket'].includes(k))) this.fail(400, 'Invalid control payload.');
    const payload = { sessionID: input.sessionID, ticket: input.ticket, action: input.action, text: input.text, agentID: input.agentID,
      ...(policy ? { enabled: input.enabled, policyTicket: input.policyTicket, offTicket: input.offTicket } : {}),
      ...(sessionAction ? { sessionTicket: input.sessionTicket,
        ...(input.action === 'set_session_color' ? { rgb: input.rgb } : {}),
        ...(input.action === 'move_session' ? { targetID: input.targetID, targetTicket: input.targetTicket } : {}) } : {}),
      ...(management ? { managementTicket: input.managementTicket,
        ...(input.creation ? { creation: { name: input.creation.name, agentType: input.creation.agentType,
          prompt: input.creation.prompt, ...(input.creation.model === undefined ? {} : { model: input.creation.model }) } } : {}) } : {}) };
    const key = `${device.id}\0${input.id.toLowerCase()}`, digest = fingerprint(payload);
    const existing = this.controls.get(key) ?? [...this.offControls.values()].find(r => r.key === key);
    if (existing) {
      if (existing.digest !== digest) this.fail(409, 'This control UUID was already used with different content.');
      if (existing.result) return existing.result;
      this.fail(409, 'This exact control is already awaiting acknowledgment. Do not resend.');
    }
    if (!this.fresh()) {
      if (sessionAction) return sessionRejected(input, 'Workspace is offline or stale. Refresh and review again; nothing was dispatched.');
      if (management) return managementRejected('Workspace is offline or stale. Refresh and review again; nothing was dispatched.');
      notDispatched(503, 'Workspace is offline or stale.');
    }
    const s = this.sessions.find(s => s.id === input.sessionID && s.ticket === input.ticket);
    if (!s || !sessionAction && (!s.connected || s.agent !== 'copilot')) {
      if (sessionAction) return sessionRejected(input, 'Session changed or disappeared. Refresh and review again; nothing was dispatched.');
      if (management) return managementRejected('Session changed, disconnected, or does not support management. Nothing was dispatched.');
      notDispatched(409, 'Session changed, disconnected, or does not support controls.');
    }
    if (sessionAction) {
      const a = s.sessionActions;
      if (!a?.editable || a.ticket !== input.sessionTicket ||
        this.sessions.filter(row => row.sessionActions?.sourceID === a.sourceID).length !== 1)
        return sessionRejected(input, 'Session actions are unsupported, ambiguous or stale. Refresh the Mac workspace; nothing was dispatched.');
      if (input.action === 'remove_session' && (!a.removable || s.connected) ||
        input.action === 'resume_session' && (!a.resumable || s.connected || a.group !== 'saved'))
        return sessionRejected(input, 'The disconnected or saved session changed. Nothing was dispatched.');
      if (input.action === 'move_session') {
        const target = this.sessions.find(row => row.id === input.targetID)?.sessionActions;
        if (![a.moveUp, a.moveDown].includes(input.targetID) || !target?.editable || target.ticket !== input.targetTicket ||
          target.group !== a.group || target.sourceID === a.sourceID ||
          this.sessions.filter(row => row.sessionActions?.sourceID === target.sourceID).length !== 1)
          return sessionRejected(input, 'The exact same-group move target changed. Refresh before moving; nothing was dispatched.');
      }
    } else if (policy) {
      // Off still needs fresh session authority, but must be able to supersede an in-flight enable.
      if (!s.capabilities.dangerousAutoYes || !validPolicy(s.dangerousAutoYes) || !offTicket(s.dangerousAutoYes.offTicket) ||
        s.dangerousAutoYes.offTicket !== input.offTicket || !off && s.dangerousAutoYes.ticket !== input.policyTicket)
        notDispatched(409, 'Dangerous Auto-yes is unsupported or its Mac policy changed. Refresh this exact session.');
    } else if (management) {
      const capability = { create_subagent: 'subagentCreate', remove_subagent: 'subagentRemove', stop_idle_subagents: 'subagentCleanup' }[input.action];
      if (!s.capabilities[capability] || s.managementTicket !== input.managementTicket)
        return managementRejected('Management support or its live catalog changed. Refresh and review this session; nothing was dispatched.');
      if (input.action === 'create_subagent') {
        if (!s.subagentTypes?.includes(input.creation.agentType) ||
          input.creation.model !== undefined && !s.subagentModels?.includes(input.creation.model))
          return managementRejected('The selected live type or model is no longer available. Nothing was dispatched; no default was substituted.');
      } else {
        const d = this.details.get(s.id);
        if (!d || d.ticket !== s.ticket || !d.team || d.team.error)
          return managementRejected('Wait for a valid team snapshot for this exact session. Nothing was dispatched.');
        if (input.action === 'remove_subagent' && !d.team.agents.some(a => a.id === input.agentID && ['completed', 'failed', 'cancelled'].includes(a.status)))
          return managementRejected('Only a currently known ended helper can be removed. Nothing was dispatched; Stop is a separate action.');
      }
    } else if (input.agentID) {
      const d = this.details.get(s.id), a = d?.team?.agents.find(a => a.id === input.agentID);
      if (!d || d.ticket !== s.ticket || d.team?.error || !a || !['running', 'idle'].includes(a.status) ||
        !s.capabilities[input.action === 'stop' ? 'subagentStop' : 'subagentChat'] || ['send', 'interrupt'].includes(input.action))
        this.fail(409, 'Exact subagent is ended, unavailable, or unsupported. No fallback was sent.');
    } else if (!s.capabilities.steering || input.action === 'send' && s.capabilities.steeringImmediate !== true)
      this.fail(409, 'This session does not support the requested delivery mode. Reload its Notify extension or choose Queue.');
    if (off && this.offControls.get(s.id)?.offTicket === input.offTicket)
      this.fail(409, 'Off for this exact policy epoch is already pending or uncertain. Check the Mac; it will not be replayed.');
    if (management && (this.controls.size >= 256 || this.pending.size >= 8))
      return managementRejected('Control safety history is full or commands await acknowledgment. Nothing was dispatched; no extra capacity was granted.');
    if (sessionAction && (this.controls.size >= 256 || this.pending.size >= 8))
      return sessionRejected(input, 'Control safety history is full or commands await acknowledgment. Nothing was dispatched; no extra capacity was granted.');
    if ((!off && this.controls.size >= 256) || this.pending.size >= (off ? 9 : 8))
      notDispatched(429, 'Control safety history is full or too many commands await acknowledgment. Wait for a new native generation.');
    const r = { ...payload, key, device: device.id, digest, nativeID: off ? input.offTicket : randomUUID(),
      ...(policy ? { policyRevision: s.dangerousAutoYes.revision } : {}) };
    // One slot per session; replacement is safe only when native Off authority has invalidated the old epoch.
    if (off) this.offControls.set(s.id, r);
    else this.controls.set(key, r);
    return new Promise(resolve => {
      r.resolve = resolve;
      r.timer = setTimeout(() => this.complete(r, 504, { ok: false, status: 'unknown',
        error: 'No native acknowledgment in time. The control may have arrived; check the Mac before another action.' }), this.ackTimeout);
      this.pending.set(r.nativeID, r);
      this.emit({ type: 'control', id: r.nativeID, ...payload });
    });
  }
}
