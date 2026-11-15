import { randomUUID, createHash } from 'node:crypto';
import { object } from './validation.mjs';

const str = (v, max, nonempty = false) => typeof v === 'string' && v.length <= max && (!nonempty || v.length > 0);
const id = v => str(v, 128, true) && !v.includes('\0');
const ticket = v => str(v, 256, true);
const bool = v => typeof v === 'boolean';
const count = v => Number.isSafeInteger(v) && v >= 0 && v <= 1000000;
const unique = values => new Set(values).size === values.length;
const bytes = v => Buffer.byteLength(JSON.stringify(v));
const fingerprint = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const allowedStatuses = ['sending', 'queued', 'received', 'stopped', 'cancelled', 'failed', 'unknown'];

export function validWorkspace(m) {
  return Array.isArray(m.sessions) && m.sessions.length <= 256 && count(m.total) && bool(m.truncated) &&
    (m.truncated ? m.total >= m.sessions.length : m.total === m.sessions.length) && unique(m.sessions.map(s => s?.id)) &&
    m.sessions.every(s => object(s) && id(s.id) && ticket(s.ticket) && str(s.name, 65535) && str(s.project, 65535) &&
      str(s.agent, 128) && /^#[a-f\d]{6}$/i.test(s.color) && str(s.state, 128) && bool(s.connected) &&
      object(s.capabilities) && ['steering', 'subagentChat', 'subagentStop'].every(k => bool(s.capabilities[k])) &&
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
    m.controls.every(c => object(c) && id(c.id) && ['queue', 'interrupt', 'stop'].includes(c.action) &&
      str(c.message, 16000) && allowedStatuses.includes(c.status) && str(c.detail, 4000) &&
      (c.agentID == null || id(c.agentID)) && str(c.createdAt, 64, true) && Number.isFinite(Date.parse(c.createdAt)));
}

export class Workspace {
  constructor({ emit, now, fail, ackTimeout, devices }) {
    Object.assign(this, { emit, now, fail, ackTimeout, devices });
    this.sessions = []; this.total = 0; this.truncated = false; this.available = false;
    this.details = new Map(); this.selections = new Map(); this.waiters = new Map();
    this.controls = new Map(); this.pending = new Map(); this.error = 'Workspace unavailable. Update or reconnect Notify on the Mac.';
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
    const value = { connected, sessions: connected ? this.sessions : [], total: connected ? this.total : 0,
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
  }
  command(m) {
    if (m.type === 'control_result') {
      this.tick();
      const r = this.pending.get(m.id);
      if (!r) return;
      if (!bool(m.ok) || !str(m.detail ?? '', 4000) || !str(m.error ?? '', 1000) ||
        (m.ok && (!id(m.commandID) || !(r.action === 'stop' ? m.status === 'stopped' : ['queued', 'received'].includes(m.status))))) {
        this.complete(r, 502, { ok: false, status: 'unknown', error: 'Invalid native control acknowledgment. Check the Mac.' }); return;
      }
      this.complete(r, m.ok ? 200 : 502, { ok: m.ok, commandID: m.commandID ?? null,
        status: allowedStatuses.includes(m.status) ? m.status : 'unknown', detail: m.detail ?? '',
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
      this.sessions = m.sessions; this.total = m.total; this.truncated = m.truncated;
      this.updated = this.now(); this.available = true; this.error = undefined;
      for (const [sid, detail] of this.details) if (!this.live(sid, detail.ticket)) this.details.delete(sid);
      for (const r of this.pending.values()) if (!this.live(r.sessionID, r.ticket))
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
    if (!str(input.id, 36) || !/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(input.id) ||
      !id(input.sessionID) || !ticket(input.ticket) || !['queue', 'interrupt', 'stop'].includes(input.action) ||
      !str(input.text, 16000) || (input.action === 'stop' ? input.text !== '' : !input.text.trim()) ||
      (input.agentID !== undefined && !id(input.agentID)) ||
      Object.keys(input).some(k => !['id', 'sessionID', 'ticket', 'action', 'text', 'agentID'].includes(k))) this.fail(400, 'Invalid control payload.');
    const payload = { sessionID: input.sessionID, ticket: input.ticket, action: input.action, text: input.text, agentID: input.agentID };
    const key = `${device.id}\0${input.id.toLowerCase()}`, digest = fingerprint(payload), existing = this.controls.get(key);
    if (existing) {
      if (existing.digest !== digest) this.fail(409, 'This control UUID was already used with different content.');
      if (existing.result) return existing.result;
      this.fail(409, 'This exact control is already awaiting acknowledgment. Do not resend.');
    }
    if (!this.fresh()) this.fail(503, 'Workspace is offline or stale.');
    const s = this.sessions.find(s => s.id === input.sessionID && s.ticket === input.ticket);
    if (!s || !s.connected || s.agent !== 'copilot') this.fail(409, 'Session changed, disconnected, or does not support controls.');
    if (input.agentID) {
      const d = this.details.get(s.id), a = d?.team?.agents.find(a => a.id === input.agentID);
      if (!d || d.ticket !== s.ticket || d.team?.error || !a || !['running', 'idle'].includes(a.status) ||
        !s.capabilities[input.action === 'stop' ? 'subagentStop' : 'subagentChat'] || input.action === 'interrupt')
        this.fail(409, 'Exact subagent is ended, unavailable, or unsupported. No fallback was sent.');
    } else if (!s.capabilities.steering) this.fail(409, 'This session does not support steering.');
    if (this.controls.size >= 256 || this.pending.size >= 8) this.fail(429, 'Control safety history is full or too many commands await acknowledgment. Wait for a new native generation.');
    const r = { ...payload, device: device.id, digest, nativeID: randomUUID() };
    this.controls.set(key, r);
    return new Promise(resolve => {
      r.resolve = resolve;
      r.timer = setTimeout(() => this.complete(r, 504, { ok: false, status: 'unknown',
        error: 'No native acknowledgment in time. The control may have arrived; check the Mac before another action.' }), this.ackTimeout);
      this.pending.set(r.nativeID, r);
      this.emit({ type: 'control', id: r.nativeID, ...payload });
    });
  }
}
