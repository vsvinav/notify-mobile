import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Workspace } from './workspace.mjs';
import { object, validSnapshot, validReply } from './validation.mjs';

const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const keyOf = item => `${item.sessionID}\0${item.request.id}\0${item.ticket}`;

// Only called after authenticated channel authorization; native remains the dispatcher.
export class RemoteActions {
  #emit; #now; #workspace; #requests = []; #total = 0; #updated = -Infinity;
  #pending = new Map(); #blocked = new Set(); #ackTimeout;
  #seen = new Set(); #attention;
  constructor({ emit, devices, now = Date.now, ackTimeout = 20000, attention = () => {} }) {
    this.#emit = emit; this.#now = now; this.#ackTimeout = ackTimeout;
    this.#attention = attention;
    this.#workspace = new Workspace({ emit, devices, now, ackTimeout, fail });
  }
  #finish(id, status, data) {
    const record = this.#pending.get(id);
    if (!record) return;
    clearTimeout(record.timer);
    this.#pending.delete(id);
    record.resolve({ status, data });
  }
  command(message) {
    if (!object(message)) fail(400, 'Invalid native message.');
    if (['workspace', 'workspace_detail', 'control_result'].includes(message.type)) {
      this.#workspace.command(message); return;
    }
    if (message.type === 'result') {
      this.#finish(message.id, message.ok === true ? 200 : 502, message.ok === true
        ? { ok: true } : { ok: false, error: typeof message.error === 'string'
          ? message.error.slice(0, 1000) : 'Native reply outcome is unknown. Check the Mac.' });
      return;
    }
    if (message.type !== 'snapshot') fail(400, 'Unsupported native action message.');
    if (Buffer.byteLength(JSON.stringify(message)) > 1048576 || !validSnapshot(message)) {
      this.close(); fail(503, 'Native snapshot is invalid. Internet actions are paused.');
    }
    this.#requests = message.requests; this.#total = message.total; this.#updated = this.#now();
    const keys = new Set(this.#requests.map(keyOf));
    const newlyWaiting = this.#requests.some(item => !item.sending && !this.#seen.has(keyOf(item)));
    this.#seen = keys;
    for (const key of this.#blocked) if (!keys.has(key)) this.#blocked.delete(key);
    for (const [id, pending] of this.#pending) if (!keys.has(pending.key))
      this.#finish(id, 409, { ok: false, error: 'Request changed. Its earlier reply outcome may be unknown.' });
    if (newlyWaiting) this.#attention();
  }
  async request(path, input, device, signal) {
    if (!object(input) || signal?.aborted) fail(400, 'Invalid or disconnected remote request.');
    const fresh = this.#now() - this.#updated < 12000;
    if (path === 'state') return { status: 200, data: {
      paired: true, device: { id: device.id, name: device.name }, connected: fresh,
      requests: fresh ? this.#requests.map(item => ({ ...item, sending: item.sending || this.#blocked.has(keyOf(item)) })) : [],
      total: fresh ? this.#total : 0, lease: 12000, pushEnabled: false
    } };
    if (path === 'workspace') {
      const response = new EventEmitter();
      const abort = () => response.emit('close');
      signal?.addEventListener('abort', abort, { once: true });
      try { return await this.#workspace.read(input, device, response); }
      finally { signal?.removeEventListener('abort', abort); }
    }
    if (path === 'control') return this.#workspace.control(input, device);
    if (path !== 'reply') fail(404, 'Unsupported remote action.');
    if (!fresh) fail(503, 'Native snapshot is stale. Reconnect before replying.');
    const item = this.#requests.find(item => item.sessionID === input.sessionID &&
      item.request.id === input.requestID && item.ticket === input.ticket);
    if (!item) fail(409, 'Request changed. Review a fresh request.');
    const key = keyOf(item);
    if (item.sending || this.#blocked.has(key)) fail(409, 'Reply already sent or awaiting acknowledgment. Do not resend.');
    if (!validReply(item.request, input)) fail(400, 'Choose only offered options and allowed answers.');
    if (this.#pending.size >= 8) fail(429, 'Too many replies await acknowledgment.');
    this.#blocked.add(key);
    const id = randomUUID();
    return new Promise(resolve => {
      const timer = setTimeout(() => this.#finish(id, 504, {
        ok: false, error: 'Native reply outcome is unknown. Check the Mac before another action.'
      }), this.#ackTimeout);
      this.#pending.set(id, { resolve, timer, key, deviceID: device.id });
      this.#emit({ type: 'reply', id, sessionID: input.sessionID, requestID: input.requestID,
        ticket: input.ticket, decision: input.decision, answers: input.answers ?? {},
        ...(input.permissionOptionID !== undefined ? { permissionOptionID: input.permissionOptionID } : {}),
        ...(input.feedback !== undefined ? { feedback: input.feedback } : {}) });
    });
  }
  disconnect(deviceID) {
    this.#workspace.revoke(deviceID);
    for (const [id, pending] of this.#pending) if (pending.deviceID === deviceID)
      this.#finish(id, 503, { ok: false, error: 'Connection lost. Reply outcome is unknown; do not resend automatically.' });
  }
  close() {
    this.#updated = -Infinity; this.#requests = []; this.#total = 0;
    this.#workspace.invalidate('Internet connection lost. Pending control outcomes are unknown.');
    for (const [id] of this.#pending) this.#finish(id, 503, {
      ok: false, error: 'Internet connection lost. Reply outcome is unknown.'
    });
    for (const waiter of this.#workspace.waiters.values())
      waiter.finish(503, { error: 'Internet connection lost.' });
  }
}
