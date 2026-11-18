import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { object } from './validation.mjs';
import { isOffID, isPolicyOffRPC } from './workspace.mjs';

const ownerFields = ['issuer', 'subject', 'macID'];
const deviceFields = ['deviceID', 'keyHash'];
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !value.includes('\0');
const shape = (value, fields) => object(value) && Object.keys(value).length === fields.length &&
  fields.every(field => Object.hasOwn(value, field));
const validOwner = value => shape(value, ownerFields) && ownerFields.every(field => text(value[field]));
const validDevice = value => shape(value, deviceFields) && text(value.deviceID) &&
  typeof value.keyHash === 'string' && /^[a-f\d]{64}$/.test(value.keyHash);
const sameOwner = (a, b) => ownerFields.every(field => a[field] === b[field]);
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

// Local authorization only: callers must verify channel identity and service grants
// before connect(). Administration must never be exposed as remote message handlers.
export class RemoteAccess {
  #owner; #store; #state; #now; #clock = -Infinity;
  #enabled = false; #fault = false; #busy = 0; #writes = Promise.resolve();
  #epoch = randomUUID(); #channels = new Map(); #history = new Map(); #pending = new Set();

  static async open({ owner, store, now = () => performance.now() }) {
    if (!validOwner(owner)) fail(400, 'Invalid remote owner identity.');
    owner = Object.freeze({ ...owner });
    const state = await store.read();
    if (state !== null && (!shape(state, ['version', 'owner', 'devices']) || state.version !== 1 ||
      !validOwner(state.owner) || !sameOwner(state.owner, owner) || !Array.isArray(state.devices) ||
      state.devices.length > 8 || !state.devices.every(validDevice) ||
      new Set(state.devices.map(device => device.deviceID)).size !== state.devices.length))
      fail(503, 'Invalid remote policy or owner mismatch. Remote access remains disabled.');
    return new RemoteAccess(owner, store, state?.devices ?? [], now);
  }

  constructor(owner, store, devices, now) {
    this.#owner = Object.freeze({ ...owner });
    this.#store = store;
    this.#state = { version: 1, owner: this.#owner, devices: devices.map(device => Object.freeze({ ...device })) };
    this.#now = now;
    this.#time();
  }

  get epoch() { return this.#epoch; }

  #time() {
    const value = this.#now();
    if (!Number.isFinite(value) || value < 0 || value < this.#clock) {
      this.#fault = true; this.disable();
      fail(503, 'Remote authorization clock is invalid. Reopen remote access locally.');
    }
    this.#clock = value;
    return value;
  }

  #ready() {
    if (this.#fault || this.#busy) fail(503, 'Remote policy is unavailable or changing.');
    if (!this.#enabled) fail(503, 'Remote access is disabled.');
  }

  enable() {
    if (this.#fault || this.#busy) fail(503, 'Remote policy is unavailable or changing.');
    this.#time();
    this.#enabled = true;
  }

  disable() {
    this.#enabled = false;
    this.#invalidate();
  }

  #invalidate() {
    for (const handle of this.#channels.keys()) this.disconnect(handle);
    this.#epoch = randomUUID();
    this.#history.clear();
  }

  #update(change) {
    if (this.#fault) fail(503, 'Remote policy storage failed. Reopen remote access locally.');
    this.#busy++;
    this.#invalidate();
    const write = this.#writes.then(async () => {
      if (this.#fault) fail(503, 'Remote policy storage failed.');
      const next = { ...this.#state, devices: change(this.#state.devices) };
      try {
        await this.#store.write(next);
      } catch (error) {
        this.#fault = true; this.disable();
        throw error;
      }
      this.#state = next;
    }).finally(() => { this.#busy--; });
    // Preserve serialization after rejection; the caller still receives the error.
    this.#writes = write.then(() => undefined, () => undefined);
    return write;
  }

  async approveDevice(device) {
    if (!validDevice(device)) fail(400, 'Invalid remote device identity.');
    const approved = Object.freeze({ ...device });
    return this.#update(devices => {
      const remaining = devices.filter(item => item.deviceID !== approved.deviceID);
      if (remaining.length >= 8) fail(429, 'Remote device limit reached.');
      return [...remaining, approved];
    });
  }

  async revokeDevice(deviceID) {
    if (!text(deviceID)) fail(400, 'Invalid remote device identity.');
    return this.#update(devices => devices.filter(device => device.deviceID !== deviceID));
  }

  connect(peer, leaseMs) {
    this.#ready();
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0 || leaseMs > 30000)
      fail(400, 'Remote authorization lifetime must be between 1 and 30000 milliseconds.');
    if (!shape(peer, [...ownerFields, ...deviceFields]) || !sameOwner(peer, this.#owner) ||
      !this.#state.devices.some(device => device.deviceID === peer.deviceID && device.keyHash === peer.keyHash))
      fail(403, 'Remote device is not authorized.');
    const now = this.#time();
    for (const [handle, channel] of this.#channels) if (channel.expires <= now) this.disconnect(handle);
    if (this.#channels.size >= 48) fail(429, 'Remote connection limit reached.');
    const controller = new AbortController();
    const handle = Object.freeze({ epoch: this.#epoch, signal: controller.signal });
    const timer = setTimeout(() => this.disconnect(handle), leaseMs);
    timer.unref();
    this.#channels.set(handle, { peer: Object.freeze({ ...peer }), expires: now + leaseMs, controller, timer });
    return handle;
  }

  authorize(handle) {
    const channel = this.#channels.get(handle);
    if (!channel) fail(403, 'Remote channel is closed or unknown.');
    this.#ready();
    if (this.#time() >= channel.expires) {
      this.disconnect(handle);
      fail(403, 'Remote channel authorization expired.');
    }
    return channel.peer;
  }

  // Only a freshly verified, bound service proof may extend this live handle.
  renew(handle, leaseMs) {
    if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0 || leaseMs > 30000)
      fail(400, 'Remote authorization lifetime must be between 1 and 30000 milliseconds.');
    this.authorize(handle);
    const channel = this.#channels.get(handle);
    channel.expires = this.#clock + leaseMs;
    clearTimeout(channel.timer);
    channel.timer = setTimeout(() => this.disconnect(handle), leaseMs);
    channel.timer.unref();
  }

  disconnect(handle) {
    const channel = this.#channels.get(handle);
    if (!channel) return;
    this.#channels.delete(handle);
    clearTimeout(channel.timer);
    channel.controller.abort();
  }

  async dispatch(handle, command, send) {
    const peer = this.authorize(handle);
    if (!shape(command, ['id', 'epoch', 'payload']) ||
      typeof command.id !== 'string' || !/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(command.id) ||
      !Buffer.isBuffer(command.payload) || command.payload.length === 0 || command.payload.length > 131072 ||
      typeof send !== 'function') fail(400, 'Invalid remote command envelope.');
    if (command.epoch !== this.#epoch) fail(409, 'Remote command belongs to an expired epoch.');
    const payload = Buffer.from(command.payload);
    let off = false;
    try { off = isPolicyOffRPC(command.id, JSON.parse(payload)); } catch {}
    if (isOffID(command.id) && !off) fail(400, 'Off UUIDs cannot identify other remote work.');
    const key = `${peer.deviceID}\0${command.id.toLowerCase()}`;
    const digest = createHash('sha256').update(payload).digest('hex');
    const existing = this.#history.get(key) ?? [...this.#pending].find(record => record.offKey === key)?.digest;
    if (existing !== undefined) fail(409, existing === digest
      ? 'Remote command already dispatched; its outcome may be unknown. Do not resend.'
      : 'Remote command UUID was reused with different content.');
    if ((!off && this.#history.size >= 256) || this.#pending.size >= (off ? 9 : 8)) {
      if (off) return { status: 429, data: { notDispatched: true, error: 'Too many remote commands await acknowledgment.' } };
      fail(429, 'Remote command safety history or pending limit reached.');
    }
    this.authorize(handle);
    const reservation = { offKey: off ? key : undefined, digest };
    // Only epoch-bound Off delegates replay admission to Workspace's bounded native-authority ledger.
    // Ordinary UUID history is never evicted; malformed/repurposed Off IDs cannot enter this lane.
    if (!off) this.#history.set(key, digest);
    this.#pending.add(reservation);
    try {
      // No await between final authorization/reservation and dispatch invocation.
      // Native target, capability, request and audit checks remain mandatory.
      return await send(payload);
    } finally {
      this.#pending.delete(reservation);
    }
  }
}
