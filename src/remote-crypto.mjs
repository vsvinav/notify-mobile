import { spawn } from 'node:child_process';

const LIMIT = 5_242_880;

export class NativeCrypto {
  #child; #queue = []; #buffer = Buffer.alloc(0); #error; #closed; #timer;
  constructor(executable, args) {
    this.#child = spawn(executable, args, {
      stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1' }
    });
    this.#closed = new Promise(resolve => {
      this.#child.once('close', () => { this.#fail(new Error('Native encrypted channel closed.')); resolve(); });
    });
    this.#child.on('error', () => this.#fail(new Error('Native encrypted channel could not start.')));
    this.#child.stdin.on('error', () => this.#fail(new Error('Native encrypted channel pipe closed.')));
    this.#child.stderr.on('data', () => this.#fail(new Error('Native signing identity is unavailable. Pair again from this Mac.')));
    this.#child.stdout.on('data', chunk => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      if (this.#buffer.length > LIMIT) return this.#fail(new Error('Native encrypted channel response is too large.'));
      let end;
      while ((end = this.#buffer.indexOf(10)) >= 0) {
        const line = this.#buffer.subarray(0, end);
        this.#buffer = this.#buffer.subarray(end + 1);
        const pending = this.#queue.shift();
        if (!pending) return this.#fail(new Error('Unexpected native encrypted channel response.'));
        clearTimeout(this.#timer);
        try {
          const value = JSON.parse(line.toString('utf8'));
          if (!value || typeof value !== 'object' || Object.keys(value).length !== 1)
            throw new Error('Invalid native encrypted channel response.');
          if (typeof value.error === 'string') pending.reject(new Error(value.error.slice(0, 500)));
          else if (Object.hasOwn(value, 'result')) pending.resolve(value.result);
          else throw new Error('Invalid native encrypted channel response.');
        } catch (error) {
          pending.reject(error); this.#fail(error); return;
        }
        this.#write();
      }
    });
  }
  #fail(error) {
    if (this.#error) return;
    this.#error = error;
    clearTimeout(this.#timer);
    for (const item of this.#queue.splice(0)) item.reject(error);
    this.#child.kill();
  }
  #write() {
    if (this.#error || !this.#queue.length) return;
    const item = this.#queue[0];
    if (item.sent) return;
    item.sent = true;
    this.#timer = setTimeout(() => this.#fail(new Error('Native encrypted channel timed out.')), 10000);
    this.#child.stdin.write(item.line, error => {
      if (error) this.#fail(new Error('Native encrypted channel pipe closed.'));
    });
  }
  get failed() { return this.#error !== undefined; }
  call(op, args = {}) {
    if (this.#error) return Promise.reject(this.#error);
    if (this.#queue.length >= 8) return Promise.reject(new Error('Native encrypted channel is busy.'));
    if (typeof op !== 'string' || Object.hasOwn(args, 'op'))
      return Promise.reject(new Error('Invalid native encrypted channel operation.'));
    const line = `${JSON.stringify({ op, ...args })}\n`;
    if (Buffer.byteLength(line) > LIMIT) return Promise.reject(new Error('Native encrypted channel command is too large.'));
    return new Promise((resolve, reject) => {
      this.#queue.push({ line, resolve, reject, sent: false });
      this.#write();
    });
  }
  async close() {
    this.#fail(new Error('Native encrypted channel closed.'));
    return this.#closed;
  }
}
