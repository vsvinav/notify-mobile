import { createCompanion } from './server.mjs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
process.umask(0o077);
let companion, buffer = Buffer.alloc(0), queue = Promise.resolve(), stopping = false;
const emit = event => {
  if (!process.stdout.write(`${JSON.stringify(event)}\n`)) process.stdin.pause();
};
process.stdout.on('drain', () => { if (!stopping) process.stdin.resume(); });
const error = message => emit({ type: 'error', message: message.slice(0, 500) });
async function stop(code = 0) {
  if (stopping) return;
  stopping = true; process.stdin.pause();
  await companion?.close();
  process.exitCode = code;
  process.stdin.destroy();
}
let queued = 0;
process.stdin.on('data', chunk => {
  buffer = Buffer.concat([buffer, chunk]);
  while (true) {
    const end = buffer.indexOf(10);
    if (end < 0) break;
    if (end > 1048576) {
      error('Mobile protocol line exceeds 1 MiB. Mobile has been stopped; no request fields were truncated.');
      void stop(1); return;
    }
    const line = buffer.subarray(0, end);
    buffer = buffer.subarray(end + 1);
    if (++queued > 16) {
      error('Too many queued native mobile commands. Mobile has been stopped.');
      void stop(1); return;
    }
    queue = queue.then(async () => {
      if (stopping) return;
      let command;
      try { command = JSON.parse(line.toString('utf8')); }
      catch { throw new Error('Invalid native mobile JSON command.'); }
      if (command?.type === 'start') {
        if (companion) throw new Error('Mobile is already started.');
        if (typeof command.directory !== 'string') throw new Error('Mobile start requires a private data directory.');
        companion = await createCompanion({ directory: command.directory, emit });
        if (stopping) await companion.close();
      } else if (command?.type === 'stop') {
        await stop();
      } else {
        if (!companion) throw new Error('Start the mobile companion before sending commands.');
        await companion.command(command);
      }
    }).catch(async failure => {
      error(failure.message || 'Mobile companion failed.');
      if (!companion) await stop(1);
    }).finally(() => { queued--; });
  }
  if (buffer.length > 1048576) {
    error('Mobile protocol line exceeds 1 MiB. Mobile has been stopped.');
    void stop(1);
  }
});
process.stdin.on('end', () => {
  if (buffer.length) {
    error('Native mobile pipe ended with an incomplete JSON line.');
    void stop(1);
  } else {
    void queue.then(() => stop());
  }
});
process.stdin.on('error', () => { void stop(1); });
process.stdout.on('error', () => { void stop(1); });
process.on('SIGTERM', () => { void stop(); });
process.on('SIGINT', () => { void stop(); });
process.on('uncaughtException', () => { error('Mobile helper failed unexpectedly and has stopped. Disable and enable mobile on the Mac.'); void stop(1); });
process.on('unhandledRejection', () => { error('Mobile helper failed unexpectedly and has stopped. Disable and enable mobile on the Mac.'); void stop(1); });
