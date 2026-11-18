import { createRemoteCompanion } from './remote-companion.mjs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
process.umask(0o077);
let companion, buffer = Buffer.alloc(0), queue = Promise.resolve(), queued = 0, stopping = false;
const emit = event => {
  if (stopping) return;
  if (process.stdout.writableLength > 2_097_152) { void stop(1); return; }
  if (!process.stdout.write(`${JSON.stringify(event)}\n`)) process.stdin.pause();
};
const report = error => emit({ type: 'error', message: String(error?.message ?? 'Internet helper failed.').slice(0, 500) });
async function stop(code = 0) {
  if (stopping) return;
  stopping = true; process.stdin.pause();
  await companion?.close();
  process.exitCode = code;
  process.stdin.destroy();
}
process.stdout.on('drain', () => { if (!stopping) process.stdin.resume(); });
process.stdin.on('data', chunk => {
  if (stopping) return;
  buffer = Buffer.concat([buffer, chunk]);
  let end;
  while ((end = buffer.indexOf(10)) >= 0) {
    if (end > 1048576 || ++queued > 16) {
      report(new Error('Internet native command limit exceeded. No actions were retried.'));
      void stop(1); return;
    }
    const line = buffer.subarray(0, end); buffer = buffer.subarray(end + 1);
    queue = queue.then(async () => {
      if (stopping) return;
      const command = JSON.parse(line.toString('utf8'));
      if (command?.type === 'start') {
        if (companion || typeof command.directory !== 'string' || typeof command.origin !== 'string')
          throw new Error('Invalid or duplicate internet start command.');
        companion = await createRemoteCompanion({ directory: command.directory, origin: command.origin, emit });
        if (stopping) await companion.close();
        else void companion.prepareInvitation();
      } else if (command?.type === 'stop') await stop();
      else {
        if (!companion) throw new Error('Start internet access locally first.');
        await companion.command(command);
      }
    }).catch(async error => { report(error); await stop(1); }).finally(() => { queued--; });
  }
  if (buffer.length > 1048576) { report(new Error('Internet native command is too large.')); void stop(1); }
});
process.stdin.on('end', () => {
  if (buffer.length) { report(new Error('Incomplete internet command.')); void stop(1); }
  else void queue.then(() => stop());
});
process.stdin.on('error', () => { void stop(1); });
process.stdout.on('error', () => { void stop(1); });
process.on('SIGTERM', () => { void stop(); });
process.on('SIGINT', () => { void stop(); });
process.on('uncaughtException', () => { report(new Error('Internet helper failed and stopped.')); void stop(1); });
process.on('unhandledRejection', () => { report(new Error('Internet helper failed and stopped.')); void stop(1); });
