import { readPanel, panelAction } from './panel-provider.mjs';
import { object } from './validation.mjs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
process.umask(0o077);
process.stdout.on('error', () => { process.exitCode = 1; });

const invalid = () => Object.assign(new Error(), { status: 400 });

async function run() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 4096) throw invalid();
    chunks.push(chunk);
  }
  let command;
  try {
    command = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch { throw invalid(); }
  if (!object(command)) throw invalid();
  const keys = Object.keys(command);
  if (command.type === 'read' && keys.length === 1) return readPanel();
  if (command.type === 'action' && keys.length === 2 && Object.hasOwn(command, 'input'))
    return panelAction(command.input);
  throw invalid();
}

let response;
try { response = await run(); }
catch (error) {
  const status = error?.status === 400 ? 400 : 500;
  response = { status, data: { ok: false, error: status === 400 ? 'Invalid panel request.' : 'Panel helper failed.' } };
}
try { process.stdout.end(`${JSON.stringify(response)}\n`); }
catch { process.exitCode = 1; }
