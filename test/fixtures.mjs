import https from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { mkdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createCompanion } from '../src/server.mjs';

export const permission = (ticket = 'ticket-1') => ({
  sessionID: 'session-1', sessionName: 'Website release', project: 'notify', agent: 'Claude',
  color: '#70d6c4', ticket, notificationID: 'notification-1',
  request: { id: 'request-1', kind: 'permission', title: 'Open the release preview?',
    detail: 'Review this exact destination before allowing access.', autoEligible: false,
    questions: [], permissionOptions: [{ id: 'once-tool', label: 'Allow this tool', detail: 'For this session only' }],
    supportsFeedback: true },
  fields: [
    { id: 0, label: 'Destination', value: 'https://preview.example.com/releases/notify?version=2026-11-14', presentation: 'code', target: 'URL' },
    { id: 1, label: 'Before you continue', value: 'This action opens an external website.', presentation: 'warning' }
  ], sending: false
});

export const question = (freeform = true) => ({
  ...permission('question-ticket'), notificationID: 'question-notification',
  request: { id: 'question-1', kind: 'question', title: 'How should we ship this?',
    detail: 'Choose the release targets and leave instructions.', autoEligible: false,
    questions: [
      { id: 'targets', text: 'Release targets', multiple: true, allowFreeform: false, minimumSelections: 1,
        options: [{ label: 'iPhone', description: 'Installed on the Home Screen' }, { label: 'Android', description: 'Installed web app' }] },
      { id: 'instructions', text: 'Release instructions', multiple: false, allowFreeform: freeform,
        options: [{ label: 'Stage first', description: 'Review before publishing' }, { label: 'Ship now', description: 'Publish immediately' }] }
    ] }, fields: []
});

export async function fixture(options = {}) {
  const directory = `${process.cwd()}/.test-data/${randomUUID()}`;
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const events = [];
  const app = await createCompanion({
    directory, emit: event => events.push(event),
    network: { address: '127.0.0.1', netmask: '255.0.0.0' }, testOnlyLoopback: true,
    httpsPort: 0, httpPort: 0, ...options
  });
  return {
    app, events, directory,
    call: (route, body = {}, opts = {}) => call(app.url, app.ca, route, body, opts),
    close: async () => { await app.close(); await rm(directory, { recursive: true, force: true }); }
  };
}

export function call(base, ca, route, body = {}, { cookie, origin = base, host, raw, type = 'application/json', method = 'POST' } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(route, base);
    const headers = { 'content-type': type, origin, ...(cookie ? { cookie } : {}), ...(host ? { host } : {}) };
    const request = https.request(url, { ca, method, headers, rejectUnauthorized: true,
      checkServerIdentity: (_name, cert) => checkServerIdentity(url.hostname, cert) }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        let data;
        try { data = JSON.parse(text); } catch { data = text; }
        resolve({ status: response.statusCode, data, cookie: response.headers['set-cookie']?.[0]?.split(';')[0], headers: response.headers });
      });
    });
    request.on('error', reject);
    request.end(raw ?? (method === 'GET' ? undefined : JSON.stringify(body)));
  });
}

export async function pair(f) {
  await f.app.command({ type: 'invite' });
  const invite = f.events.filter(e => e.type === 'status').at(-1).status.pairingCode;
  const pending = await f.call('/api/pair', { code: invite, name: 'Test phone' });
  const pairing = f.events.findLast(e => e.type === 'pairing');
  await f.app.command({ type: 'pair', id: pairing.id, allow: true });
  const ready = await f.call('/api/pair-status', {}, { cookie: pending.cookie });
  return { cookie: ready.cookie, id: ready.data.device.id };
}
