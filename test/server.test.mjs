import test from 'node:test';
import assert from 'node:assert/strict';
import { stat, readFile, writeFile, symlink } from 'node:fs/promises';
import { fixture, pair, permission, question } from './fixtures.mjs';
import { validPushEndpoint, genericPayload, publicPushAddress } from '../src/push.mjs';
import { privateIPv4, sameSubnet } from '../src/network.mjs';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createCompanion } from '../src/server.mjs';
import { certificates } from '../src/certificates.mjs';

test('pairing requires comparison confirmation and consumes a single expiring invitation', async t => {
  const f = await fixture(); t.after(f.close);
  await f.app.command({ type: 'invite' });
  const code = f.events.at(-1).status.pairingCode;
  const pending = await f.call('/api/pair', { code, name: 'My iPhone' });
  assert.equal(pending.status, 202);
  assert.match(pending.headers['set-cookie'][0], /Secure; HttpOnly; SameSite=Strict/);
  assert.equal((await f.call('/api/state', {}, { cookie: pending.cookie })).status, 401);
  assert.equal((await f.call('/api/pair', { code, name: 'Another' })).status, 403);
  const event = f.events.findLast(e => e.type === 'pairing');
  assert.match(event.code, /^\d{6}$/);
  assert.equal(pending.data.code, event.code);
  assert.equal((await f.call('/api/pair-status', {}, { cookie: pending.cookie })).data.state, 'pending');
  await f.app.command({ type: 'pair', id: event.id, allow: true });
  const accepted = await f.call('/api/pair-status', {}, { cookie: pending.cookie });
  assert.equal(accepted.status, 200);
  assert.equal((await f.call('/api/state', {}, { cookie: accepted.cookie })).status, 200);
  assert.equal((await stat(f.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(`${f.directory}/state.json`)).mode & 0o777, 0o600);
});

test('pending comparison survives consumed invite and emits authoritative clear on expiry', async t => {
  let clock = Date.now();
  const f = await fixture({ now: () => clock }); t.after(f.close);
  await f.app.command({ type: 'invite' });
  const code = f.events.at(-1).status.pairingCode;
  const pending = await f.call('/api/pair', { code, name: 'Pending phone' });
  const id = f.events.findLast(e => e.type === 'pairing').id;
  const consumed = f.events.findLast(e => e.type === 'status').status;
  assert.equal(consumed.pairingCode, undefined);
  assert.deepEqual(consumed.pendingPairingIDs, [id]);
  await f.app.command({ type: 'snapshot', requests: [], total: 0 });
  assert.deepEqual(f.events.findLast(e => e.type === 'status').status.pendingPairingIDs, [id]);
  await f.app.command({ type: 'offline' });
  const eventCount = f.events.length;
  clock += 180001;
  // The real server timer must emit a clear without another native command.
  await new Promise(resolve => setTimeout(resolve, 1100));
  const expired = f.events.slice(eventCount).filter(e => e.type === 'status').at(-1);
  assert.ok(expired, 'expiry must emit an unsolicited status update');
  assert.deepEqual(expired.status.pendingPairingIDs, []);
  assert.equal((await f.call('/api/pair-status', {}, { cookie: pending.cookie })).status, 401);
  await assert.rejects(f.app.command({ type: 'pair', id, allow: true }), /expired/);
});

test('accepting or rejecting a comparison clears only that pending ID', async t => {
  const f = await fixture(); t.after(f.close);
  const ids = [];
  for (const name of ['Accepted phone', 'Declined phone']) {
    await f.app.command({ type: 'invite' });
    const code = f.events.at(-1).status.pairingCode;
    await f.call('/api/pair', { code, name });
    ids.push(f.events.findLast(e => e.type === 'pairing').id);
  }
  assert.deepEqual(f.events.findLast(e => e.type === 'status').status.pendingPairingIDs, ids);
  await f.app.command({ type: 'pair', id: ids[0], allow: true });
  assert.deepEqual(f.events.findLast(e => e.type === 'status').status.pendingPairingIDs, [ids[1]]);
  await f.app.command({ type: 'pair', id: ids[1], allow: false });
  assert.deepEqual(f.events.findLast(e => e.type === 'status').status.pendingPairingIDs, []);
});

test('HTTPS authentication, origin, host, content type, body limits and bootstrap isolation', async t => {
  const f = await fixture(); t.after(f.close);
  const { cookie } = await pair(f);
  assert.equal((await f.call('/api/state')).status, 401);
  assert.equal((await f.call('/api/state', {}, { cookie, origin: 'https://evil.example' })).status, 403);
  assert.equal((await f.call('/api/state', {}, { cookie, origin: '' })).status, 403);
  assert.equal((await f.call('/api/state', {}, { cookie, host: 'evil.example' })).status, 403);
  assert.equal((await f.call('/api/state', {}, { cookie, type: 'text/plain' })).status, 415);
  assert.equal((await f.call('/api/state', {}, { cookie, raw: '{' })).status, 400);
  assert.equal((await f.call('/api/reply', {}, { cookie, raw: 'x'.repeat(131073) })).status, 413);
  assert.equal((await f.call('/no-route', {}, { cookie })).status, 404);
  assert.equal((await fetch(`${f.app.setupURL}/api/state`)).status, 404);
  const setup = await (await fetch(f.app.setupURL)).text();
  assert.match(setup, /fingerprint/i);
  assert.doesNotMatch(setup, /ticket-1|pairingCode|PRIVATE KEY/);
});

test('native acknowledgment is required; in-flight and completed duplicate replies are rejected', async t => {
  const f = await fixture(); t.after(f.close);
  const { cookie } = await pair(f);
  const item = permission();
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const reply = { sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision: 'allow', answers: {} };
  let settled = false;
  const pending = f.call('/api/reply', reply, { cookie }).then(r => { settled = true; return r; });
  await new Promise(r => setTimeout(r, 40));
  assert.equal(settled, false);
  const command = f.events.findLast(e => e.type === 'reply');
  assert.equal(command.permissionOptionID, undefined);
  assert.equal((await f.call('/api/reply', reply, { cookie })).status, 409);
  await f.app.command({ type: 'result', id: 'wrong', ok: true });
  assert.equal(settled, false);
  await f.app.command({ type: 'result', id: command.id, ok: true });
  assert.equal((await pending).status, 200);
  assert.equal((await f.call('/api/reply', reply, { cookie })).status, 409);
  const persisted = await readFile(`${f.directory}/state.json`, 'utf8');
  assert.doesNotMatch(persisted, /Website release|preview\.example|ticket-1|request-1/);
});

test('fixed choices, freeform, scopes, feedback and freshness match offered request', async t => {
  const f = await fixture(); t.after(f.close);
  const { cookie } = await pair(f);
  let item = question(false);
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const reply = { sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision: 'answer',
    answers: { targets: ['iPhone'], instructions: ['invented'] } };
  assert.equal((await f.call('/api/reply', reply, { cookie })).status, 400);
  item = question(true);
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const pending = f.call('/api/reply', reply, { cookie });
  await new Promise(r => setTimeout(r, 30));
  const event = f.events.findLast(e => e.type === 'reply');
  assert.deepEqual(event.answers.instructions, ['invented']);
  await f.app.command({ type: 'result', id: event.id, ok: false, error: 'Agent disconnected' });
  assert.equal((await pending).status, 502);
  item = permission('new-ticket');
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const scoped = { ...reply, requestID: item.request.id, ticket: item.ticket, decision: 'allow', answers: {}, permissionOptionID: 'invented' };
  assert.equal((await f.call('/api/reply', scoped, { cookie })).status, 400);
  const valid = f.call('/api/reply', { ...scoped, permissionOptionID: 'once-tool' }, { cookie });
  await new Promise(r => setTimeout(r, 30));
  const allowed = f.events.findLast(e => e.type === 'reply');
  assert.equal(allowed.permissionOptionID, 'once-tool');
  await f.app.command({ type: 'result', id: allowed.id, ok: true });
  assert.equal((await valid).status, 200);
  await f.app.command({ type: 'offline' });
  assert.equal((await f.call('/api/reply', scoped, { cookie })).status, 503);
});

test('revocation invalidates credentials and pending acknowledgments', async t => {
  const f = await fixture(); t.after(f.close);
  const { cookie, id } = await pair(f);
  const item = permission();
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const pending = f.call('/api/reply', { sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision: 'deny', answers: {} }, { cookie });
  await new Promise(r => setTimeout(r, 30));
  await f.app.command({ type: 'revoke', id });
  assert.equal((await pending).status, 401);
  assert.equal((await f.call('/api/state', {}, { cookie })).status, 401);
  assert.deepEqual(f.events.findLast(e => e.type === 'status').status.devices, []);
});

test('push endpoints are provider-only HTTPS and payload has no request content', () => {
  for (const endpoint of [
    'https://web.push.apple.com/QH123', 'https://fcm.googleapis.com/fcm/send/token',
    'https://updates.push.services.mozilla.com/wpush/v2/token'
  ]) assert.equal(validPushEndpoint(endpoint), true, endpoint);
  for (const endpoint of [
    'http://fcm.googleapis.com/fcm/send/x', 'https://fcm.googleapis.com.evil.test/x',
    'https://evil@fcm.googleapis.com/x', 'https://127.0.0.1/x', 'https://fcm.googleapis.com:444/x',
    'https://api.apple.com/x', 'https://google.com/x', 'https://web.push.apple.com/x#fragment',
    'https://fcm.googleapis.com/x?next=https://evil.test', 'https://web.push.apple.com./x'
  ]) assert.equal(validPushEndpoint(endpoint), false, endpoint);
  assert.deepEqual(JSON.parse(genericPayload), { title: 'Notify', body: 'Notify needs you. Open the app to review on your local network.', tag: 'notify-attention', url: '/' });
});

test('push DNS rejects non-public IPv4 ranges including carrier NAT and metadata services', () => {
  for (const ip of ['127.0.0.1', '169.254.169.254', '10.0.0.3', '100.64.0.1', '100.65.2.3', '100.127.255.1',
    '192.0.2.10', '198.18.0.1', '198.51.100.7', '203.0.113.3', '224.0.0.1', '::1', '::ffff:127.0.0.1']) {
    assert.equal(publicPushAddress(ip), false, ip);
  }
  assert.equal(publicPushAddress('142.250.1.1'), true);
});

test('subscription errors surface; expired subscriptions are removed; dedup stores only hashes', async t => {
  const sent = [];
  const f = await fixture({ pushSend: async (subscription, payload) => { sent.push({ subscription, payload }); } });
  t.after(f.close);
  const { cookie } = await pair(f);
  const subscription = { endpoint: 'https://web.push.apple.com/test', keys: { p256dh: 'B' + 'a'.repeat(86), auth: 'a'.repeat(22) } };
  assert.equal((await f.call('/api/push', { subscription }, { cookie })).status, 200);
  await f.app.command({ type: 'snapshot', requests: [permission()], total: 1 });
  await f.app.flushPush();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].payload, genericPayload);
  await f.app.command({ type: 'snapshot', requests: [permission()], total: 1 });
  await f.app.flushPush();
  assert.equal(sent.length, 1);
  await f.app.command({ type: 'test-push' });
  await f.app.flushPush();
  assert.equal(sent.length, 2);
  assert.equal((await f.call('/api/push', { subscription: { ...subscription, endpoint: 'https://evil.test/' } }, { cookie })).status, 400);
  const disk = JSON.parse(await readFile(`${f.directory}/state.json`, 'utf8'));
  assert.match(disk.seen[0], /^[a-f0-9]{64}$/);
});

test('invitation expiry, pair rejection, rate limiting and bounded devices are explicit', async t => {
  let clock = Date.now();
  const f = await fixture({ now: () => clock }); t.after(f.close);
  await f.app.command({ type: 'invite' });
  let code = f.events.at(-1).status.pairingCode;
  await f.app.command({ type: 'snapshot', requests: [], total: 0 });
  assert.equal(f.events.findLast(e => e.type === 'status').status.pairingCode, code);
  clock += 180001;
  assert.equal((await f.call('/api/pair', { code, name: 'Phone' })).status, 403);
  await f.app.command({ type: 'invite' });
  code = f.events.at(-1).status.pairingCode;
  const pending = await f.call('/api/pair', { code, name: 'Phone' });
  await f.app.command({ type: 'pair', id: f.events.findLast(e => e.type === 'pairing').id, allow: false });
  assert.equal((await f.call('/api/pair-status', {}, { cookie: pending.cookie })).data.state, 'denied');
  for (let i = 0; i < 4; i++) await f.call('/api/pair', { code: '00000000', name: 'Phone' });
  assert.equal((await f.call('/api/pair', { code, name: 'Phone' })).status, 429);
  clock += 180001;
  for (let i = 0; i < 8; i++) { await pair(f); clock += 180001; }
  await assert.rejects(f.app.command({ type: 'invite' }), /Eight phones/);
  assert.equal((await f.call('/api/pair', { code: '00000000', name: 'Ninth' })).status, 409);
});

test('expired native snapshot, changed tickets, feedback and native timeout fail closed', async t => {
  let clock = Date.now();
  const f = await fixture({ now: () => clock, ackTimeout: 80 }); t.after(f.close);
  const { cookie } = await pair(f);
  const item = permission();
  const reply = { sessionID: item.sessionID, requestID: item.request.id, ticket: item.ticket, decision: 'deny', answers: {} };
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  assert.equal((await f.call('/api/reply', { ...reply, feedback: '   ' }, { cookie })).status, 400);
  assert.equal((await f.call('/api/reply', { ...reply, ticket: 'old-ticket' }, { cookie })).status, 409);
  clock += 12001;
  assert.equal((await f.call('/api/state', {}, { cookie })).data.connected, false);
  assert.equal((await f.call('/api/reply', reply, { cookie })).status, 503);
  await f.app.command({ type: 'snapshot', requests: [item], total: 1 });
  const pending = f.call('/api/reply', { ...reply, feedback: 'Do not run this command.' }, { cookie });
  const timedOut = await pending;
  assert.equal(timedOut.status, 504);
  assert.equal(f.events.findLast(e => e.type === 'reply').feedback, 'Do not run this command.');
  assert.equal((await f.call('/api/reply', reply, { cookie })).status, 409);
  await assert.rejects(f.app.command({ type: 'snapshot', requests: [{ ...item, fields: [{ ...item.fields[0], value: 'x'.repeat(1048576) }] }], total: 1 }), /snapshot/);
  assert.equal((await f.call('/api/state', {}, { cookie })).data.connected, false);
});

test('push provider failures are visible and expired subscriptions are removed', async t => {
  let failure = 500;
  const f = await fixture({ pushSend: async () => { throw Object.assign(new Error('secret provider response'), { statusCode: failure }); } });
  t.after(f.close);
  const { cookie, id } = await pair(f);
  const subscription = { endpoint: 'https://fcm.googleapis.com/fcm/send/disposable', keys: { p256dh: 'B' + 'a'.repeat(86), auth: 'a'.repeat(22) } };
  await f.call('/api/push', { subscription }, { cookie });
  await f.app.command({ type: 'test-push' }); await f.app.flushPush();
  assert.match(f.events.findLast(e => e.type === 'status').status.pushMessage, /could not reach/);
  assert.equal((await f.call('/api/state', {}, { cookie })).data.pushEnabled, true);
  failure = 410;
  await f.app.command({ type: 'test-push' }); await f.app.flushPush();
  assert.equal((await f.call('/api/state', {}, { cookie })).data.pushEnabled, false);
  assert.match(f.events.findLast(e => e.type === 'status').status.pushMessage, /expired/);
  assert.doesNotMatch(JSON.stringify(f.events), /secret provider response|disposable/);
  await f.call('/api/push', { subscription }, { cookie });
  await f.app.command({ type: 'revoke', id });
  const disk = await readFile(`${f.directory}/state.json`, 'utf8');
  assert.doesNotMatch(disk, /disposable/);
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '1');
});

test('only private IPv4 and same-subnet peers are eligible', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.1', '192.168.1.3']) assert.equal(privateIPv4(ip), true);
  for (const ip of ['127.0.0.1', '0.0.0.0', '172.32.0.1', '8.8.8.8', '192.168.999.1']) assert.equal(privateIPv4(ip), false);
  const network = { address: '192.168.1.3', netmask: '255.255.255.0' };
  assert.equal(sameSubnet('192.168.1.5', network), true);
  assert.equal(sameSubnet('192.168.2.5', network), false);
  assert.equal(sameSubnet('::ffff:192.168.1.5', network), false);
});

test('protocol rejects malformed or oversized lines without leaking stdin or hanging', async () => {
  for (const input of ['not-json-secret\n', '{"type":"start"', `${'x'.repeat(1048577)}\n`]) {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['src/main.mjs'], { env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.on('error', reject);
      child.stdin.on('error', error => { if (error.code !== 'EPIPE') reject(error); });
      child.on('exit', code => resolve({ code, stdout, stderr }));
      child.stdin.end(input);
    });
    assert.equal(result.code, 1);
    const events = result.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.equal(events[0].type, 'error');
    assert.doesNotMatch(result.stdout, /not-json-secret/);
    assert.equal(result.stderr, '');
  }
});

test('notification hashes and device cookies survive a restart without replaying push alerts', async t => {
  let sent = 0;
  const f = await fixture({ pushSend: async () => { sent++; } }); t.after(f.close);
  const { cookie } = await pair(f);
  await f.call('/api/push', { subscription: { endpoint: 'https://web.push.apple.com/synthetic',
    keys: { p256dh: 'B' + 'a'.repeat(86), auth: 'a'.repeat(22) } } }, { cookie });
  await f.app.command({ type: 'snapshot', requests: [permission()], total: 1 }); await f.app.flushPush();
  assert.equal(sent, 1);
  await f.app.close();
  const restarted = await createCompanion({ directory: f.directory, emit: () => {},
    network: { address: '127.0.0.1', netmask: '255.0.0.0' }, testOnlyLoopback: true, httpsPort: 0, httpPort: 0,
    pushSend: async () => { sent++; } });
  t.after(() => restarted.close());
  await restarted.command({ type: 'snapshot', requests: [permission()], total: 1 }); await restarted.flushPush();
  assert.equal(sent, 1);
  const { call } = await import('./fixtures.mjs');
  assert.equal((await call(restarted.url, restarted.ca, '/api/state', {}, { cookie })).status, 200);
  for (const name of ['ca.pem', 'ca-key.pem', 'server.pem', 'server-key.pem', 'state.json']) {
    assert.equal((await stat(`${f.directory}/${name}`)).mode & 0o777, 0o600);
  }
});

test('certificate renewal refuses symbolic-link key destinations', async t => {
  const f = await fixture(); t.after(f.close);
  await f.app.close();
  const { unlink } = await import('node:fs/promises');
  await unlink(`${f.directory}/server.pem`);
  await unlink(`${f.directory}/server-key.pem`);
  const protectedFile = `${f.directory}/do-not-overwrite`;
  await writeFile(protectedFile, 'protected fixture', { mode: 0o600 });
  await symlink(protectedFile, `${f.directory}/server-key.pem`);
  await assert.rejects(certificates(f.directory, '127.0.0.1', true));
  assert.equal(await readFile(protectedFile, 'utf8'), 'protected fixture');
});

test('generated CA name constraints reject a public DNS identity', async t => {
  const f = await fixture(); t.after(f.close);
  const run = promisify(execFile);
  const extension = `${f.directory}/public-test.cnf`, certificate = `${f.directory}/public-test.pem`;
  await writeFile(extension, '[server]\nbasicConstraints=critical,CA:false\nsubjectAltName=DNS:example.com\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  const options = { env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '1' } };
  await run('/usr/bin/openssl', ['x509', '-req', '-in', `${f.directory}/server.csr`,
    '-CA', `${f.directory}/ca.pem`, '-CAkey', `${f.directory}/ca-key.pem`,
    '-set_serial', '11', '-days', '1', '-extfile', extension, '-extensions', 'server', '-out', certificate], options);
  await assert.rejects(
    run('/usr/bin/openssl', ['verify', '-CAfile', `${f.directory}/ca.pem`, certificate], options),
    error => /permitted subtree violation/i.test(`${error.stdout} ${error.stderr}`)
  );
});
