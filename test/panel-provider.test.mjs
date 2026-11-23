import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { RemoteActions } from '../src/remote-actions.mjs';
import { sanitizePanel } from '../src/panel-provider.mjs';

const token = 'T'.repeat(43);
const device = { id: 'phone', name: 'Synthetic', expires: 30000 };

async function provider(t, handle, { mode = 0o600, key = token } = {}) {
  const root = join(process.cwd(), '.test-data');
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'panel-'));
  const calls = [];
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    calls.push({ method: request.method, url: request.url, authorization: request.headers.authorization, body });
    if (request.headers.authorization !== `Bearer ${token}`) { response.writeHead(401).end('{"error":"no"}'); return; }
    const reply = await handle(request, body);
    if (request.socket.destroyed) return;
    const [status, value] = reply;
    response.writeHead(status, { 'Content-Type': 'application/json' }).end(typeof value === 'string' ? value : JSON.stringify(value));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const file = join(directory, 'panel.json');
  await writeFile(file, JSON.stringify({ version: 1, port: server.address().port, token: key, pid: process.pid, name: 'Synthetic' }), { mode });
  await chmod(file, mode);
  const previous = process.env.NOTIFY_PANEL_FILE;
  process.env.NOTIFY_PANEL_FILE = file;
  const actions = new RemoteActions({ emit() {}, devices: () => [device] });
  t.after(async () => {
    actions.close();
    if (previous === undefined) delete process.env.NOTIFY_PANEL_FILE; else process.env.NOTIFY_PANEL_FILE = previous;
    server.closeAllConnections(); server.close();
    await rm(directory, { recursive: true });
  });
  return { calls, file, request: (path, input = {}) => actions.request(path, input, device) };
}

async function runPanel(t, file, input, { closeStdout = false, beforeEnd } = {}) {
  const child = spawn(process.execPath, ['src/panel-main.mjs'], {
    cwd: process.cwd(), env: { NOTIFY_PANEL_FILE: file, NODE_TLS_REJECT_UNAUTHORIZED: '0' },
    stdio: ['pipe', 'pipe', 'pipe']
  });
  const stdout = [], stderr = [];
  let outputSize = 0, errorSize = 0;
  const result = new Promise((resolve, reject) => {
    const fail = error => { child.kill('SIGKILL'); reject(error); };
    const timeout = setTimeout(() => fail(new Error('Owned panel helper timed out')), 5000);
    child.once('error', fail);
    child.stdin.on('error', error => {
      if (!['EPIPE', 'ERR_STREAM_DESTROYED'].includes(error.code)) fail(error);
    });
    child.stdout.on('data', chunk => {
      outputSize += chunk.length;
      if (outputSize > 300 * 1024) { fail(new Error('Panel stdout exceeded limit')); return; }
      stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      errorSize += chunk.length;
      if (errorSize > 8192) { fail(new Error('Panel stderr exceeded limit')); return; }
      stderr.push(chunk);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() });
    });
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await result.catch(() => {});
  });
  if (closeStdout) child.stdout.destroy();
  child.stdin.write(typeof input === 'string' || Buffer.isBuffer(input) ? input : JSON.stringify(input));
  if (beforeEnd) await beforeEnd(child);
  child.stdin.end();
  const output = await result;
  assert.equal(output.signal, null);
  assert.equal(output.stderr, '');
  if (closeStdout) {
    assert.equal(output.code, 1);
    assert.equal(output.stdout, '');
    return;
  }
  assert.equal(output.code, 0);
  assert.match(output.stdout, /^[^\n]+\n$/);
  const response = JSON.parse(output.stdout);
  assert.deepEqual(Object.keys(response).sort(), ['data', 'status']);
  assert.equal(output.stdout.includes(token), false, 'Discovery bearer must not cross stdout');
  return response;
}

const item = (id, extra = {}) => ({ id, title: `Item ${id}`, tone: 'warn', ...extra });

test('stage tracks reference surviving items, preserve recent activity and never invent completion', () => {
  const track = { version: 1, title: 'Stages',
    stages: [{ id: 'plan', label: 'Plan', hint: 'Your decision', kind: 'decision', secret: 'drop' },
      { id: 'build', label: 'Build', kind: 'normal' }],
    placements: [{ itemId: 'example', stageId: 'build', secret: 'drop' }], secret: 'drop' };
  const feed = { version: 1, tabs: [{ id: 'work', label: 'Work', track,
    sections: [{ title: 'Needs attention', emphasis: 'attention', items: [item('example', {
      log: { entries: [{ at: '12:14', text: 'Work was reported.', secret: 'drop' }], secret: 'drop' }
    })] }] }] };
  const projected = sanitizePanel(feed).tabs[0];
  assert.deepEqual(projected.track, { version: 1, title: 'Stages',
    stages: [{ id: 'plan', label: 'Plan', hint: 'Your decision', kind: 'decision' }, { id: 'build', label: 'Build', kind: 'normal' }],
    placements: [{ itemId: 'example', stageId: 'build' }] });
  assert.equal(projected.sections[0].emphasis, 'attention');
  assert.deepEqual(projected.sections[0].items[0].log, { entries: [{ at: '12:14', text: 'Work was reported.' }], truncated: false });
  assert.equal(JSON.stringify(projected).includes('secret'), false);
  assert.equal(projected.track.stages[0].completed, undefined);
  for (const invalid of [
    { ...track, version: 2 },
    { ...track, stages: [...track.stages, track.stages[0]] },
    { ...track, stages: [{ ...track.stages[0], kind: 'completed' }] },
    { ...track, placements: [{ itemId: 'missing', stageId: 'build' }] },
    { ...track, placements: [{ itemId: 'example', stageId: 'missing' }] },
    { ...track, placements: [...track.placements, ...track.placements] },
    { ...track, placements: Array.from({ length: 61 }, () => track.placements[0]) }
  ]) {
    const result = sanitizePanel({ ...feed, tabs: [{ ...feed.tabs[0], track: invalid }] }).tabs[0];
    assert.equal(result.track, undefined);
    assert.equal(result.sections[0].items[0].id, 'example', 'Invalid presentation keeps generic fallback content');
  }
  const duplicate = structuredClone(feed);
  duplicate.tabs[0].sections[0].items.push(item('example'));
  assert.equal(sanitizePanel(duplicate).tabs[0].track, undefined);
});

test('activity projection labels omitted entries instead of pretending the log is complete', () => {
  const entries = [{ at: 'now', text: 'Keep this' }, { text: 'x'.repeat(1001) }, { text: 'bad\u0000text' },
    ...Array.from({ length: 8 }, (_, i) => ({ text: `Entry ${i}` }))];
  const feed = { version: 1, tabs: [{ id: 'work', label: 'Work', sections: [
    { title: '', items: [item('example', { log: { entries } })] }
  ] }] };
  const result = sanitizePanel(feed).tabs[0].sections[0].items[0].log;
  assert.equal(result.truncated, true);
  assert.deepEqual(result.entries.map(entry => entry.text), ['Keep this', 'Entry 0', 'Entry 1', 'Entry 2', 'Entry 3', 'Entry 4']);
});

test('optional text forms are projected as a whole without private provider configuration', async t => {
  const form = { version: 1, actionId: 'new-note', title: 'Add a todo', submitLabel: 'Research and draft',
    placeholder: 'Describe a feature', minLength: 5, maxLength: 300 };
  const p = await provider(t, async () => [200, { version: 1, tabs: [
    { id: 'notes', label: 'Notes', sections: [], form: { ...form, command: 'must not cross', token } }
  ] }]);
  const result = await p.request('panel');
  assert.deepEqual(result.data.panel.tabs[0].form, form);
  for (const invalid of [{ ...form, version: 2 }, { ...form, minLength: 301 }, { ...form, maxLength: 301 },
    { ...form, minLength: 0 }, { ...form, minLength: 6, maxLength: 5 }, { ...form, actionId: 'bad id' }]) {
    const projected = sanitizePanel({ version: 1, tabs: [{ id: 'notes', label: 'Notes', sections: [], form: invalid }] });
    assert.equal(projected.tabs[0].form, undefined);
  }
  assert.equal(JSON.stringify(result.data).includes(token), false);
});

test('form preview and send preserve exact bounded text and reject invalid input before IO', async t => {
  const confirmationToken = 'P'.repeat(43);
  const p = await provider(t, async () => [200, { ok: true, confirm: 'Exact generated instruction', confirmationToken }]);
  const text = 'A "fictional" feature\nwith  two spaces and Unicode \u{1f4dd}';
  await p.request('panel_action', { actionId: 'new-note', preview: true, text });
  await p.request('panel_action', { actionId: 'new-note', preview: false, text, confirmationToken });
  assert.deepEqual(p.calls.map(call => JSON.parse(call.body)), [
    { actionId: 'new-note', preview: true, text },
    { actionId: 'new-note', preview: false, text, confirmationToken }
  ]);
  for (const bad of ['', '   ', 'x'.repeat(301), 'hello\u0000world', 'hello\u007fworld', 'hello\u0085world', 42, {}]) {
    await assert.rejects(p.request('panel_action', { actionId: 'new-note', preview: true, text: bad }),
      error => error.status === 400);
  }
  assert.equal(p.calls.length, 2);
});

test('panel feed is re-serialised with only known fields and within limits', async t => {
  const feed = { version: 1, title: 'Synthetic', updatedAt: '2026-11-18T18:40:00.000Z', secret: 'drop',
    copilot: { connected: true, busy: false, extra: 1 },
    tabs: [
      { id: 'tunnel', label: 'Tunnel', badge: 2, hidden: true, sections: [{ title: 'Needs you', note: 'x', items: [
        item('a', { subtitle: 'Parked', url: 'https://example.invalid/a', extra: 'x', actions: [
          { id: 'approve:APA-1:main', label: 'Approve', style: 'primary', prompt: 'drop' },
          { id: 'bad id', label: 'Bad' }, { id: 'status:APA-1', label: 'L'.repeat(25) },
          ...Array.from({ length: 6 }, (_, i) => ({ id: `s:${i}`, label: 'S' }))] }),
        item('b', { url: 'http://insecure.invalid', tone: 'purple', badge: 5 }),
        { id: 'c', title: 'T'.repeat(141) },
        ...Array.from({ length: 70 }, (_, i) => item(`n${i}`))
      ] }] },
      { id: 'Bad', label: 'Upper' }, { id: 'tunnel', label: 'Duplicate' },
      ...Array.from({ length: 8 }, (_, i) => ({ id: `t${i}`, label: 'Tab', sections: [] }))
    ] };
  const p = await provider(t, async () => [200, feed]);
  const result = await p.request('panel');
  assert.equal(result.status, 200);
  assert.equal(result.data.available, true);
  const { panel } = result.data;
  assert.deepEqual(Object.keys(panel).sort(), ['copilot', 'tabs', 'title', 'updatedAt', 'version']);
  assert.deepEqual(panel.copilot, { connected: true, busy: false });
  assert.equal(panel.tabs.length, 6);
  assert.deepEqual(panel.tabs.map(tab => tab.id), ['tunnel', 't0', 't1', 't2', 't3', 't4']);
  const [tunnel] = panel.tabs;
  assert.deepEqual(Object.keys(tunnel).sort(), ['badge', 'id', 'label', 'sections']);
  assert.deepEqual(Object.keys(tunnel.sections[0]).sort(), ['items', 'title']);
  const items = tunnel.sections[0].items;
  assert.equal(items.length, 60);
  assert.equal(items.some(entry => entry.id === 'c'), false);
  assert.deepEqual(items[0], { id: 'a', title: 'Item a', subtitle: 'Parked', tone: 'warn', url: 'https://example.invalid/a',
    actions: [{ id: 'approve:APA-1:main', label: 'Approve', style: 'primary' },
      { id: 's:0', label: 'S' }, { id: 's:1', label: 'S' }, { id: 's:2', label: 'S' }] });
  assert.deepEqual(items[1], { id: 'b', title: 'Item b', tone: 'idle', actions: [] });
  assert.equal(p.calls[0].method, 'GET');
  assert.equal(p.calls[0].url, '/api/panel');
});

test('insecure discovery file is refused before contacting the provider', async t => {
  const p = await provider(t, async () => [200, { version: 1, tabs: [] }], { mode: 0o640 });
  const result = await p.request('panel');
  assert.deepEqual(result, { status: 200, data: { available: false, reason: 'Panel discovery file is insecure.' } });
  assert.equal(p.calls.length, 0);
});

test('rejected token and oversize feeds are unavailable without leaking the token', async t => {
  const wrong = await provider(t, async () => [200, { version: 1, tabs: [] }], { key: 'W'.repeat(43) });
  const rejected = await wrong.request('panel');
  assert.deepEqual(rejected, { status: 200, data: { available: false, reason: 'Panel provider rejected the request.' } });
  assert.equal(JSON.stringify(rejected).includes('W'.repeat(43)), false);
  const large = await provider(t, async () => [200, JSON.stringify({ version: 1, tabs: [], pad: 'x'.repeat(262144) })]);
  assert.deepEqual((await large.request('panel')).data, { available: false, reason: 'Panel feed is too large.' });
  await assert.rejects(large.request('panel', { extra: true }), /Invalid panel request/);
});

test('panel action forwards only the bound confirmation and whitelists the reply', async t => {
  const confirmationToken = 'P'.repeat(43);
  const p = await provider(t, async (request, body) => {
    const { preview } = JSON.parse(body);
    return preview
      ? [200, { ok: true, confirm: 'Approve APA-1 prompt', label: 'Approve APA-1', confirmationToken, prompt: 'hidden', token }]
      : [503, { ok: false, error: 'E'.repeat(1200), stack: 'hidden' }];
  });
  const preview = await p.request('panel_action', { actionId: 'approve:APA-1:main', preview: true });
  assert.deepEqual(preview, { status: 200, data: { ok: true, confirm: 'Approve APA-1 prompt', label: 'Approve APA-1', confirmationToken } });
  assert.deepEqual(JSON.parse(p.calls[0].body), { actionId: 'approve:APA-1:main', preview: true });
  assert.equal(p.calls[0].method, 'POST');
  assert.equal(p.calls[0].url, '/api/panel/action');
  const sent = await p.request('panel_action', { actionId: 'approve:APA-1:main', preview: false, confirmationToken });
  assert.deepEqual(JSON.parse(p.calls[1].body), { actionId: 'approve:APA-1:main', preview: false, confirmationToken });
  assert.equal(sent.status, 503);
  assert.deepEqual(Object.keys(sent.data).sort(), ['error', 'ok']);
  assert.equal(sent.data.error.length, 1000);
  for (const input of [{ actionId: 'bad id', preview: true }, { actionId: 'a'.repeat(129), preview: true },
    { actionId: 'status:APA-1', preview: 'yes' }, { actionId: 'status:APA-1', preview: true, extra: 1 },
    { actionId: 'status:APA-1', preview: false },
    { actionId: 'status:APA-1', preview: false, confirmationToken: 'short' },
    { actionId: 'status:APA-1', preview: true, confirmationToken }, {}])
    await assert.rejects(p.request('panel_action', input), error => error.status === 400);
  assert.equal(p.calls.length, 2);
});

test('one-shot helper waits for stdin EOF and returns only a sanitized read', async t => {
  const p = await provider(t, async () => [200, {
    version: 1, title: 'Synthetic', tabs: [], token, command: 'private', endpoint: 'private'
  }]);
  const response = await runPanel(t, p.file, { type: 'read' }, {
    beforeEnd: async child => {
      await new Promise(resolve => setTimeout(resolve, 80));
      assert.equal(p.calls.length, 0, 'A complete JSON value is not a command until stdin EOF');
      assert.equal(child.exitCode, null);
    }
  });
  assert.deepEqual(response, { status: 200, data: {
    available: true, panel: { version: 1, title: 'Synthetic', tabs: [] }
  } });
  assert.equal(p.calls.length, 1);
  assert.equal(p.calls[0].url, '/api/panel');
});

test('one-shot helper rejects malformed, oversized and unknown commands before provider IO', async t => {
  const p = await provider(t, async () => [200, { version: 1, tabs: [] }]);
  const invalid = [
    '', '{"private":"do not echo"', 'null', '[]', 'true', '42', '"read"', '{}',
    '{"type":"unknown"}', '{"type":"read","input":{}}', '{"type":"read","file":"private"}',
    '{"type":"action"}', '{"type":"action","input":{},"extra":true}',
    '{"type":"read"}\n{"type":"read"}',
    ' '.repeat(4097), '{"type":"read"}'.padEnd(4097),
    JSON.stringify({ type: 'action', input: { actionId: 'note', preview: true, text: 'é'.repeat(300) } }).padEnd(4096),
    Buffer.concat([Buffer.from('{"type":"action","input":{"actionId":"note","preview":true,"text":"'),
      Buffer.from([0xff]), Buffer.from('"}}')])
  ];
  for (const input of invalid) {
    assert.deepEqual(await runPanel(t, p.file, input),
      { status: 400, data: { ok: false, error: 'Invalid panel request.' } });
  }
  assert.equal(p.calls.length, 0);
  assert.equal((await runPanel(t, p.file, '{"type":"read"}'.padEnd(4096))).data.available, true);
  assert.equal(p.calls.length, 1);
});

test('one-shot helper delegates exact action validation without provider IO', async t => {
  const p = await provider(t, async () => [200, { ok: true }]);
  for (const input of [
    null, [], {}, { actionId: 'bad id', preview: true }, { actionId: 'note', preview: 'true' },
    { actionId: 'note', preview: true, confirmationToken: 'P'.repeat(43) },
    { actionId: 'note', preview: false }, { actionId: 'note', preview: false, confirmationToken: 'short' },
    { actionId: 'note', preview: true, text: '😀'.repeat(151) },
    { actionId: 'note', preview: true, text: 'private\u0000text' },
    { actionId: 'note', preview: true, text: '  ' }, { actionId: 'note', preview: true, extra: 'private' }
  ]) {
    assert.deepEqual(await runPanel(t, p.file, { type: 'action', input }),
      { status: 400, data: { ok: false, error: 'Invalid panel request.' } });
  }
  assert.equal(p.calls.length, 0);
});

test('one-shot helper previews without dispatch and sends exact raw text and token only once', async t => {
  const confirmationToken = 'P'.repeat(43);
  const text = '  A "fictional" feature\nwith\t two spaces and Unicode 📝  ';
  let dispatches = 0;
  const p = await provider(t, async (request, body) => {
    if (JSON.parse(body).preview) return [200, {
      ok: true, confirm: 'Exact instruction', confirmationToken, token, command: 'private'
    }];
    dispatches++;
    return [200, { ok: true, sent: true }];
  });
  const preview = await runPanel(t, p.file, { type: 'action', input: { actionId: 'note', preview: true, text } });
  assert.deepEqual(preview, { status: 200, data: { ok: true, confirm: 'Exact instruction', confirmationToken } });
  assert.equal(dispatches, 0);
  assert.equal(p.calls.length, 1);
  const sent = await runPanel(t, p.file, { type: 'action', input: {
    actionId: 'note', preview: false, text, confirmationToken
  } });
  assert.deepEqual(sent, { status: 200, data: { ok: true, sent: true } });
  assert.equal(dispatches, 1);
  assert.deepEqual(p.calls.map(call => JSON.parse(call.body)), [
    { actionId: 'note', preview: true, text }, { actionId: 'note', preview: false, text, confirmationToken }
  ]);
  assert.ok(p.calls.every(call => call.method === 'POST' && call.url === '/api/panel/action'));
});

test('one-shot helper does not turn demo or tokenless previews into dispatch', async t => {
  const p = await provider(t, async () => [200, { ok: true, demo: true, confirm: 'Demo only' }]);
  assert.deepEqual(await runPanel(t, p.file, { type: 'action', input: { actionId: 'note', preview: true } }),
    { status: 200, data: { ok: true, demo: true, confirm: 'Demo only' } });
  assert.equal((await runPanel(t, p.file, { type: 'action', input: { actionId: 'note', preview: false } })).status, 400);
  assert.equal(p.calls.length, 1);
});

test('one-shot helper preserves explicit provider failure and stale confirmation responses', async t => {
  const p = await provider(t, async request => request.method === 'GET'
    ? [503, { error: 'private' }]
    : [409, { ok: false, error: 'Confirmation is stale.', stack: 'private', token }]);
  assert.deepEqual(await runPanel(t, p.file, { type: 'read' }),
    { status: 200, data: { available: false, reason: 'Panel provider returned HTTP 503.' } });
  assert.deepEqual(await runPanel(t, p.file, { type: 'action', input: {
    actionId: 'note', preview: false, confirmationToken: 'P'.repeat(43)
  } }), { status: 409, data: { ok: false, error: 'Confirmation is stale.' } });
  assert.equal(p.calls.length, 2);
});

test('one-shot helper reports a lost send response as unknown without resending', async t => {
  const p = await provider(t, async request => { request.socket.destroy(); });
  assert.deepEqual(await runPanel(t, p.file, { type: 'action', input: {
    actionId: 'note', preview: false, text: 'Raw instruction', confirmationToken: 'P'.repeat(43)
  } }), { status: 504, data: { ok: false, error: 'Panel action outcome is unknown. Check the Mac before retrying.' } });
  assert.equal(p.calls.length, 1);
});

test('one-shot helper exits quietly when its stdout pipe closes', async t => {
  const p = await provider(t, async () => [200, { version: 1, tabs: [] }]);
  await runPanel(t, p.file, { type: 'read' }, { closeStdout: true });
  assert.equal(p.calls.length, 1);
});
