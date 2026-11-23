import http from 'node:http';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { object } from './validation.mjs';

const LIMIT = 262144;
const tokenPattern = /^[A-Za-z0-9_-]{32,128}$/;
const actionPattern = /^[A-Za-z0-9:._-]{1,128}$/;
const confirmationPattern = /^[A-Za-z0-9_-]{43}$/;
const label = (value, max, empty = false) => typeof value === 'string' && value.length <= max &&
  (empty || value.length > 0) && !/[\0-\x1f\x7f]/.test(value);
const unavailable = reason => ({ status: 200, data: { available: false, reason } });
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };

export const panelFile = () => process.env.NOTIFY_PANEL_FILE || join(homedir(), '.copilot', 'pipeline-ui', 'panel.json');

async function discover(file) {
  let handle;
  try { handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch (error) { return { reason: error.code === 'ENOENT' ? 'Panel provider is not running.' : 'Panel discovery file is unreadable.' }; }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid())
      return { reason: 'Panel discovery file is insecure.' };
    if (stat.size > 4096) return { reason: 'Panel discovery file is invalid.' };
    let value;
    try { value = JSON.parse(await handle.readFile('utf8')); } catch { return { reason: 'Panel discovery file is invalid.' }; }
    if (!object(value) || !Number.isInteger(value.port) || value.port < 1 || value.port > 65535 ||
      typeof value.token !== 'string' || !tokenPattern.test(value.token)) return { reason: 'Panel discovery file is invalid.' };
    return { port: value.port, token: value.token };
  } finally { await handle.close(); }
}

function call({ port, token }, method, path, body, timeout, limit, signal) {
  return new Promise((resolve, reject) => {
    const abort = AbortSignal.any([AbortSignal.timeout(timeout), ...(signal ? [signal] : [])]);
    const failure = error => reject(abort.aborted && !signal?.aborted ? Object.assign(new Error('timeout'), { code: 'TIMEOUT' }) : error);
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
    if (body !== undefined) Object.assign(headers, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    const request = http.request({ host: '127.0.0.1', port, path, method, headers, signal: abort, agent: false }, response => {
      if (Number(response.headers['content-length']) > limit) {
        response.destroy(); reject(Object.assign(new Error('large'), { code: 'TOO_LARGE' })); return;
      }
      const chunks = []; let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > limit) { response.destroy(); reject(Object.assign(new Error('large'), { code: 'TOO_LARGE' })); return; }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', failure);
    });
    request.on('error', failure);
    request.end(body);
  });
}

const take = (value, max, map) => Array.isArray(value) ? value.map(map).filter(Boolean).slice(0, max) : [];

function action(value) {
  if (!object(value) || typeof value.id !== 'string' || !actionPattern.test(value.id) || !label(value.label, 24)) return;
  return { id: value.id, label: value.label,
    ...(['primary', 'danger', 'default'].includes(value.style) ? { style: value.style } : {}) };
}
function log(value) {
  if (!object(value) || !Array.isArray(value.entries)) return;
  const entries = value.entries.slice(0, 8).filter(entry => object(entry) && label(entry.text, 1000) &&
    (entry.at === undefined || label(entry.at, 40, true)))
    .map(entry => ({ text: entry.text, ...(entry.at !== undefined ? { at: entry.at } : {}) }));
  return { entries, truncated: value.truncated === true || entries.length !== value.entries.length };
}
function item(value) {
  if (!object(value) || !label(value.id, 64) || !label(value.title, 140)) return;
  const recent = log(value.log);
  return { id: value.id, title: value.title,
    ...(label(value.subtitle, 280, true) ? { subtitle: value.subtitle } : {}),
    tone: ['ok', 'warn', 'red', 'info', 'idle'].includes(value.tone) ? value.tone : 'idle',
    ...(label(value.url, 300) && value.url.startsWith('https://') ? { url: value.url } : {}),
    ...(recent ? { log: recent } : {}),
    actions: take(value.actions, 4, action) };
}
function section(value) {
  if (!object(value) || !label(value.title, 60, true)) return;
  return { title: value.title, ...(value.emphasis === 'attention' ? { emphasis: 'attention' } : {}),
    items: take(value.items, 60, item) };
}
function track(value, sections) {
  if (!object(value) || value.version !== 1 || !label(value.title, 60) ||
      !Array.isArray(value.stages) || value.stages.length < 1 || value.stages.length > 24 ||
      !Array.isArray(value.placements) || value.placements.length > 60) return;
  const ids = new Set(), placed = new Set(), counts = new Map(), stages = [], placements = [];
  for (const section of sections) for (const item of section.items) counts.set(item.id, (counts.get(item.id) || 0) + 1);
  for (const stage of value.stages) {
    if (!object(stage) || typeof stage.id !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(stage.id) ||
        ids.has(stage.id) || !label(stage.label, 40) || !['normal', 'gate', 'decision'].includes(stage.kind) ||
        (stage.hint !== undefined && !label(stage.hint, 80, true))) return;
    ids.add(stage.id);
    stages.push({ id: stage.id, label: stage.label, kind: stage.kind,
      ...(stage.hint !== undefined ? { hint: stage.hint } : {}) });
  }
  for (const placement of value.placements) {
    if (!object(placement) || counts.get(placement.itemId) !== 1 ||
        placed.has(placement.itemId) || !ids.has(placement.stageId)) return;
    placed.add(placement.itemId);
    placements.push({ itemId: placement.itemId, stageId: placement.stageId });
  }
  return { version: 1, title: value.title, stages, placements };
}
function form(value) {
  if (!object(value) || value.version !== 1 || typeof value.actionId !== 'string' || !actionPattern.test(value.actionId) ||
      !label(value.title, 60) || !label(value.submitLabel, 24) ||
      !Number.isInteger(value.minLength) || !Number.isInteger(value.maxLength) ||
      value.minLength < 1 || value.maxLength > 300 || value.minLength > value.maxLength ||
      (value.placeholder !== undefined && !label(value.placeholder, 140, true))) return;
  return { version: 1, actionId: value.actionId, title: value.title, submitLabel: value.submitLabel,
    minLength: value.minLength, maxLength: value.maxLength,
    ...(value.placeholder !== undefined ? { placeholder: value.placeholder } : {}) };
}
function tab(value) {
  if (!object(value) || typeof value.id !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(value.id) || !label(value.label, 24)) return;
  const input = form(value.form);
  const sections = take(value.sections, 12, section);
  const stages = track(value.track, sections);
  return { id: value.id, label: value.label,
    ...(Number.isInteger(value.badge) && value.badge >= 0 && value.badge <= 999 ? { badge: value.badge } : {}),
    ...(input ? { form: input } : {}),
    ...(stages ? { track: stages } : {}),
    sections };
}
export function sanitizePanel(value) {
  if (!object(value) || value.version !== 1) return;
  const ids = new Set();
  return { version: 1,
    ...(label(value.title, 60) ? { title: value.title } : {}),
    ...(label(value.updatedAt, 40) && !Number.isNaN(Date.parse(value.updatedAt)) ? { updatedAt: value.updatedAt } : {}),
    ...(object(value.copilot) ? { copilot: { connected: value.copilot.connected === true, busy: value.copilot.busy === true } } : {}),
    tabs: take(value.tabs, 6, entry => {
      const result = tab(entry);
      if (!result || ids.has(result.id)) return;
      ids.add(result.id); return result;
    }) };
}

export async function readPanel({ file = panelFile(), signal } = {}) {
  const provider = await discover(file);
  if (provider.reason) return unavailable(provider.reason);
  let response;
  try { response = await call(provider, 'GET', '/api/panel', undefined, 4000, LIMIT, signal); }
  catch (error) {
    return unavailable(error.code === 'TOO_LARGE' ? 'Panel feed is too large.'
      : error.code === 'TIMEOUT' ? 'Panel provider timed out.' : 'Panel provider is unreachable.');
  }
  if (response.status === 401 || response.status === 403) return unavailable('Panel provider rejected the request.');
  if (response.status !== 200) return unavailable(`Panel provider returned HTTP ${response.status}.`);
  let panel;
  try { panel = sanitizePanel(JSON.parse(response.body)); } catch {}
  if (!panel) return unavailable('Panel feed is invalid.');
  if (Buffer.byteLength(JSON.stringify(panel)) > LIMIT) return unavailable('Panel feed is too large.');
  return { status: 200, data: { available: true, panel } };
}

export async function panelAction(input, { file = panelFile(), signal } = {}) {
  if (!object(input) || Object.keys(input).some(key => !['actionId', 'preview', 'confirmationToken', 'text'].includes(key)) ||
    typeof input.actionId !== 'string' || !actionPattern.test(input.actionId) || typeof input.preview !== 'boolean' ||
    (input.text !== undefined && (typeof input.text !== 'string' || !input.text.trim() || input.text.length > 300 ||
      /[\0-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(input.text))) ||
    (input.preview ? input.confirmationToken !== undefined :
      typeof input.confirmationToken !== 'string' || !confirmationPattern.test(input.confirmationToken)))
    fail(400, 'Invalid panel action.');
  const provider = await discover(file);
  if (provider.reason) return { status: 503, data: { ok: false, error: provider.reason } };
  let response;
  try {
    response = await call(provider, 'POST', '/api/panel/action',
      JSON.stringify({ actionId: input.actionId, preview: input.preview,
        ...(input.text !== undefined ? { text: input.text } : {}),
        ...(!input.preview ? { confirmationToken: input.confirmationToken } : {}) }), 10000, 65536, signal);
  } catch {
    // A sent action may have been delivered even when its response is lost.
    return { status: 504, data: { ok: false, error: input.preview ? 'Panel provider did not respond.'
      : 'Panel action outcome is unknown. Check the Mac before retrying.' } };
  }
  let value;
  try { value = JSON.parse(response.body); } catch {}
  if (!object(value)) return { status: response.status >= 400 ? response.status : 502,
    data: { ok: false, error: 'Panel provider returned invalid data.' } };
  const data = {};
  for (const key of ['ok', 'sent', 'wasBusy', 'demo']) if (typeof value[key] === 'boolean') data[key] = value[key];
  for (const key of ['confirm', 'label']) if (typeof value[key] === 'string' && value[key].length <= 1000) data[key] = value[key];
  if (typeof value.confirmationToken === 'string' && confirmationPattern.test(value.confirmationToken))
    data.confirmationToken = value.confirmationToken;
  if (typeof value.error === 'string') data.error = value.error.slice(0, 1000);
  const { status } = response;
  return { status: (status >= 200 && status < 300) || (status >= 400 && status <= 599) ? status : 502, data };
}
