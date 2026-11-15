import { test, expect } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { fixture, permission, pair } from '../fixtures.mjs';

let f, workspace, version, releases, heartbeat, commands, acknowledge;
const helper = (id, status = 'idle', parentAgentID) => ({
  id, name: id === 'working' ? 'Release reviewer' : `Helper ${id}`,
  task: 'Review the release checklist', status, model: 'configured-model',
  parentKnown: true, ...(parentAgentID ? { parentAgentID } : {})
});
const entry = (id, kind, detail, agentID) => ({
  id, kind, title: kind === 'assistant' ? 'Response' : 'Reported activity',
  detail, status: 'complete', timestamp: '2026-11-14T12:00:00Z', ...(agentID ? { agentID } : {})
});
function changed() { version++; for (const release of releases) release(); releases.clear(); }

test.beforeEach(async ({ page, context }) => {
  f = await fixture(); releases = new Set(); version = 1; commands = [];
  const requests = [permission()];
  await f.app.command({ type: 'snapshot', requests, total: 1 });
  heartbeat = setInterval(() => { void f.app.command({ type: 'snapshot', requests, total: 1 }); }, 5000);
  const device = await pair(f);
  await context.addCookies([{ name: '__Host-notify', value: device.cookie.split('=')[1],
    url: f.app.url, secure: true, httpOnly: true, sameSite: 'Strict' }]);
  const session = {
    id: 'session-1', name: 'Website release', project: 'notify', agent: 'copilot',
    color: '#C06444', state: 'working', connected: true, ticket: 'generation-1',
    capabilities: { steering: true, subagentChat: true, subagentStop: true },
    runningCount: 1, idleCount: 19
  };
  workspace = {
    connected: true, sessions: [session], total: 1, truncated: false,
    detail: {
      sessionID: session.id, ticket: session.ticket, truncated: false, controls: [],
      team: { agents: [helper('working', 'running'), ...Array.from({ length: 19 }, (_, i) => helper(`${i + 1}`))],
        runningCount: 1, idleCount: 19, truncated: false },
      activity: [
        entry('reply', 'assistant', 'Reviewing the release notes.'),
        entry('thinking', 'reasoning', 'Comparing the reported release targets.'),
        entry('child-reply', 'assistant', 'Checking the signing instructions.', 'working')
      ]
    }
  };
  await page.route('**/api/workspace', async route => {
    const input = route.request().postDataJSON();
    if (input.revision === String(version)) await new Promise(resolve => {
      const finish = () => { clearTimeout(timer); releases.delete(finish); resolve(); };
      const timer = setTimeout(finish, 8000); releases.add(finish);
    });
    await route.fulfill({ json: { ...workspace, revision: String(version),
      detail: input.sessionID === workspace.detail?.sessionID ? workspace.detail : null } });
  });
  await page.route('**/api/control', async route => {
    commands.push(route.request().postDataJSON());
    const result = await new Promise(resolve => { acknowledge = resolve; });
    await route.fulfill({ status: result.ok ? 200 : 502, json: result });
  });
  await page.goto(f.app.url);
  await expect(page.getByText('Connected', { exact: true })).toBeVisible();
});

test.afterEach(async ({ page }) => {
  clearInterval(heartbeat);
  acknowledge?.({ ok: false, error: 'Fixture closed' }); acknowledge = undefined;
  for (const release of releases) release();
  await page.unrouteAll({ behavior: 'wait' });
  await f.close();
});

async function openSession(page) {
  await page.getByRole('button', { name: 'Sessions', exact: true }).click();
  await page.getByRole('button', { name: 'Open Website release', exact: true }).click();
  await expect(page.getByLabel('Chat with', { exact: true })).toBeVisible();
}

test('live exact-target chat preserves drafts, separates activity and waits for acknowledgment', async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await expect(page.getByRole('button', { name: 'Allow once', exact: true })).toBeVisible();
  await openSession(page);
  await expect(page.locator('.chat-feed')).toContainText('Reviewing the release notes.');
  await expect(page.locator('.chat-feed')).not.toContainText('Comparing the reported');
  await expect(page.getByText('Comparing the reported release targets.', { exact: true })).toBeVisible();
  const sendBounds = await page.getByRole('button', { name: 'Send', exact: true }).boundingBox();
  expect(sendBounds.y + sendBounds.height).toBeLessThanOrEqual(844);
  const composer = page.getByLabel('Message');
  await composer.fill('Keep my main-agent draft');
  await mkdir('.impeccable/review', { recursive: true });
  await page.screenshot({ path: '.impeccable/review/workspace-chat-light-390.png', fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.screenshot({ path: '.impeccable/review/workspace-chat-dark-390.png', fullPage: true });
  await page.getByLabel('Chat with', { exact: true }).selectOption('working');
  await expect(composer).toHaveValue('');
  await composer.fill('Check the <exact> signing command & report back.');
  workspace.detail.activity.push(entry('stream', 'assistant', 'A new streamed response.', 'working'));
  changed();
  await expect(page.locator('.chat-feed')).toContainText('A new streamed response.', { timeout: 1500 });
  await expect(composer).toHaveValue('Check the <exact> signing command & report back.');
  await expect(composer).toBeFocused();
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(page.getByText('Waiting for agent acknowledgment…', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  expect(commands).toHaveLength(1);
  expect(commands[0]).toMatchObject({ sessionID: 'session-1', ticket: 'generation-1',
    action: 'queue', agentID: 'working', text: 'Check the <exact> signing command & report back.' });
  expect(commands[0].id).toMatch(/^[a-f0-9-]{36}$/i);
  acknowledge({ ok: true, commandID: 'native-command', status: 'received', detail: 'Agent received your message.' });
  await expect(composer).toHaveValue('');
  await page.getByLabel('Chat with', { exact: true }).selectOption('');
  await expect(composer).toHaveValue('Keep my main-agent draft');
  await page.getByRole('button', { name: 'All sessions', exact: true }).click();
  await page.getByRole('button', { name: 'Open Website release', exact: true }).click();
  await expect(composer).toHaveValue('Keep my main-agent draft');
  await page.getByRole('button', { name: 'Requests', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow once', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test('org chart groups nineteen idle helpers into one tile, expands and opens the exact helper', async ({ page }) => {
  await openSession(page);
  await page.getByRole('button', { name: 'Hierarchy', exact: true }).click();
  await expect(page.locator('.agent-tile')).toHaveCount(3);
  const main = await page.locator('.agent-tile[data-agent-id=""]').boundingBox();
  const running = await page.locator('.agent-tile[data-agent-id="working"]').boundingBox();
  const idle = await page.getByRole('button', { name: '+19 idle subagents', exact: true }).boundingBox();
  expect(main.y + main.height).toBeLessThan(running.y);
  expect(Math.abs(idle.y - running.y)).toBeLessThan(2);
  expect(main.width).toBeGreaterThan(running.width);
  await mkdir('.impeccable/review', { recursive: true });
  await page.screenshot({ path: '.impeccable/review/workspace-hierarchy-light-390.png', fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.screenshot({ path: '.impeccable/review/workspace-hierarchy-dark-390.png', fullPage: true });
  await page.getByRole('button', { name: '+19 idle subagents', exact: true }).click();
  await expect(page.locator('.agent-tile')).toHaveCount(21);
  await page.getByRole('button', { name: '100%', exact: true }).click();
  await page.getByRole('button', { name: 'Chat with Helper 19', exact: true }).click();
  await expect(page.getByLabel('Chat with', { exact: true })).toHaveValue('19');
  await page.getByRole('button', { name: 'Hierarchy', exact: true }).click();
  await page.getByRole('button', { name: 'Hide idle', exact: true }).click();
  await expect(page.locator('.agent-tile')).toHaveCount(3);
  await page.setViewportSize({ width: 320, height: 568 });
  await page.getByRole('button', { name: 'Fit', exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('unknown ancestry stays unlinked and a stale stop confirmation cannot change targets', async ({ page }) => {
  workspace.detail.team.agents = [
    helper('working', 'running', '1'), helper('1'), { ...helper('unknown', 'running'), parentKnown: false },
    helper('ended', 'cancelled')
  ];
  workspace.detail.team.runningCount = 2; workspace.detail.team.idleCount = 1;
  workspace.sessions[0].runningCount = 2; workspace.sessions[0].idleCount = 1;
  changed();
  await openSession(page);
  await page.getByRole('button', { name: 'Hierarchy', exact: true }).click();
  await expect(page.getByText('Parent: Helper 1', { exact: true })).toBeVisible();
  await expect(page.getByText('Parent not reported', { exact: true })).toBeVisible();
  expect(await page.locator('.main-branch > .tree-children .agent-tile[data-agent-id="working"]').count()).toBe(0);
  await page.getByRole('button', { name: '+1 inactive subagent', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Chat with Helper ended', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Chat with Release reviewer', exact: true }).click();
  await page.getByRole('button', { name: 'Stop subagent', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('descendants');
  workspace.sessions[0].ticket = 'generation-2'; workspace.detail.ticket = 'generation-2'; changed();
  await page.getByRole('dialog').getByRole('button', { name: 'Stop', exact: true }).click();
  await expect(page.getByText('This session changed. Review it again before sending.', { exact: true })).toBeVisible();
  expect(commands).toHaveLength(0);
  workspace.sessions[0].capabilities = { steering: false, subagentChat: false, subagentStop: false };
  workspace.sessions[0].agent = 'claude'; changed();
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Stop subagent', exact: true })).toBeDisabled();
});

test('confirmed controls keep their target and failures retain the phone draft', async ({ page }) => {
  await openSession(page);
  await page.getByLabel('Chat with', { exact: true }).selectOption('working');
  await page.getByRole('button', { name: 'Stop subagent', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(commands).toHaveLength(0);
  await page.getByRole('button', { name: 'Stop subagent', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Stop', exact: true }).click();
  await expect.poll(() => commands.length).toBe(1);
  expect(commands[0]).toMatchObject({ action: 'stop', text: '', agentID: 'working', sessionID: 'session-1' });
  acknowledge({ ok: true, commandID: 'stopped-command', status: 'stopped', detail: 'Selected helper stopped.' });
  await expect(page.getByText('Selected helper stopped.', { exact: true })).toBeVisible();
  await page.getByLabel('Chat with', { exact: true }).selectOption('');
  await page.getByLabel('Message').fill('Use the reviewed release plan.');
  await page.getByRole('button', { name: 'Interrupt', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Interrupt', exact: true }).click();
  await expect.poll(() => commands.length).toBe(2);
  expect(commands[1]).toMatchObject({ action: 'interrupt', text: 'Use the reviewed release plan.' });
  expect(commands[1].agentID).toBeUndefined();
  acknowledge({ ok: false, error: 'Delivery is uncertain. Check the Mac before sending again.' });
  await expect(page.getByLabel('Message')).toHaveValue('Use the reviewed release plan.');
  await expect(page.getByText('Delivery is uncertain. Check the Mac before sending again.', { exact: true })).toBeVisible();
  expect(commands).toHaveLength(2);
});

test('code remains literal, own echoes are not duplicated, and revocation clears phone drafts', async ({ page, context }) => {
  workspace.detail.activity.push(
    entry('code', 'assistant', '## Checked command\n```sh\nprintf \'<exact> & literal\'\n```'),
    { ...entry('echo', 'user', 'Run only the reviewed command.'), clientTurnID: 'receipt-1' }
  );
  workspace.detail.controls.push({ id: 'receipt-1', action: 'queue', message: 'Run only the reviewed command.',
    status: 'received', detail: 'Received', createdAt: '2026-11-14T12:00:00Z' });
  changed();
  await openSession(page);
  await expect(page.locator('.chat-feed').getByText('Run only the reviewed command.', { exact: true })).toHaveCount(1);
  await expect(page.locator('.chat-code pre')).toHaveText("printf '<exact> & literal'");
  await page.getByLabel('Message').fill('Private unsent phone draft');
  await context.setOffline(true);
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await expect(page.getByLabel('Message')).toHaveValue('Private unsent phone draft');
  await context.setOffline(false);
  const id = f.events.findLast(event => event.type === 'status').status.devices[0].id;
  await f.app.command({ type: 'revoke', id });
  await expect(page.getByRole('button', { name: 'Pair with Mac', exact: true })).toBeVisible();
  await expect(page.getByLabel('Message')).toHaveCount(0);
  await expect(page.locator('.chat-code')).toHaveCount(0);
});

test('paired browser uses the real workspace service and waits for the exact native control result', async ({ page }) => {
  await page.unroute('**/api/workspace');
  await page.unroute('**/api/control');
  await f.app.command({ type: 'workspace', sessions: workspace.sessions, total: 1, truncated: false });
  await openSession(page);
  await expect.poll(() => f.events.some(event => event.type === 'workspace_watch' && event.sessionIDs.includes('session-1'))).toBe(true);
  await f.app.command({ type: 'workspace_detail', ...workspace.detail });
  await expect(page.locator('.chat-feed')).toContainText('Reviewing the release notes.');
  await page.getByLabel('Chat with', { exact: true }).selectOption('working');
  await page.getByLabel('Message').fill('Review this exact helper only.');
  await page.getByRole('button', { name: 'Send', exact: true }).click();
  await expect.poll(() => f.events.some(event => event.type === 'control')).toBe(true);
  const command = f.events.findLast(event => event.type === 'control');
  expect(command).toMatchObject({ sessionID: 'session-1', agentID: 'working',
    ticket: 'generation-1', action: 'queue', text: 'Review this exact helper only.' });
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeDisabled();
  await f.app.command({ type: 'control_result', id: command.id, ok: true, commandID: 'synthetic-runtime-command',
    status: 'received', detail: 'Synthetic runtime received the helper message.' });
  await expect(page.getByText('Synthetic runtime received the helper message.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Message')).toHaveValue('');
});

test('an unavailable workspace backs off instead of consuming the approval API budget', async ({ page }) => {
  let reads = 0;
  await page.route('**/api/workspace', async route => {
    reads++;
    await route.fulfill({ json: { revision: 'offline', connected: false, sessions: [], total: 0, truncated: false, detail: null } });
  });
  await page.getByRole('button', { name: 'Sessions', exact: true }).click();
  await expect(page.getByText('The Mac workspace is unavailable. Keep Notify and the session connected.', { exact: true })).toBeVisible();
  await page.waitForTimeout(300);
  expect(reads).toBe(1);
  await page.getByRole('button', { name: 'Requests', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow once', exact: true })).toBeEnabled();
});
