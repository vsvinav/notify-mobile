import { test, expect } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { fixture, permission, question } from '../fixtures.mjs';

let f, current, heartbeat;
test.beforeEach(async () => {
  f = await fixture();
  current = [permission()];
  await f.app.command({ type: 'snapshot', requests: current, total: current.length });
  heartbeat = setInterval(() => {
    void f.app.command({ type: 'snapshot', requests: current, total: current.length });
  }, 5000);
});
test.afterEach(async () => { clearInterval(heartbeat); await f.close(); });

async function connect(page) {
  await f.app.command({ type: 'invite' });
  const code = f.events.findLast(e => e.type === 'status').status.pairingCode;
  await page.goto(f.app.url);
  await page.getByLabel('Phone name').fill('My iPhone');
  await page.getByLabel('Pairing code').fill(code);
  await page.getByRole('button', { name: 'Pair with Mac', exact: true }).click();
  await expect(page.getByText('Compare on your Mac')).toBeVisible();
  const pending = f.events.findLast(e => e.type === 'pairing');
  await expect(page.getByText(pending.code, { exact: true })).toBeVisible();
  await f.app.command({ type: 'pair', id: pending.id, allow: true });
  await expect(page.getByText('Connected', { exact: true })).toBeVisible();
}

test('certificate setup continues to the actual app without automatic navigation', async ({ page }) => {
  await page.goto(f.app.setupURL);
  const continueLink = page.getByRole('link', { name: 'Continue to Notify', exact: true });
  await expect(continueLink).toHaveAttribute('href', `${f.app.url}/`);
  await expect(page.getByText('After verifying and installing the certificate', { exact: false })).toBeVisible();
  await expect(page).toHaveURL(`${f.app.setupURL}/`);
  await mkdir('.impeccable/review', { recursive: true });
  await page.screenshot({ path: '.impeccable/review/certificate-continue-390.png', fullPage: true });
  await continueLink.click();
  await expect(page).toHaveURL(`${f.app.url}/`);
  await expect(page.getByRole('button', { name: 'Pair with Mac', exact: true })).toBeVisible();
});

test('pairing, exact targets, native acknowledgment and screenshots in both themes', async ({ page }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await connect(page);
  await expect(page.getByText(permission().fields[0].value, { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Allow this tool', exact: false })).toBeVisible();
  await mkdir('.impeccable/review', { recursive: true });
  await page.screenshot({ path: '.impeccable/review/permission-light-390.png' });
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await page.screenshot({ path: '.impeccable/review/permission-dark-390.png' });
  await page.getByRole('button', { name: 'Allow once', exact: true }).click();
  await expect(page.getByText('Waiting for agent acknowledgment…', { exact: true })).toBeVisible();
  const command = f.events.findLast(e => e.type === 'reply');
  expect(command.decision).toBe('allow');
  await f.app.command({ type: 'result', id: command.id, ok: true });
  current = [];
  await f.app.command({ type: 'snapshot', requests: [], total: 0 });
  await expect(page.getByText('All caught up')).toBeVisible();
  expect(errors).toEqual([]);
});

test('multiselect and custom answers survive live snapshots, then send exact text', async ({ page }) => {
  current = [question()];
  await f.app.command({ type: 'snapshot', requests: current, total: 1 });
  await connect(page);
  await page.getByLabel('iPhone', { exact: false }).check();
  await page.getByLabel('Android', { exact: false }).check();
  await page.getByLabel('iPhone', { exact: false }).uncheck();
  await page.getByLabel('Custom answer for Release instructions').fill('Keep <exact> text & run nothing automatically.');
  current[0].sessionName = 'Website release · updated';
  await f.app.command({ type: 'snapshot', requests: current, total: 1 });
  await page.waitForTimeout(3200);
  await expect(page.getByLabel('Android', { exact: false })).toBeChecked();
  await expect(page.getByLabel('iPhone', { exact: false })).not.toBeChecked();
  await expect(page.getByLabel('Custom answer for Release instructions')).toHaveValue('Keep <exact> text & run nothing automatically.');
  await page.screenshot({ path: '.impeccable/review/questions-390.png', fullPage: true });
  await page.getByRole('button', { name: 'Send answer', exact: true }).click();
  await expect(page.getByText('Waiting for agent acknowledgment…', { exact: true })).toBeVisible();
  const command = f.events.findLast(e => e.type === 'reply');
  expect(command.answers).toEqual({ targets: ['Android'], instructions: ['Keep <exact> text & run nothing automatically.'] });
  await f.app.command({ type: 'result', id: command.id, ok: false, error: 'Agent disconnected' });
  await expect(page.getByText('Agent disconnected', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send answer', exact: true })).toBeDisabled();
});

test('service worker caches only shell files, never authenticated requests or answers', async ({ page }) => {
  await connect(page);
  await page.evaluate(() => navigator.serviceWorker.ready);
  const cachePaths = await page.evaluate(async () => {
    const keys = await caches.keys();
    const requests = await Promise.all(keys.map(async key => (await (await caches.open(key)).keys()).map(request => new URL(request.url).pathname)));
    return requests.flat();
  });
  expect(cachePaths.length).toBeGreaterThan(0);
  expect(cachePaths.every(path => ['/', '/index.html', '/app.mjs', '/styles.css', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'].includes(path))).toBe(true);
  expect(cachePaths.some(path => path.startsWith('/api/'))).toBe(false);
});

test('offline and stale state disable all actions; short screens and long content do not overflow', async ({ page, context }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  current[0].fields[0].value = 'https://example.com/' + 'very-long-unbroken-component-'.repeat(20);
  current[0].request.title = 'Review the exact destination before continuing with this production operation';
  await f.app.command({ type: 'snapshot', requests: current, total: 1 });
  await connect(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '.impeccable/review/long-value-320.png', fullPage: true });
  await page.screenshot({ path: '.impeccable/review/short-320.png' });
  await context.setOffline(true);
  await expect(page.getByText('Offline', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Allow once', exact: true })).toBeDisabled();
  await page.screenshot({ path: '.impeccable/review/offline-320.png', fullPage: true });
  await context.setOffline(false);
  clearInterval(heartbeat);
  await f.app.command({ type: 'offline' });
  await expect(page.getByText('Mac unavailable', { exact: true })).toBeVisible();
});

test('fixed answers have no custom field; revoked pairing clears sensitive rendered requests', async ({ page }) => {
  current = [question(false)];
  await f.app.command({ type: 'snapshot', requests: current, total: 1 });
  await connect(page);
  await expect(page.getByLabel('Custom answer for Release instructions')).toHaveCount(0);
  await page.getByLabel('Stage first', { exact: false }).check();
  await page.getByLabel('Ship now', { exact: false }).check();
  await expect(page.getByLabel('Stage first', { exact: false })).not.toBeChecked();
  const id = f.events.findLast(e => e.type === 'status').status.devices[0].id;
  await f.app.command({ type: 'revoke', id });
  await expect(page.getByRole('button', { name: 'Pair with Mac', exact: true })).toBeVisible();
  await expect(page.getByText('How should we ship this?')).toHaveCount(0);
});
