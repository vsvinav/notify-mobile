import { defineConfig } from '@playwright/test';
import { mkdirSync } from 'node:fs';

process.env.TMPDIR = `${process.cwd()}/.test-data/browser-runtime`;
mkdirSync(process.env.TMPDIR, { recursive: true });

export default defineConfig({
  testDir: './test/browser',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: {
    browserName: 'chromium',
    viewport: { width: 390, height: 844 },
    isMobile: true, hasTouch: true,
    ignoreHTTPSErrors: true,
    launchOptions: { args: ['--ignore-certificate-errors'] },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure'
  }
});
