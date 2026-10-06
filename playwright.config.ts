import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships.
 *
 * Port 4732 is this lab's own, confirmed free against the fleet registry with
 * `node ../crypto-lab/tools/port-sync.js` on 2026-10-06. Never the Vite default
 * 4173: `reuseExistingServer` means a run that finds something listening USES
 * it, so a shared port can scan another lab's preview — or, during a mutation
 * check, an UNMUTATED server still running from a previous run, which reads as
 * "the mutation was not caught" and sends someone to fix a check that works.
 * `--strictPort` keeps a collision visible instead of silently moving on.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  // The a11y drive walks five panels, both error branches and ~30 scans, and
  // generates real traffic until a real IV collision appears.
  timeout: 300_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4732/crypto-lab-wep-crack/',
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    // Claims run in one engine: they assert what the page SAYS and what it
    // COMPUTED, neither of which varies by browser.
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles —
    // which silently invalidates mutation checking.
    command: 'npm run build && npm run preview -- --port 4732 --strictPort',
    url: 'http://localhost:4732/crypto-lab-wep-crack/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
