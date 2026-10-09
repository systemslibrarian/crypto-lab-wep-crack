import { expect, test } from '@playwright/test';
import { boot } from './gate';

test('the hero opens a working forgery, and browser back restores the first exhibit', async ({ page }) => {
  await boot(page, 'dark');
  await page.getByRole('link', { name: /See the forgery/ }).click();
  await expect(page).toHaveURL(/#forge$/);
  await expect(page.getByRole('tab', { selected: true })).toContainText('Forge a packet');
  await expect(page.locator('#forge-original-text')).toContainText('transfer 100');
  await expect(page.locator('#forge-received-text')).toContainText('transfer 999');
  await expect(page.locator('[data-claim="forge-fixture"]')).toContainText('ICV VALID — AND FORGED');
  await expect(page.getByRole('tab', { selected: true })).toBeFocused();
  await page.goBack();
  await expect(page.getByRole('tab', { selected: true })).toContainText('RC4 itself');
  await expect(page.locator('#panel-forge')).toBeHidden();
  await page.goForward();
  await expect(page.locator('#panel-forge')).toBeVisible();
});

test('a bookmarked exhibit survives reload without saving session material', async ({ page }) => {
  await page.goto('./#ptw');
  await expect(page.getByRole('tab', { selected: true })).toContainText('Recover the key');
  await expect(page.locator('#panel-rc4')).toBeEmpty();
  await expect(page.locator('[data-claim="ptw-state"]')).toContainText('NO RUN YET');
  await page.reload();
  await expect(page.getByRole('tab', { selected: true })).toContainText('Recover the key');
  await expect(page.locator('#exhibit-position')).toHaveText('Exhibit 5 of 5');
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(['theme']);
});

test('keyboard tabs and the walkthrough controls agree on the active exhibit', async ({ page }) => {
  await boot(page, 'dark');
  await page.getByRole('tab', { selected: true }).focus();
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByRole('tab', { selected: true })).toContainText('Recover the key');
  await expect(page.getByRole('tab', { selected: true })).toBeFocused();
  await page.keyboard.press('Home');
  await page.getByRole('button', { name: /Next: Wrap it in WEP/ }).click();
  await expect(page).toHaveURL(/#wep$/);
  await expect(page.getByRole('tab', { selected: true })).toBeFocused();
  await expect(page.locator('#exhibit-position')).toHaveText('Exhibit 2 of 5');
  await page.getByRole('button', { name: /Previous exhibit/ }).click();
  await expect(page.getByRole('tab', { selected: true })).toContainText('RC4 itself');
  await expect(page.getByRole('button', { name: /Previous exhibit/ })).toBeDisabled();
});

test('RC4 accepts its full key contract and retires state when the key becomes invalid', async ({ page }) => {
  await boot(page, 'dark');
  const key = page.getByLabel('Inspection key (hex)');
  await key.fill('ab'.repeat(256));
  await expect(key).toHaveValue('ab'.repeat(256));
  await expect(key).toHaveAttribute('aria-invalid', 'false');
  await expect(page.locator('.perm-cell')).toHaveCount(256);
  await key.fill('zz');
  await expect(page.locator('#rc4-key-error')).toBeVisible();
  await expect(page.locator('.perm-cell')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Step/ })).toBeDisabled();
  await expect(page.getByLabel('Jump to an executed step')).toBeDisabled();
  await key.fill('0102030405');
  await expect(page.locator('#rc4-key-error')).toBeHidden();
  await expect(page.locator('.perm-cell')).toHaveCount(256);
  await page.getByLabel('Jump to an executed step').focus();
  await page.keyboard.press('End');
  await expect(page.locator('#rc4-step-label')).toHaveText('KEYSTREAM — output byte 15');
  await expect(page.locator('#rc4-step-out')).toContainText('16 bytes');
  await expect(page.getByRole('button', { name: /^Step/ })).toBeDisabled();
});

test('WEP identifies the invalid field and removes stale receiver verdicts', async ({ page }) => {
  await page.goto('./#wep');
  await expect(page.locator('#wep-verdict')).toBeVisible();
  await page.locator('#wep-iv').fill('zz');
  await expect(page.locator('#wep-iv')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#wep-key')).toHaveAttribute('aria-invalid', 'false');
  await expect(page.locator('#wep-input-error')).toContainText('for the IV');
  await expect(page.locator('#wep-verdict')).toHaveCount(0);
  await page.locator('#wep-iv').fill('010203');
  await expect(page.locator('#wep-iv')).toHaveAttribute('aria-invalid', 'false');
  await expect(page.locator('#wep-verdict')).toContainText('ICV CHECK PASSED');
  await expect(page.locator('#wep-input-error')).toBeEmpty();
});

test('typing a replacement preserves focus and the cursor through every redraw', async ({ page }) => {
  await page.goto('./#forge');
  const desired = page.locator('#forge-desired');
  await desired.fill('');
  await page.keyboard.type('999');
  await expect(desired).toBeFocused();
  await expect(desired).toHaveValue('999');
  expect(await desired.evaluate((node: HTMLInputElement) => node.selectionStart)).toBe(3);
  await page.keyboard.press('ArrowLeft');
  await page.keyboard.press('Backspace');
  await page.keyboard.type('8');
  await expect(desired).toHaveValue('989');
  await expect(page.locator('#forge-received-text')).toContainText('transfer 989');
  await expect(page.locator('[data-claim="forge-fixture"]')).toContainText('FORGED');
});

test('typing a collision crib preserves focus instead of dropping later keystrokes', async ({ page }) => {
  await page.goto('./#collision');
  for (let batch = 0; batch < 40; batch++) {
    if (await page.locator('#coll-crib').count()) break;
    await page.getByRole('button', { name: /Generate/ }).click();
  }
  const crib = page.locator('#coll-crib');
  await expect(crib).toBeVisible();
  await crib.fill('');
  await page.keyboard.type('hello');
  await expect(crib).toBeFocused();
  await expect(crib).toHaveValue('hello');
  await expect(page.locator('[data-claim="crib-state"]')).toContainText('UNVERIFIED');
});

test('traffic collection is cancellable and the next real run can finish', async ({ page }) => {
  await page.goto('./#ptw');
  await page.selectOption('#ptw-packets', '80000');
  const run = page.getByRole('button', { name: /^Run the attack$/ });
  await run.click();
  await expect(page.locator('#ptw-packets')).toBeDisabled();
  await page.getByRole('button', { name: /^Cancel$/ }).click();
  await expect(page.locator('[data-claim="ptw-state"]')).toHaveText('○CANCELLED');
  await expect(run).toBeEnabled();
  await expect(page.locator('#ptw-progress')).toBeHidden();
  await expect(page.locator('#ptw-result')).toBeEmpty();
  await page.selectOption('#ptw-packets', '20000');
  await run.click();
  await expect(run).toBeEnabled({ timeout: 60_000 });
  await expect(page.locator('[data-claim="ptw-state"]')).toContainText(/WEP KEY RECOVERED|NO KEY RECOVERED WITHIN THIS BUDGET/);
  await expect(page.locator('#ptw-supplied dd')).toHaveText('20,000');
});

test('cancel and session reset terminate an active worker and release all controls', async ({ page }) => {
  // Keep a worker in its search phase so this tests interruption rather than
  // racing a probabilistic recovery. No candidate or verdict is fabricated.
  await page.addInitScript(() => {
    const state = window as Window & { terminatedWorkers?: number };
    state.terminatedWorkers = 0;
    window.Worker = class extends EventTarget {
      postMessage(message: { kind: string; request: { runId: string } }): void {
        if (message.kind !== 'run') return;
        this.dispatchEvent(new MessageEvent('message', { data: {
          kind: 'progress',
          progress: { runId: message.request.runId, phase: 'ranking', processed: 20000, total: 20000, candidatesTested: 64 },
        } }));
      }
      terminate(): void { state.terminatedWorkers!++; }
    } as unknown as typeof Worker;
  });
  await page.goto('./#ptw');
  await page.selectOption('#ptw-packets', '20000');
  const run = page.getByRole('button', { name: /^Run the attack$/ });
  await run.click();
  await expect(page.locator('#ptw-progress-text')).toContainText('Ranking candidates');
  await page.getByRole('button', { name: /^Cancel$/ }).click();
  await expect(page.locator('[data-claim="ptw-state"]')).toContainText('CANCELLED');
  expect(await page.evaluate(() => (window as Window & { terminatedWorkers?: number }).terminatedWorkers)).toBe(1);
  await run.click();
  await expect(page.locator('#ptw-progress-text')).toContainText('Ranking candidates');
  await page.getByRole('button', { name: /^New session key$/ }).click();
  await expect(page.locator('[data-claim="ptw-state"]')).toContainText('NO RUN YET');
  expect(await page.evaluate(() => (window as Window & { terminatedWorkers?: number }).terminatedWorkers)).toBe(2);
  await expect(run).toBeEnabled();
  await expect(page.locator('#ptw-packets')).toBeEnabled();
  await expect(page.getByRole('button', { name: /^Cancel$/ })).toBeDisabled();
  await expect(page.locator('#ptw-progress')).toBeHidden();
});

test('a worker startup failure leaves a clear error and a usable retry control', async ({ page }) => {
  await page.addInitScript(() => {
    window.Worker = class { constructor() { throw new Error('Worker unavailable for this test'); } } as unknown as typeof Worker;
  });
  await page.goto('./#ptw');
  await page.selectOption('#ptw-packets', '20000');
  await page.getByRole('button', { name: /^Run the attack$/ }).click();
  await expect(page.locator('[data-claim="ptw-state"]')).toContainText('EXPERIMENT ERROR');
  await expect(page.locator('#ptw-status')).toContainText('Worker unavailable for this test');
  await expect(page.getByRole('button', { name: /^Run the attack$/ })).toBeEnabled();
  await expect(page.locator('#ptw-packets')).toBeEnabled();
  await expect(page.locator('#ptw-progress')).toBeHidden();
});

test('all exhibits fit a 320px screen without page-level horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto('.');
  for (const id of ['rc4', 'wep', 'collision', 'forge', 'ptw']) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#panel-${id}`)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  }
});
