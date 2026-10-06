import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where panel
 * 1 has drawn its 256-cell permutation and all 24 published vector rows and the
 * other four tabpanels are hidden and UNRENDERED; the shared skip link focused;
 * the KSA stepped, the PRGA reached, stepped back and reset; a malformed
 * inspection key behind an `aria-invalid` boundary; the WEP construction on both
 * shared-key sizes, with the wrapper's own rejection of an unsupported length
 * and of a malformed IV, and a non-zero Key ID; the collision panel's honest
 * NO COLLISION OBSERVED YET and then a REAL repeated IV, a disclosed crib
 * selected, and ground truth revealed; the forgery panel's rejected unrepaired
 * control beside its accepted-and-forged alarm, a different-length replacement
 * refused, and a wrong assumption accepted anyway; the PTW panel's NO RUN YET
 * and a changed budget; every one of this lab's eight disclosures opened through
 * its own summary; three hover states and a focus ring. Every one of those
 * states is scanned, at desktop and phone width.
 *
 * The PTW run itself is deliberately not driven here: it is a 60,000-packet
 * attack, and its duration would make this gate unreliable rather than strict.
 * `claims.spec.ts` drives it, with a budget suited to it.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion block,
 * so the rendering reduced-motion readers get was never the one scanned), why
 * no panel is revealed from script (the old gate stripped every `[hidden]` and
 * opened every `<details>` by JS before its only scan), why the lab's defaults
 * are asserted rather than assumed, and why `violations` is not the whole
 * oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
