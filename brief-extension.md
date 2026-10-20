# Extension brief — `crypto-lab-wep-crack`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-wep-crack` at `cb9df00f7c24` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap:
Katz–Lindell, *Introduction to Modern Cryptography*, 3rd ed., §7.1.4 (RC4 — the
second-output-byte bias and its derivation).

**Verdict: extension — one new card at the end of panel 1 ("RC4 itself"), not a new tab.**

## What the lab has now

Read at `cb9df00f7c24`:

- Hand-rolled RC4 in `src/rc4/rc4.ts`: `ksa` with optional per-step trace (`:78`),
  `ksaPartial` (`:103`), the streaming `Rc4Keystream` class with PRGA trace (`:129`),
  `keystream`, `rc4Apply`, `invert`. No RC4-drop.
- RFC 6229 vectors pinned in `src/rc4/vectors.ts` (both key families, offsets read from one
  continuous stream), asserted in `src/rc4/rc4.test.ts:6–35`.
- Panel 1 (`src/ui/panel1Rc4.ts`) steps real KSA/PRGA frames from the cipher's own trace
  and shows the vector table; its pass reads `TEST VECTOR MATCH`, scoped to correctness
  (claims test `e2e/claims.spec.ts:111`, "never claims RC4 is secure").
- The README already says RC4 is unsound beyond WEP (README "What it does NOT prove",
  first bullet) and cites RFC 7465 as [R2]. It names FMS and KoreK as future extensions,
  not implemented.
- The PTW attack measures its own bias rather than asserting it
  (`src/wep/attack/ptw.test.ts:68`, "favours the true sums far above chance") — the same
  habit this card should follow.
- Verdict chips: `verdict(tone, text)` in `src/ui/dom.ts:77`, tones
  `pass | fail | alarm | neutral`, rendered with icon + text + `data-verdict`.
- `scripts/mutations.mjs` runs concrete-patch mutations with a five-rule kill definition.
- `e2e/gate.ts:270` asserts `.tab-btn` count **5** — another reason this is a card in
  panel 1 and not a sixth tab.
- A grep of the sibling clones on 2026-10-20 for `Mantin|second.?byte bias` found only
  citations (this lab's README [R6]; a biography line in `crypto-lab-shamir-gate`). Re-run
  it before building.

## What to add

A card titled **"The cipher on its own: the second byte leans toward zero"**, after the
vector table in panel 1. It closes the gap between "passes RFC 6229" and "RFC 7465 forbids
it" with a measurement the reader runs.

1. **Measure it.** Draw `n` fresh 16-byte keys from `crypto.getRandomValues`
   (`n` selectable: 2¹² / 2¹⁴ / 2¹⁶ / 2¹⁸; default 2¹⁶), run the lab's own `ksa` +
   `Rc4Keystream.next(2)` for each, and count how often the **second** output byte is 0.
   Show the count, the rate as a multiple of 1/256, and a 95% Wilson interval. Beside it,
   the same count for a **control**: the second byte of `n` 2-byte strings straight from
   `crypto.getRandomValues`. Draw a 256-bin histogram of the RC4 second byte with bin 0
   called out. Expected (measured while writing this, not a result to cite): about
   2.0 × (1/256) for RC4 at 2¹⁸ keys, about 1.0 × for the control. Run the loop in chunks
   or a worker so the page stays responsive; report elapsed time.
2. **Show why (the headline mechanism).** Katz–Lindell's derivation: if the initial
   permutation has `S₀[2] = 0` and `S₀[1] = X ≠ 2`, the second output byte is exactly 0.
   A "Find such a key" button draws random keys until `ksa` produces that state (about 1 in
   256 tries — report the count), then replays the two PRGA rounds with the panel's existing
   step renderer: round 1 sets `j = X` and swaps so `S₁[X] = X`; round 2 sets `j = X + 0 = X`,
   swaps `0` into position `X`, and outputs `S₂[S₂[2] + S₂[X]] = S₂[X] = 0`. Then a
   one-line split of the measurement from step 1: of the keys whose `S₀` met the condition,
   how many gave `Z₂ = 0` (all of them — the page computes and prints it), versus the rest
   (≈ 1/256). That split is the probability sum Katz–Lindell write down, made from the
   reader's own sample.
3. **What it is worth (prose).** One short paragraph: a bias of 2/256 distinguishes RC4
   from random, and Mantin and Shamir turned it into recovery of the second plaintext byte
   when the same message is encrypted under many keys (FSE 2001); later work found many more
   biases and recovered plaintext from RC4 in TLS (AlFardan et al., USENIX Security 2013),
   and RFC 7465 then prohibited RC4 cipher suites. No numbers from those papers beyond what
   is cited below; no executed broadcast attack in this pass.

**Plain-language intro (no math):** A good stream cipher's bytes are equally likely to be
any of 256 values. RC4's second byte is not: it is zero about twice as often as it should
be. Count it yourself, then step the two moves inside RC4 that cause it.

## Why it belongs here and not in a new lab

The lab's README already claims RC4 has weaknesses beyond WEP and cites RFC 7465 for it;
panel 1 already has the real cipher, its trace, and the stepper. This card turns an
asserted sentence into a measured one, with nothing new to build but a counter.

## SECURITY / CORRECTNESS INVARIANTS

1. The card uses the lab's existing `ksa` / `Rc4Keystream` — no second RC4.
2. Keys come from `crypto.getRandomValues`; the control comes from the same source; both
   counts are reported with their `n` and interval, never as a bare percentage.
3. The bias verdict is computed from the counts (interval excludes 1/256 or not), not
   asserted: at small `n` it may honestly read "not yet distinguishable".
4. The conditioned split (step 2) is exact, not statistical: every key meeting the
   condition must give `Z₂ = 0`; if one does not, the card shows a failure, not a pass.
5. The existing `TEST VECTOR MATCH` scope note and the five tabs are unchanged.

## ARCHITECTURE

- `src/rc4/bias.ts` — pure functions: `secondByteZeroCount(n, keySource)`,
  `wilsonInterval(k, n, z = 1.96)`, `meetsKlCondition(s0)` (`s0[2] === 0 && s0[1] !== 2`),
  `findConditionedKey(rng, maxTries)`.
- `src/rc4/bias.test.ts`.
- `src/ui/panel1Rc4.ts` — append the card; reuse `verdict`, `card`, `field`, `byteBlock`
  from `src/ui/dom.ts` and the existing PRGA step rendering.
- `// [extension] point`s: (a) in `bias.ts` for a per-position bias scan of the first 256
  bytes (the AlFardan et al. picture); (b) beside the key source for a "WEP per-packet
  keys (IV ‖ shared key)" source — the FMS extension the README already promises.

## UI

Controls: sample-size select, "Measure", "Find a key with S₀[2] = 0", "Step two rounds".
Outputs: two count rows (RC4, control) with rate and interval; histogram with an
accessible table fallback (256 bins in a scrollable `role="region"` with `tabindex="0"`
and an `aria-label`); the conditioned split line; the two-round stepper reusing panel 1's
permutation drawing. Live region for progress. Stacks below 640px.

## VISUAL SEMANTICS

- RC4 interval excluding 1/256 → `alarm` chip, text **"BIASED: Z₂ = 0 at about 2/256"**
  (computed multiple shown). Not `pass`: a reproduced weakness is an alarm about the cipher.
- Control interval containing 1/256 → `neutral` chip, "CONTROL: consistent with 1/256".
- Small `n`, overlapping intervals → `neutral`, "NOT YET DISTINGUISHABLE at n = …".
- Conditioned split all-zero → `alarm`, "EVERY KEY WITH S₀[2] = 0 GAVE Z₂ = 0".
- Never colour alone; the histogram's bin 0 is marked by label and pattern, not hue.

## EDGE CASES

| Situation | Behaviour |
|---|---|
| `crypto.getRandomValues` unavailable | refuse with a message; no fallback RNG |
| Measurement cancelled or tab hidden mid-run | stop; report the partial `n` actually run and mark the verdict partial |
| `findConditionedKey` exceeds its try budget (e.g. 10,000) | report tries used and stop; never fabricate a state |
| Re-running with the same `n` | new keys, new counts; previous verdict retired and labelled as such |
| A conditioned key with `Z₂ ≠ 0` | `fail` chip naming the key — that would be an implementation bug, and the page must say so |

## Tests

**KATs:** the existing RFC 6229 rows (both key families, offsets past 256 in one
continuous stream) remain the KATs for the cipher this card uses; no new vectors are
needed and none should be invented.

**Vitest (`src/rc4/bias.test.ts`):**
- the conditioned property holds for every key found in a few thousand draws (exact);
- on a fixed `n` (e.g. 2¹⁶), the RC4 count's Wilson interval excludes 1/256 and the point
  estimate lies between 1.5× and 2.5× of 1/256 — measured, like `ptw.test.ts:68`, with
  wide margins (at 2¹⁶ the expected gap from 1/256 is about 16 standard deviations). Do
  **not** assert that a 95% interval contains 2/256 or that the control's contains 1/256:
  each of those fails about one run in twenty by construction. State the false-failure
  probability of every statistical assertion in a comment;
- the control's point estimate lies between 0.5× and 1.5× of 1/256;
- `wilsonInterval` against values computed by hand for small `k, n`.

**`e2e/claims.spec.ts` additions** (independent re-derivation: a minimal RC4 written in the
test file, not imported):
- the step-2 key shown on screen gives `S₀[2] = 0`, `S₀[1] ≠ 2` and `Z₂ = 0` under the test's
  RC4; the two stepped frames match the test's state after each round;
- the counts rendered sum correctly (RC4 histogram bins sum to `n`; bin 0 equals the printed
  count) and the printed interval equals the test's Wilson computation from the printed
  `k, n`;
- the verdict tone follows the printed interval (alarm iff it excludes 1/256);
- re-running retires the previous verdict.

**§4.1c** — add patches to `scripts/mutations.mjs` in its existing format, each with a named
owner:
1. Count the **first** byte instead of the second → the conditioned-property test fails.
2. Swap the RC4 source for the control source → the bias Vitest test fails.
3. Hard-wire the verdict to `alarm` → the "tone follows interval" claims test fails at small `n`.

**§4.1d:** the card's sentence for the lab's page-wide scope note —
> *"Passing every RFC 6229 vector does not make RC4 a sound cipher: the same verified
> implementation shows its second byte is zero about twice as often as chance."*

Fixture: the vector table reads `TEST VECTOR MATCH` on all rows **and** the bias card reads
`BIASED` at the default `n`, on screen together. Assert both, and the sentence. Delete the
sentence → the test fails; break the vector match → the test fails. (This sits beside the
lab's existing negative claim about WEP's ICV; it does not replace it.)

## README and card follow-up

- "What It Is" → no change. "What it does NOT prove", first bullet: append "— panel 1
  measures one such weakness, the second-byte bias, live."
- "Exhibits", item 1: add the bias card in one sentence.
- "Primary Sources": add Mantin–Shamir and AlFardan et al. (below); keep the R-numbering
  scheme the README already uses.
- Catalog handoff (do not edit `../crypto-lab`): no new algorithm; the card's attack list
  could gain `Distinguishing attack (RC4 second-byte bias)`.

## Do not touch

`src/rc4/rc4.ts` and `src/rc4/vectors.ts` behaviour, the WEP, collision, forgery and PTW
panels, the five-tab structure, the existing mutation cases, header, theme pin, footer.

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369): §7.1.4, Algorithms 7.1–7.2 and the derivation of
  `Pr[Z₂ = 0] ≈ 2/256` from the event `S₀[2] = 0, S₀[1] ≠ 2`.
- I. Mantin, A. Shamir, "A Practical Attack on Broadcast RC4", FSE 2001, LNCS 2355,
  pp. 152–164, doi:10.1007/3-540-45473-X_13. Verified at
  https://www.iacr.org/cryptodb/data/paper.php?pubkey=3134 (the PDF did not load here;
  quote no figure from the paper body without reading it).
- N. AlFardan, D. J. Bernstein, K. G. Paterson, B. Poettering, J. C. N. Schuldt, "On the
  Security of RC4 in TLS", 22nd USENIX Security Symposium, 2013, pp. 305–320. Verified at
  https://usenix.org/conference/usenixsecurity13/security-rc4-tls
- RFC 6229 (Strombergson, Josefsson, May 2011) and RFC 7465 (Popov, February 2015) — already
  cited by the lab as [R1] and [R2] with rfc-editor.org links; RFC 7465's title and author
  re-checked at https://datatracker.ietf.org/doc/html/rfc7465
