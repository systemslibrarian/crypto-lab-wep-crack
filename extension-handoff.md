# WEP Crack — RC4 second-byte bias extension

Brief: `brief-extension.md`. Slug: `crypto-lab-wep-crack`.
Starting main: `cb9df00f7c243151940371b7c478825f83685693`.
Pages: https://systemslibrarian.github.io/crypto-lab-wep-crack/

## Delivered

A card after Panel 1's existing RFC 6229 comparisons measures fresh 16-byte-key
RC4 second bytes alongside an independently drawn uniform control. It shows
counts, rates, baseline multiples, Wilson intervals, all 256 histogram bins,
and the exact conditioned split S0[2]=0, S0[1]≠2. The conditioned-key search
reports actual tries and replays two real PRGA frames through the existing
permutation renderer, extracted without changing its drawing behavior.

Chunking keeps the page responsive. Cancellation and hiding the panel retain
only the actual partial sample count; new runs and changed budgets retire prior
results. Missing crypto RNG and exhausted search budgets are explicit failures.
A control interval excluding chance is reported honestly, with no false secure
claim. A correct RFC implementation and a statistically biased cipher are
shown together as the negative fixture.

The original RC4 implementation and vectors, WEP/forgery/collision/PTW panels,
five-tab structure, existing mutation cases, header/theme/footer are preserved.

## Verification

- Build passed; 153 unit tests and all 56 Chromium browser tests passed.
- The unit suite uses wide statistical margins with stated model-based
  false-failure bounds, exact conditioned checks, and Wilson boundary checks.
- §4.1a: gate drives the real measurement, table, conditioned state and both
  steps; setup remains structural.
- §4.1b: independent RC4 recomputes the key's initial state and both full
  256-element permutations. The claims suite independently derives intervals,
  counts histogram totals and verifies every visible verdict, cancellation and
  retirement. A declared input fixture exercises the neutral interval branch.
- §4.1c: 7/7 concrete mutations killed. `extension-mutation-report.json` records
  passing baseline, nonempty patch, successful build and changed hash, named
  owning assertion failure, restored source/hash and restored passing test.
  One earlier baseline attempt failed and was not counted; the final full run
  passed every baseline and restoration.
- §4.1d: all 24 RFC vector rows and measured bias are asserted beside the
  explicit limitation sentence. Removing that sentence is independently killed.
- Accessibility: existing desktop/380px scans and the new full 320px scan pass.
  Visual inspection found squeezed labels; a scoped block layout fixed them,
  and the 320px scan passed again. No new contrast exemptions.
- Local installed Chromium 153.0.8010.0 is selected through an ignored config
  because the pinned download endpoint is unavailable. Original CI unchanged.
- Sources: IACR Mantin–Shamir bibliographic record (no paper-body figures quoted),
  AlFardan et al. USENIX 2013 primary page, and existing RFC 6229/7465 references.

## Catalog handoff — no shared catalog edits

No new algorithm chip. Suggested attack-list addition:
`Distinguishing attack (RC4 second-byte bias)`.
Suggested card text: “Measure RC4's second-byte bias beside passing published
vectors, then step through the permutation condition that forces a zero byte.”
Implemented: `src/rc4/bias.ts:7` condition, :8 Wilson interval, :18 measurement,
:24 existing KSA/PRGA calls, :39 conditioned search; `src/ui/biasCard.ts` renders
actual measurements and frames. Prose only: broadcast and TLS recovery attacks.
Concept deepened: pseudorandomness and distinguishing attacks on stream ciphers.
README changes extend existing Exhibits and R-numbered Primary Sources sections.

Final remote commit and served-byte evidence are recorded after publication.
The shared fleet deploy-sync checker remains blocked by missing unrelated
sibling clones; no shared census/checker/catalog/counsel content was changed.
