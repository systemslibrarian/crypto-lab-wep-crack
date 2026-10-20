# WEP Crack

Interactive browser demo of **WEP's failure as a system** — hand-rolled RC4 and
CRC-32, the WEP protected-body construction, keystream reuse through a repeated
IV, a forged packet the genuine integrity check accepts, and a real PTW
implementation that recovers the 104-bit shared key from locally generated
traffic.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-wep-crack/

## What It Is

A teaching exhibit, **not production crypto**.

The primitives are real and hand-rolled, because they are the teaching subject:
**RC4** (KSA and PRGA, in `src/rc4/rc4.ts`) and the reflected IEEE **CRC-32**
(`src/wep/crc32.ts`). The construction is WEP's: a 3-byte public IV prepended to
a 5- or 13-byte shared key to form the RC4 per-packet key, a CRC-32 of the
plaintext payload serialised little-endian as the ICV, and
`IV || keyIdByte || RC4(payload || ICV)` as the protected body. Key recovery is
an actual implementation of **PTW** (Tews, Weinmann and Pyshkin, 2007), not a
simulation of one.

**The core lesson:** a correctly implemented cipher can still be part of a
broken cryptographic system. RC4 here passes every published test vector. WEP
still falls, because the system around the cipher repeats per-packet keystream,
checks integrity with an unkeyed linear checksum, and hands the attacker the
first three bytes of every RC4 key.

**Security model.** All traffic is generated locally by the page. There is no
radio capture, no monitor mode, no injection and no capture-file import — a
deliberate scope boundary, not an unfinished feature. The simulated attacker
runs in a worker that receives captured protected bodies and the published
traffic-profile assumptions, and never the shared key, the generator's state,
any plaintext, or a callable reference to the generator. A separate experiment
controller holds ground truth and makes the final byte-for-byte comparison.
That separation is real as a matter of data flow — it is what makes the recovery
a result rather than a lookup — but it is **not** a security boundary: these are
experimental roles inside one browser tab, and hiding a value in an interface
does not make it inaccessible to someone inspecting their own browser.

### What is modelled, and what is not

Modelled: the **WEP protected body** — the clear IV and Key ID field, and the
encrypted payload and ICV.

Not modelled: the 802.11 MAC header, the outer frame check sequence, radio
metadata, retransmissions and physical capture. This is **not a complete on-air
frame** and **not a capture-file format**. The encrypted ICV is not the outer
802.11 FCS.

Synthetic traffic reproduces the cryptographic construction and the attack's
assumptions. Its packet mix, IV policy and known-plaintext availability are
chosen by this lab, so its statistics are not those of arbitrary real traffic.

### What it does NOT prove

- **Not that RC4 is sound.** Passing RFC 6229 vectors establishes agreement with
  a specification. RC4 has cryptographic weaknesses beyond anything WEP does
  with it, and RFC 7465 prohibits RC4 cipher suites in TLS. Nothing here implies
  that fresh keys plus a MAC would rehabilitate RC4 as a modern design choice — panel 1 measures one such weakness, the second-byte bias, live.
- **Not that a patched WEP would be safe.** There is no "secure WEP" setting.
  The separate obligations are sound key and nonce handling, cryptographic
  authentication, and a sound primitive and construction.
- **Not that a passing integrity check means anything about authenticity.**
  That is this lab's stated negative claim, and panel 4 is its evidence:

  > A valid WEP integrity check does not establish that a message is authentic
  > or unmodified.

- WPA/WPA2/WPA3, TKIP, chopchop and fragmentation attacks are outside this
  experiment. **FMS and KoreK are future extensions and are not implemented.**

## Exhibits

1. **RC4 itself** — step the actual KSA swaps and PRGA output, with the real
   256-byte permutation drawn and the current `i`, `j` and output index marked.
   Every frame is executed state, read back from the cipher's own trace. All 24
   RFC 6229 expected-byte rows are computed and shown beside the published
   bytes; a pass reads `TEST VECTOR MATCH`, scoped on screen to implementation
   correctness. The second-byte bias card compares fresh-key RC4 output with a random control, shows a Wilson interval and histogram, and replays the exact conditioned two-round mechanism.
2. **Wrap it in WEP** — build the protected body step by step: the IV-prepended
   per-packet key, the CRC-32 of the plaintext, the little-endian ICV, the
   serialised body, and the receiver's genuine verification. Both shared-key
   sizes work here, with the WEP key size and the RC4 key length reported as the
   separate quantities they are.
3. **Keystream reuse** — generate traffic under one key and the declared IV
   policy, and wait for a *real* repeated IV. Until one occurs the panel reports
   `NO COLLISION OBSERVED YET`. When one does, XOR the aligned ciphertexts to
   get `C1 XOR C2 = P1 XOR P2`, then drag a disclosed crib across it to derive
   candidate bytes in the other message. Candidates stay marked unverified; a
   separate ground-truth reveal is marked revealed and never counted as
   recovery.
4. **Forge a packet** — the negative claim's evidence fixture. First the
   control: flip a payload bit and leave the ICV alone, and the receiver
   rejects. Then apply the affine CRC correction — computed from the
   modification alone, with no key and no plaintext — and the *same* receiver
   accepts a packet whose decrypted message has changed. The verdict reads
   `ICV VALID — AND FORGED`, as an alarm, with the claim sentence beside it.
5. **Recover the key** — a fresh 104-bit session key, traffic under the
   LLC/SNAP + ARP-request profile, and a real PTW run in a worker. The vote
   tables are inspectable with each sum's noise floor beside its leader. The
   attacker reports a *validated candidate* after checking it against reserved
   distinct-IV packets; only the controller's byte-for-byte comparison renders
   `WEP KEY RECOVERED`. A validated candidate that is not the key is an
   experiment failure, not a recovery.

## When to Use It

Use it to teach that cryptographic engineering is a systems problem: to show
why a nonce or IV must not repeat, why integrity needs a *keyed* primitive
rather than a checksum, and why "we used a real cipher" is not a security
argument.

**Do NOT use it** as an attack tool against any network. It accepts no bytes
from outside the page, by design, and the extension seams for real frame intake
are deliberately unimplemented. And do not use WEP: it has been broken since
2001 and deprecated for most of that time.

## What Can Go Wrong

The whole lab is a catalogue of this, but the three failures it demonstrates
directly:

- **A 24-bit IV repeats.** Under uniform random draws a collision arrives at a
  few thousand packets, well before the space is exhausted — the birthday bound,
  not an operator mistake. Two packets under the same IV and key share a
  keystream, so XORing their ciphertexts cancels it and leaves the XOR of the
  plaintexts. (A single uninterrupted counter would behave differently: a 24-bit
  field does not by itself oblige an early collision, the *policy* decides, and
  the page states which policy it used.)
- **An unkeyed checksum cannot authenticate.** CRC-32 with a fixed initial
  register and final XOR is affine at a fixed length, so
  `CRC32(P XOR D) XOR CRC32(P) = CRC32(D) XOR CRC32(zeros(n))` — a correction
  term the attacker computes from `D` alone. Encrypting the ICV does not help:
  the keystream cancels out of the correction too.
- **The IV is part of the RC4 key.** Three bytes of every per-packet key are
  public, which makes the key schedule's statistical weaknesses exploitable.
  PTW votes on the running sums of the secret key bytes, one vote per captured
  packet, and ranks candidates until one validates.

## Real-World Usage

WEP shipped in IEEE 802.11-1997 and protected the majority of wireless networks
for roughly a decade — the PTW paper's own survey found 46.3% of networks still
on WEP in March 2007, *after* the attacks were public. Borisov, Goldberg and
Wagner published the message-modification and keystream-reuse analysis in 2001;
Fluhrer, Mantin and Shamir published the key-scheduling weakness the same year;
PTW reduced 104-bit key recovery to under a minute in 2007. WEP was withdrawn
in favour of WPA2 and later WPA3, and RC4 itself was prohibited in TLS by RFC
7465 in 2015.

## How to Run Locally

```bash
npm install
npm run dev          # serves the demo
npm test             # unit and known-answer tests
npm run build        # tsc --noEmit && vite build
npm run test:a11y    # the WCAG 2.1 AA gate (builds first)
npm run test:claims  # the rendered-claims suite
npm run mutations    # prove the tests bite (see Build & Verify)
```

Playwright needs its browser once: `npx playwright install chromium`.

The **Start the walkthrough** link enters the five exhibits in order; **See the
forgery** jumps straight to the accepted message modification. Previous/next
controls and arrow-key tab navigation keep the active exhibit in the URL
(`/#rc4`, `/#wep`, `/#collision`, `/#forge`, `/#ptw`), so an exhibit can be
bookmarked or shared. Session keys and traffic are never saved in the URL.
Scope notes and all 24 vector comparisons are available in expandable sections.

The RC4 slider jumps to actual executed KSA or PRGA state. Invalid keys clear
that state and explain the required format. PTW generates traffic in yielding
batches, so progress remains visible and collection can be cancelled. Cancelling
an active search terminates its worker immediately; resetting the session also
releases the worker and restores the controls. Interrupted runs do not display
unavailable final measurements.

## Build & Verify

**200 tests pass** — 149 unit and known-answer tests under Vitest, plus 38
rendered-claim tests and 11 interaction regressions under Playwright, plus the
2-test accessibility gate. `npm run test:claims` runs both browser claim and
interaction suites; `npx playwright test` runs all browser checks together.

The interaction regressions cover bookmarked exhibits, browser history,
keyboard navigation, the full RC4 key-length contract, field-specific errors,
typing and cursor preservation, cancellation during traffic collection and
worker search, session resets, worker startup failure, and reflow at 320px.

The evidence behind the numbers, all of it external to this repo:

- **RC4** reproduces all **24** RFC 6229 expected-byte rows across 6 keys, 3 key
  sizes and the RFC's two independent key families (`src/rc4/vectors.ts`,
  transcribed from rfc-editor.org). Each row is driven through one
  `Rc4Keystream`, so the offsets are read as stream positions rather than
  blocks — a generator that silently re-keyed per chunk would match offset 0 and
  fail offset 240. RC4 also reproduces the PTW paper's own worked KSA example
  for key `CA FE BA BE`.
- **CRC-32** hits the published check values (`CRC32("123456789") = 0xCBF43926`,
  and 0 for empty input) and agrees with a table-free bit-at-a-time routine over
  300 inputs. The affine-difference identity is checked across 11 payload
  lengths and 132 masks, and a bare `CRC32(D)` is shown *not* to be the
  correction term.
- **The WEP protected-body fixtures are sourced outside this repo.** With IV
  `01:02:03` the per-packet keys are byte-for-byte RFC 6229 section 2's 64- and
  128-bit test keys, so the RFC publishes these keystreams outright; the ICV
  literal is CPython `zlib.crc32`'s output. `wepEncrypt` is checked against
  those bytes rather than against itself, because a round trip alone can conceal
  matching encoder and decoder mistakes. Serialisation follows Linux
  `net/mac80211/wep.c`.
- **Attacker separation** is checked four ways, because an import scan presented
  as proof of isolation is not proof: the worker's import graph is walked on
  disk and must not reach a stateful generator module; `assertCaptureOnly`
  inspects the real runtime message *inside the worker*, rejecting prohibited
  field names at any depth and any callable; the attack is run from a JSON round
  trip with no generator in scope and still recovers; and duplicate IVs are
  shown not to inflate vote counts.
- **The accessibility gate** scans the production build for zero WCAG 2.1 A/AA
  violations, and also asserts axe's `incomplete` bucket, computes contrast
  arithmetically over every text node (including `aria-hidden` content, which
  both axe and the default walk skip), measures non-text contrast on every
  control boundary, and checks 1.4.10 reflow at 380px. It was proved to bite:
  degrading `--control-border` to the decorative divider value made it fail
  naming `NEW 1.37:1 (needs 3:1) [control-boundary]` on every button, input and
  tab, with the build still succeeding.
- **Mutation discipline: 10 of 10 killed** (`npm run mutations`). Each of the
  brief's faults is a concrete patch with a named owning test, and a kill
  requires all five of: the owning test passing unmutated in the same run, a
  non-empty source diff, a build that *succeeds* with the bundle hash moved,
  the named test failing, and a clean restore that goes green again. A patch
  that does not compile is `DOES NOT BUILD` and is never a kill; a red run that
  matches a build error or a refused connection is `INCONCLUSIVE` rather than
  counted. The runner writes its own records to `mutation-report.json`.

### Measured PTW results

Recovery is **probabilistic**, and these are this implementation's own
measurements — not the paper's figures. Measured 2026-10-06 on Apple silicon
(arm64) under Node 24, with the paper's three search scenarios and a
200,000-candidate budget:

| Packets | Recovered | Attempted |
| ------- | --------- | --------- |
| 20,000  | 0         | 8         |
| 40,000  | 3         | 8         |
| 50,000  | 10        | 12        |
| 60,000  | 11        | 12        |
| 70,000  | 8         | 8         |

In the browser, a fresh random 104-bit key recovered from 60,000 packets in
**908 ms** end to end (629 ms of attack after 2 candidates in a later run).

The PTW paper reports recovery from fewer than 40,000 packets in **50% of
cases** under its own stated conditions, with all three scenarios and a
1,000,000-key limit. That is a probabilistic result from that paper's
experiments: it is not a guarantee, not a browser benchmark, and not a claim
about this implementation.

**Declared departures from the paper**, so its figures are not borrowed: the
strong-byte scenarios here assume only the top one and two most-likely-strong
sums rather than searching further; the candidate cap is 200,000 rather than a
million; 40-bit recovery is outside stage 1; and candidate validation is
*stricter* than the paper's — the known keystream prefix **and** the genuine WEP
ICV on reserved distinct-IV packets, where the paper used six keystream bytes on
ten random sessions. Failure to recover does **not** prove that more packets
were the only thing missing: for a strong key byte the correct value's votes are
equidistributed, so more samples never help that sum.

## Performance

Generating 60,000 protected bodies takes roughly 200–650 ms in the browser; the
PTW run itself is typically 70–700 ms when it succeeds and is bounded by a
200,000-candidate and 30-second budget when it does not. The attack runs in a
dedicated worker with progress and cancellation, so the page stays responsive.

## Related Demos

- [OTP Vault](https://systemslibrarian.github.io/crypto-lab-otp-vault/) — the
  two-time-pad reasoning behind panel 3, and crib assumptions, on a keystream
  that is a deliberate stand-in rather than a real cipher.
- [ChaCha20 Stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/)
  — nonce reuse with a real modern stream cipher.
- [Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) —
  AES-GCM nonce misuse, including GHASH authentication-key recovery, which is
  why keystream reuse is not only ever a plaintext problem.
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — the
  authenticated-encryption lesson, and which AES modes do *not* provide
  integrity.
- [Padding Oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)
  — another concrete attack on a protocol's *use* of cryptography rather than on
  its cipher.

## Primary Sources

- **[R1]** Strombergson and Josefsson, [RFC 6229: Test Vectors for the Stream
  Cipher RC4](https://www.rfc-editor.org/rfc/rfc6229.html), May 2011.
- **[R2]** Popov, [RFC 7465: Prohibiting RC4 Cipher
  Suites](https://www.rfc-editor.org/rfc/rfc7465.html), February 2015.
- **[R3]** Tews, Weinmann and Pyshkin, [Breaking 104 bit WEP in less than 60
  seconds](https://eprint.iacr.org/2007/120), 2007 — section 3.1 for Klein's
  map, section 4 for the extension to sums, section 5 for the ARP assumption,
  section 6 for ranking and strong keys, section 7 for the measured results.
- **[R4]** Linux,
  [`net/mac80211/wep.c`](https://github.com/torvalds/linux/blob/master/net/mac80211/wep.c)
  — IV/Key ID serialisation, IV-prepended RC4 keying, little-endian encrypted
  CRC ICV.
- **[R5]** Deutsch, [RFC 1952 section
  8](https://www.rfc-editor.org/rfc/rfc1952.html) — the reflected CRC-32 routine
  and its initialisation/finalisation convention.
- **[R6]** Fluhrer, Mantin and Shamir, *Weaknesses in the Key Scheduling
  Algorithm of RC4*, SAC 2001 — background for the future FMS extension.
- **[R7]** Borisov, Goldberg and Wagner, *Intercepting Mobile Communications:
  The Insecurity of 802.11*, MobiCom 2001 — the original WEP analysis and
  message-modification result.
- **[R8]** IEEE 802.11-1997, the WEP construction.
- **[R9]** Mantin and Shamir, [A Practical Attack on Broadcast RC4](https://www.iacr.org/cryptodb/data/paper.php?pubkey=3134), FSE 2001, LNCS 2355, pp. 152–164, doi:10.1007/3-540-45473-X_13. Bibliographic record verified; no paper-specific recovery figures are quoted.
- **[R10]** AlFardan, Bernstein, Paterson, Poettering and Schuldt, [On the Security of RC4 in TLS](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/alfardan), USENIX Security 2013, pp. 305–320. The authors report plaintext-recovery attacks; this card executes only the bias measurement.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
