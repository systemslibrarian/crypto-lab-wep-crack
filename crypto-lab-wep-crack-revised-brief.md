# Build brief — `crypto-lab-wep-crack`

**Revision 2 · 2026-10-06 · Full replacement brief.**

Build a Crypto Lab browser exhibit called **WEP Crack**. This document specifies the work; it does not claim that a repository has been created or that the implementation has passed any tests.

Read the target repository's instructions and the current `audits/_MASTER-TEMPLATE.md` in [systemslibrarian/crypto-lab](https://github.com/systemslibrarian/crypto-lab) before implementation. The master template governs build, teaching, appearance, accessibility, claims testing, documentation, and deployment. Apply its full lifecycle. Report a material conflict rather than silently weakening a requirement. Use Vite and TypeScript, with a static frontend and no backend.

## 1. Decision and learning goal

**Recommended home: a new repository, `crypto-lab-wep-crack`.**

The justification is a coherent protocol experiment: build a WEP protected payload, demonstrate keystream reuse, forge a message that passes the genuine integrity check, and recover the shared key using PTW. This is broader than adding an RC4 selector to an existing stream-cipher lab.

The CrypTool 2 WEPAttacks component supplied the initial lead. It is a comparison point, not the justification for the exhibit or a substitute for the original research.

Before building, refresh the overlap check against the current catalog and relevant lab source. Search `RC4`, `WEP`, `802.11`, `CRC-32`, `ICV`, `FMS`, `PTW`, and `KoreK`, then inspect the implementations behind plausible matches. Catalog wording is discovery evidence, not proof of implementation or absence. If another lab now demonstrates the same WEP construction, forgery, and key-recovery experiment, reassess the proposed home before creating a duplicate.

The earlier source review identified these neighboring lessons:

| Lab | Relevant existing lesson | Relationship to this brief |
| --- | --- | --- |
| OTP Vault | Two-time-pad XOR and crib dragging; its reuse panel identifies its keystream as a stand-in | Link to the reasoning behind panel 3 |
| ChaCha20 Stream | Nonce reuse with a real modern stream cipher | Compare repeated keystream across constructions |
| Nonce Guard | AES-GCM nonce reuse, including GHASH authentication-key recovery | Explain that confidentiality and authenticity can both fail; do not describe this lab as only plaintext recovery |

Recheck the earlier source locations: OTP Vault's `src/otp/cribdrag.ts` and `src/ui/keystreamReusePanel.ts`; ChaCha20 Stream's `src/cipher.ts` and `src/ui.ts`; Nonce Guard's `src/crypto.ts`. Record the reviewed commits and actual findings in the normal implementation report.

**Core lesson:** A correctly implemented cipher can still be part of a broken cryptographic system. In WEP, repeated per-packet keystream exposes relationships between messages, the CRC-based integrity check permits deliberate alteration, and statistical weaknesses exposed by its RC4 keying allow recovery of the shared secret.

**Required negative claim:** “A valid WEP integrity check does not establish that a message is authentic or unmodified.”

Passing RC4 known-answer tests establishes agreement with specified outputs. It does not establish security. RC4 has cryptographic weaknesses beyond WEP, and RFC 7465 prohibits RC4 cipher suites in TLS. Do not suggest that fresh keys and a MAC rehabilitate RC4 as a modern design choice. [R2]

## 2. Demo metadata and scope

| Field | Value |
| --- | --- |
| Repository | `crypto-lab-wep-crack` |
| Short name / H1 | WEP Crack |
| Subtitle | RC4 · WEP integrity failures · PTW key recovery |
| One-liner | Builds WEP protected payloads with real RC4 and CRC-32, demonstrates accepted forgeries, and runs PTW key recovery against generated traffic. |
| Category | ATTACKS proposed; confirm through the catalog's assignment rules |
| Level | Advanced, with a plain-language entry path |
| Accent and favicon | Assign through the existing fleet rules |
| Primitives and construction | RC4 KSA/PRGA; WEP per-packet keying; CRC-32 ICV; PTW |
| First-release recovery target | A 104-bit WEP shared key |

**Stage 1 includes:** inspectable RC4; RFC 6229 vectors; WEP protected-body construction and parsing; 40-bit and 104-bit shared-key handling in the WEP wrapper; random-IV collisions; ciphertext alteration with ICV repair; and complete PTW recovery for the 104-bit profile.

**Outside stage 1:** FMS and KoreK implementations; 40-bit PTW recovery; radio capture, monitor mode, injection, and capture-file import; WPA/WPA2/WPA3; TKIP; chopchop and fragmentation attacks. Name FMS and KoreK as future extensions without advertising them as implemented.

## 3. Experiment boundaries

All attack traffic is generated locally. Stage 1 models the **WEP protected body**, including the clear IV/Key ID field and encrypted payload/ICV. It does not construct or transmit a complete 802.11 radio frame. The MAC header, outer frame check sequence, radio metadata, retransmissions, and physical capture process are outside this model.

Label this boundary on the page and in the README. Use “WEP protected body” or “modeled WEP packet” where precision matters. Do not claim complete on-air frame fidelity or capture-file compatibility.

Synthetic traffic can reproduce the selected cryptographic construction and attack assumptions. Its packet mix, IV policy, known-plaintext availability, and loss behavior are chosen by the lab. Do not claim its statistics are identical to arbitrary real network traffic.

The recovery experiment must use a new session key. Keys exposed in the RC4 or construction walkthrough must never become the supposedly hidden recovery key. The simulated attacker receives captured bytes and the published traffic-profile assumptions. A separate experiment controller retains ground truth for the final comparison.

These are experimental roles inside a browser application. Hiding a value in the interface does not make it inaccessible to a person inspecting their own browser.

## 4. WEP construction contract

### Keys and serialization

Keep the WEP shared key separate from the RC4 per-packet key:

| Quantity | Size / construction |
| --- | --- |
| WEP shared key | 5 bytes (40 bits) or 13 bytes (104 bits) |
| IV | 3 bytes (24 bits), public |
| RC4 per-packet key | `IV || sharedKey`: 8 or 16 bytes (64 or 128 bits) |
| Clear WEP prefix | 3-byte IV followed by one Key ID/reserved byte |
| ICV | 4-byte CRC-32 of the plaintext payload, serialized little-endian |
| Protected body | `IV || keyIdByte || RC4(plaintext || ICV)` |

The Key ID occupies the upper two bits of its byte; use zero reserved bits for the stage-1 profile. Keep one key slot per experiment. The Key ID byte is transmitted but is not part of the RC4 key. Do not confuse the encrypted ICV with the omitted outer 802.11 FCS. [R4]

The **WEP wrapper** enforces the 5/13-byte shared-key restriction. The generic RC4 core has its own documented input contract and must accept the lengths required by the standalone vectors and per-packet keys. Never restrict the RC4 core itself to “40/104-bit WEP keys.”

Use ordinary WEP RC4 from the first keystream byte. Do not add RC4-drop or another modification that changes the construction being attacked.

### CRC-32 parameters and repair

Implement the reflected IEEE CRC-32 convention: normal polynomial `0x04C11DB7` (reflected representation `0xEDB88320`), initial register `0xFFFFFFFF`, reflected processing, and final XOR `0xFFFFFFFF`. The check value for ASCII `123456789` is `0xCBF43926`; the empty input gives zero. Verify the routine against an independent reference, then verify ICV byte order in a WEP fixture. [R4, R5]

The conventional initialized/finalized CRC function is **affine at a fixed length**. Its XOR difference is linear. For an `n`-byte payload `P` and an `n`-byte XOR mask `D`:

```text
CRC32(P XOR D) XOR CRC32(P) = CRC32(D) XOR CRC32(zeros(n))

icvDelta = CRC32(D) XOR CRC32(zeros(n))
forgedEncryptedPayload = encryptedPayload XOR D
forgedEncryptedICV = encryptedICV XOR LE32(icvDelta)
```

Here `zeros(n)` means exactly `n` zero bytes, and `LE32` serializes a 32-bit value little-endian. This identity follows from cancelling the fixed initialization/finalization offset. A single `CRC32(D)` is not the required correction for this CRC API.

Panel 4 uses same-length modifications only. The attack computes the correction without the plaintext or key. The receiver decrypts and checks the ordinary WEP ICV through the same code path used for unmodified packets.

### IV policy

For the live collision and PTW experiments, generate independent uniform 24-bit IVs with replacement, using the browser cryptographic random source. State this policy. Use deterministic seeded generators only for clearly identified test fixtures.

Random IVs can collide before the space is exhausted. A single uninterrupted counter can traverse its space without repetition before wrapping; resets and multiple transmitters change that situation. Do not teach that every IV policy must produce an early birthday collision merely because the field has 24 bits.

Never shrink the IV space or silently insert a collision to accelerate the live experiment. A labeled reproducible collision fixture may be offered separately and must report its actual generated sequence and count.

## 5. Traffic profile and attacker inputs

Use a documented **LLC/SNAP plus Ethernet/IPv4 ARP-request profile** for stage-1 recovery. Its plaintext is the 8-byte LLC/SNAP prefix followed by a 28-byte ARP request. The first 16 payload bytes are predictable:

```text
AA AA 03 00 00 00 08 06  00 01 08 00 06 04 00 01
```

This is the source of the attacker's known plaintext. The original PTW work explains how recognizable ARP traffic supplies this prefix and hence 16 keystream bytes. [R3, §5]

Because this exhibit omits MAC headers, the packet class is an explicit, public property of the generated profile. Do not pretend the attacker identified ARP from unavailable fields. Keep the remaining address fields well formed; the attack must not receive their secret ground-truth values through an auxiliary argument.

The attack intake derives the known keystream prefix by XORing the captured encrypted prefix with the profile's expected bytes. Define supported lengths, Key ID, and profile assumptions before parsing.

Run attack computation in a dedicated worker with an explicit message contract. Its input may contain captured protected bodies, the public profile identifier, the declared key size, resource budgets, and a run identifier. It must not contain the shared key, generator seed/state, full plaintext, or a callable reference to the generator/controller. Candidate validation uses captured evidence, not an oracle that compares guesses with the hidden key.

Keep separate counts for total packets generated, packets supplied to the attacker, usable samples, duplicate IVs excluded, voting samples, and validation samples. Count each IV once for voting within the modeled single-key session. Reserve a small set of additional distinct-IV packets for candidate validation and exclude them from the vote totals.

An import check is only one guard. Review the complete data flow and test the worker boundary with capture-only inputs. Pure RC4/CRC helpers may be shared; stateful generator modules may not be imported into the attacker.

## 6. Five teaching panels

### Panel 1 — RC4 itself

Step through the actual KSA permutation swaps and PRGA output. Show the 256-byte permutation and the indices involved in the current operation, with a compact explanation of what changes. Animation must reflect executed state.

Compare computed keystream bytes with fixed RFC 6229 expected bytes. A passing result reads **TEST VECTOR MATCH**, with an adjacent explanation that this checks implementation correctness. Do not label it “RC4 secure.” The panel uses an inspection key separate from the recovery session. [R1]

### Panel 2 — Wrap it in WEP

Show how the IV, shared key, plaintext, CRC, and serialized protected body relate. Let the learner inspect the clear IV and Key ID, then step through encryption and the receiver's genuine verification.

Support both WEP shared-key sizes in this construction panel. Label the resulting RC4 key length separately. Indicate that panel 5 targets the 104-bit profile.

### Panel 3 — IV collision and keystream reuse

Generate traffic under one key using the declared IV policy. Detect a real repeated IV and show its two packet positions and the count observed. Until one occurs, report **NO COLLISION OBSERVED YET**.

XOR aligned ciphertext payload bytes to obtain the XOR of the corresponding plaintext bytes. Keep the encrypted ICV outside this plaintext display:

```text
C1 XOR C2 = P1 XOR P2
```

This does not identify both messages by itself. Let the learner supply or select an explicitly disclosed crib, derive candidate bytes in the other message, and distinguish assumptions from verified recovery. Never obtain unknown bytes by reading generator plaintext behind the interface.

A separate ground-truth reveal can check the learner's candidate. Mark revealed information as revealed, and do not count it as attacker recovery. Link to OTP Vault and ChaCha20 Stream for the shared reasoning.

### Panel 4 — Change a message and repair the ICV

Provide a chosen ciphertext bit change and display its same-length XOR mask. First show that applying it without the compensating ICV change causes the receiver's ICV check to fail. Then apply the correct repair term and pass the forged packet through the same receiver.

The receiver must accept the repaired packet, and the experiment must show that the decrypted payload differs from the original. The cryptographic verdict reads **ICV VALID — AND FORGED**, styled as an alarm because authenticity failed.

Keep this sentence visible beside the accepted forgery: **“A valid WEP integrity check does not establish that a message is authentic or unmodified.”** Receiver acceptance here means acceptance by the modeled WEP integrity check, not by every higher-layer application or network policy.

### Panel 5 — Recover the shared key with PTW

Generate a fresh 104-bit session key, collect the defined traffic, and run an actual PTW implementation. Recovery must work from distinct-IV samples; it must not depend on panel 3 finding a collision.

Make the mechanism inspectable: show how one usable sample changes the statistical vote tables, how leading values rank, and how a candidate is checked. Label the quantities being voted on accurately; do not mislabel votes for intermediate key-byte sums as independently certain key bytes. Expert disclosure can provide the equations and source references.

A candidate must satisfy the public validation rule on several reserved distinct-IV packets. Use their predictable prefix and genuine decryption/ICV verification; disclose the number checked. Only then may the attacker report a validated candidate. The separate experiment controller compares that candidate byte-for-byte with its hidden key and renders **WEP KEY RECOVERED** only on equality. A mismatch is an experiment failure, not a successful recovery.

Show measured capture counts, unique voting samples, validation samples, candidates tested, and elapsed compute time. Separate the paper's published result from this run's observations.

## 7. PTW scope, reliability, and resource limits

Build PTW as the sole stage-1 recovery method. Its use of more broadly usable IVs avoids restricting the experiment to the FMS weak-IV class. Suitable known plaintext is still required.

The paper reports recovery from fewer than 40,000 packets in 50% of cases under its stated conditions. This is a probabilistic result, not a success guarantee or a browser benchmark. [R3]

Follow the published voting and candidate-search method, documenting implementation choices and any departures. A winning vote alone is not a verified key. Do not advertise the paper's success rate for a simplified implementation that has not reproduced it.

Use bounded batches in a worker. Provide progress, cancellation, an explicit packet cap, a candidate-search cap, and a time/resource limit. Choose initial defaults from measured browser runs and document the browser, device class, budgets, and observed results. Do not invent performance figures in advance.

Distinguish these states:

| State | Required meaning |
| --- | --- |
| Collecting / searching | The current run is still processing its declared workload |
| No usable samples | Input lacks the required supported evidence |
| No key recovered within this budget | The bounded run completed without a validated result |
| Cancelled | Processing stopped at the learner's request |
| Recovered | The candidate passed capture-based validation and the separate ground-truth comparison |
| Experiment error | Parsing, worker, or independent truth checks exposed an implementation/problem state |

Failure to recover does not prove that the only issue is too few packets. Clear any previous verdict when inputs or sessions change; tag messages by run identifier so late worker replies cannot restore a stale result.

Measure recovery across a predetermined set of different keys and packet sequences. Publish successes and failures with their budgets. A reproducible teaching fixture may accompany fresh-key runs, but label it and execute the real attack. Never substitute a stored recovered answer.

## 8. Correctness and implementation invariants

1. **Real primitives:** implement inspectable RC4 in `src/rc4/rc4.ts` and CRC-32 in `src/wep/crc32.ts`. Use the browser cryptographic random source for fresh live keys/IVs. Preserve the master template's requirements for teaching implementations and dependencies.
2. **One verifier:** unmodified and forged packets use the same WEP receiver. No second permissive verification path, forced success, or UI-only validity flag.
3. **Attacker separation:** the worker consumes the documented capture contract only. The ground-truth controller cannot steer votes, validate guesses by secret equality, or select an answer for the attacker.
4. **Measured claims:** displayed bytes and counters derive from actual execution. Statistical rankings are evidence, not probabilities unless a probability model is explicitly justified.
5. **Session isolation:** keep generated session material in memory, with no storage, URL, analytics, or log persistence. Reset releases references and invalidates work; do not claim guaranteed memory erasure in JavaScript.
6. **Honest scope:** the page identifies WEP, its modeled boundaries, and the specific traffic assumptions. WPA2/WPA3 are outside the experiment.

If consulting another implementation, record its version and license. Validate it independently before using its outputs as a reference. Do not copy code under incompatible terms or treat the existence of a package as correctness evidence.

## 9. Tests and evidence

### Primitive and construction tests

- RC4: immutable RFC 6229 expected outputs for 40-, 64-, and 128-bit test keys, including offsets 0 and 256. These are byte offsets in a stream, not cipher block boundaries. Verify continuation of PRGA state across chunks. [R1]
- CRC: the check values above, independent reference agreement, and the affine-difference identity across multiple payload lengths and modification masks.
- WEP: both shared-key sizes, IV/Key ID handling, little-endian ICV, round trips, malformed lengths, and an independently sourced protected-body fixture.
- For that fixture, use published expected bytes or output from a named, pinned reference implementation. Record provenance and exact inputs. Do not calculate the expected ciphertext using the lab's own encryptor. Round trips alone can conceal matching encoder/decoder mistakes.
- Forgery controls: an original packet is accepted; a deterministic one-bit payload change without ICV repair is rejected; that same change with the correct repair is accepted and changes the receiver's plaintext.

### Attacker and recovery tests

- Run the worker from captured serialized inputs with generator state absent. Inspect imports and runtime messages for prohibited fields; do not present a static import scan as proof of isolation.
- Verify that duplicate IVs do not inflate independent vote counts and that reserved validation packets never enter the voting set.
- Reject a deliberately wrong candidate using public captured evidence. Ground-truth equality must occur only after the attacker returns its result.
- Use reproducible corpora and several independent keys for regression. Add a bounded fresh-key smoke run without making a probabilistic success on every random run a flaky mandatory assertion.
- Exercise low-data, no-usable-data, budget exhaustion, cancellation, and late-result cases. Use a fixed fixture known to exhaust its configured search budget when asserting that exact outcome.

### Rendered claims — `e2e/claims.spec.ts`

Drive the real interface and assert the evidence behind every rendered claim, following master-template §4.1b:

- A vector-match verdict corresponds to actual computed bytes matching the external expected vector.
- The collision pair really shares the IV under the same key, and the displayed payload XOR equals an independent XOR of the two ground-truth payloads.
- Crib-derived bytes match the disclosed assumption and ciphertext relation. Test verified recovery separately from the XOR relation; do not compare a plaintext directly to `P1 XOR P2` and call that recovery.
- The forged packet passes the genuine receiver and changes its decrypted payload.
- PTW returns the exact generator key for the deterministic success fixture, with equality computed independently of the UI string.
- Displayed generated, voting, validation, duplicate, and candidate counts match their actual events.
- Changing inputs or cancelling retires the old verdict, including when an old worker message arrives later.

### Negative claim — master-template §4.1d

The evidence fixture is the **accepted, altered packet** in panel 4. Reach it through the UI. Assert the successful genuine ICV check, the altered received message, and the visible negative-claim sentence together. Satisfy the template's rendered-check requirements; do not hide a failed construction check or manufacture a pass.

The fixture's cryptographic checks succeed while the security property fails. Its alarm styling expresses the forgery. The separate unrepaired-tamper control establishes that the verifier can reject invalid packets; that rejection is not the evidence fixture itself.

Passing RC4 vectors alongside a WEP break may illustrate correctness versus security, but must not be presented as proof that RC4 has no cryptographic weakness.

### Executable mutations — master-template §4.1c

Provide a mutation runner with concrete, uniquely anchored patches and owning tests. At minimum cover these fault effects:

| Fault introduced | Evidence the owning test must lose |
| --- | --- |
| Incorrect RC4 PRGA operation | Published vector agreement |
| WEP verifier always accepts | Rejection of the deterministic unrepaired tamper |
| CRC repair term zeroed or replaced by bare `CRC32(D)` | Successful forgery with the correct received modification |
| PTW always returns a fixed key | Exact recovery across fixtures with different keys |
| Candidate validation always accepts | Rejection of a known wrong candidate |
| Duplicate-IV exclusion removed | Accurate unique voting-sample count |
| Collision XOR display corrupted | Independent plaintext-XOR equality |
| Negative-claim text deleted | Visible limitation attached to the accepted forgery |
| Genuine ICV check broken in the forgery fixture | Successful construction check within the negative-claim fixture |

Keep the full rendered-verdict inventory aligned with the claims suite. Establish a passing baseline in the same mutation run, verify that each patch changes the source, build and serve the mutated code with evidence of the changed bundle, and require the named assertion to fail. Compilation failures and server failures are not mutation kills. Restore each patch immediately and have the runner produce the observed results.

## 10. Visual semantics and accessibility

Follow the current fleet header, hero, theme, footer, and accessibility requirements. Reuse the established design rather than introducing an unrelated shell.

| Result | Visual meaning |
| --- | --- |
| RC4 expected bytes match | Green correctness result: `TEST VECTOR MATCH` |
| Ordinary WEP ICV passes | Scoped check result, without an authenticity claim |
| Altered packet passes ICV | Alarm: `ICV VALID — AND FORGED` |
| Verified plaintext or key disclosed by an attack | Alarm: a secret has been exposed |
| Crib guess, leading vote, or candidate awaiting validation | Neutral/provisional |
| Budget exhausted or no collision observed | Neutral observation with its actual limits |

Use text and icons alongside color. Make stepping, modification controls, vote-table inspection, progress, and cancellation keyboard accessible. Respect reduced motion. Provide understandable summaries for visual state and avoid flooding assistive technology with per-packet updates. Verify grayscale and deuteranopia readability and pass the master template's accessibility gate.

## 11. Edge cases

- Invalid WEP shared-key size: reject at the WEP wrapper with a clear explanation of the supported profile.
- Empty/invalid RC4 input key: reject according to the RC4 API contract; do not apply the WEP shared-key rule there.
- Protected body too short for its clear prefix and encrypted ICV: reject before slicing or decryption.
- Unsupported Key ID/profile or insufficient known-prefix length: reject or exclude with a named reason and consistent counters.
- No collision yet: show that observation without changing the generator's policy.
- PTW failure within the budget: preserve the measured counts, show the scoped outcome, and allow a new bounded run.
- Session reset or worker failure: stop accepting results for the old run and remove its recovered-key verdict.
- Unknown plaintext beyond a crib: keep it unknown; never silently substitute generator truth.

## 12. Extension seams

Keep explicit, small extension points without implementing them in stage 1:

- `src/wep/attack/`: FMS weak-IV recovery and KoreK correlations beside PTW, using the same capture-only contract and independent checks.
- Attack profile handling: separately tested 40-bit recovery or additional plaintext models.
- Frame intake: a future parser for real captures, with explicit MAC/header parsing, packet classification, and provenance. Stage-1 protected bodies are not already a capture-file format.

Do not add placeholder attack controls that imply those methods work.

## 13. Links out

Confirm current catalog destinations before linking:

- **OTP Vault:** two-time-pad reasoning and crib assumptions.
- **ChaCha20 Stream:** reuse of a real stream cipher's keystream.
- **Nonce Guard:** GCM nonce misuse, confidentiality, and authentication failures.
- **AES Modes:** the authenticated-encryption lesson in the relevant panel; avoid implying every AES mode provides integrity.
- **Padding Oracle:** another concrete attack involving a protocol's use of cryptography.

The takeaway should name the separate design obligations: appropriate key/nonce handling, cryptographic authentication, and a sound primitive/construction. Do not offer “secure WEP” or a single patched setting as a modern solution.

## 14. Completion criteria

Finish the master template's build, teaching, visual, accessibility, README, dependency-automation, and deployment requirements within the authorization given to the builder. This brief itself does not authorize additional external actions beyond that task.

The implementation is complete when all five panels execute their actual mechanisms; the 104-bit PTW fixture recovers through the capture-only path; the negative-claim fixture is reachable; independent vectors and a WEP fixture pass; and the rendered-claim, mutation, build, and accessibility gates pass.

Report what was built, source and reference versions, actual test counts, measured PTW results and budgets, any departures from the paper, and remaining model limitations. Distinguish implemented, tested, and deployed status. Do not mark a requirement satisfied merely because its intended test was written.

## 15. Primary sources and provenance

Use these as implementation references. Record specific sections, versions, and fixture provenance when building. The source-derived facts above do not replace reading the relevant algorithms.

- **[R1]** J. Strombergson and S. Josefsson, [RFC 6229: Test Vectors for the Stream Cipher RC4](https://www.rfc-editor.org/rfc/rfc6229.html), May 2011. Source for fixed expected RC4 outputs and stream offsets.
- **[R2]** A. Popov, [RFC 7465: Prohibiting RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465.html), February 2015, §§1–2. Security context; it is not a WEP specification.
- **[R3]** Erik Tews, Ralf-Philipp Weinmann, and Andrei Pyshkin, [Breaking 104 bit WEP in less than 60 seconds](https://eprint.iacr.org/2007/120), 2007; [full paper mirror](https://wiki-files.aircrack-ng.org/doc/others/120.pdf). Read the algorithm and vote derivation, §5 for ARP assumptions, §6 for ranking and validation, and §7 for measured results.
- **[R4]** Linux, [`net/mac80211/wep.c`](https://github.com/torvalds/linux/blob/master/net/mac80211/wep.c). Primary implementation reference for IV/Key ID serialization, IV-prepended RC4 keying, and encrypted little-endian CRC ICV. Pin a commit if deriving a fixture; this reference does not substitute for reading the standard or permit copying code without license review.
- **[R5]** P. Deutsch, [RFC 1952: GZIP file format specification version 4.3](https://www.rfc-editor.org/rfc/rfc1952.html), May 1996, §8. Independent reference for the reflected CRC-32 routine and initialization/finalization convention; not a WEP framing source.
- **[R6]** Scott Fluhrer, Itsik Mantin, and Adi Shamir, [Weaknesses in the Key Scheduling Algorithm of RC4](https://doi.org/10.1007/3-540-45537-X_1), SAC 2001, LNCS 2259. Historical and technical background for the future FMS extension.
- **[R7]** Nikita Borisov, Ian Goldberg, and David Wagner, *Intercepting Mobile Communications: The Insecurity of 802.11*, MobiCom 2001; [author's project page](https://people.eecs.berkeley.edu/~daw/research/wireless.html). Original WEP security analysis and background for message modification.
- **[R8]** IEEE 802.11-1997, WEP construction. Cite the applicable clause if the standard text is obtained during implementation; do not invent a clause or claim direct verification of inaccessible text.
- **[R9]** CrypTool 2, [WEPAttacks implementation](https://github.com/CrypToolProject/CrypTool-2/blob/main/CrypPlugins/WEPAttacks/WEPAttacks/WEPAttacks.cs). Initial comparison lead and possible implementation cross-check. Confirm its current path and license before use; the original papers remain the attack references.

The CRC-difference equation in this brief is an algebraic derivation from the stated CRC convention. Worker separation, held-out validation, UI behavior, resource limits, and testing requirements are requirements for this exhibit rather than claims that the cited papers prescribe this application design.
