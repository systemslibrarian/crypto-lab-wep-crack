#!/usr/bin/env node
/**
 * The mutation runner — master template 4.1c.
 *
 * A green suite is not evidence until you have watched it fail. A SENTENCE
 * describing a mutation cannot be replayed and a paragraph describing a run is
 * the author's side of the claim rather than the run's, so every mutation here
 * is a CONCRETE PATCH — a file, an anchor that must occur exactly once, and its
 * replacement — and every `observed` record below is written by the thing that
 * ran it rather than typed.
 *
 * A KILL REQUIRES ALL FIVE, in this order, and the script enforces each:
 *   1. BASELINE — the owning test PASSES unmutated, in this same run. A test
 *      that was already failing proves nothing when it fails again.
 *   2. PATCHED — the source diff is NON-EMPTY. A patch that silently did not
 *      apply looks exactly like a mutation nothing caught.
 *   3. BUILT AND MOVED — the build SUCCEEDS and the built bundle's hash
 *      CHANGES. A mutation that breaks tsc is DOES NOT BUILD and is never a
 *      kill: `vite preview` serves whatever is already in dist/, so a failed
 *      build leaves the previous good bundle in place and the whole suite
 *      passes green against source that no longer compiles.
 *   4. KILLED — the NAMED owning test fails. A red run whose output matches a
 *      build error, a server that never started, or a refused connection is
 *      classified INCONCLUSIVE rather than counted.
 *   5. RESTORED — the file is put back, the diff is empty again, and the owning
 *      test passes again.
 *
 * Playwright runs with --retries=0 and CI=1. Both matter: a retry that dies of
 * ERR_CONNECTION_REFUSED produces mixed output that proves nothing, and
 * `reuseExistingServer: !process.env.CI` means a run that finds something
 * listening USES it — so without CI=1 a mutation check can be answered by an
 * UNMUTATED preview still running from an earlier run, which reads as "the
 * mutation was not caught" and sends someone to fix a check that works.
 *
 * Usage:  node scripts/mutations.mjs [id ...]
 */

import { execFileSync, execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const DIST_ASSETS = join(ROOT, 'dist', 'assets');

/**
 * The brief's mutation set (its section 9 table), one entry per fault.
 *
 * `owner` names the single test that must lose its evidence. Naming it is the
 * point: "some test went red" is not a kill, because the test that went red may
 * have nothing to do with what changed.
 */
const MUTATIONS = [
  {
    id: 'rc4-prga',
    fault: 'Incorrect RC4 PRGA operation',
    evidence: 'Published vector agreement',
    file: 'src/rc4/rc4.ts',
    anchor: '      const outIndex = (this.s[this.i] + this.s[this.j]) & 0xff;',
    replacement: '      const outIndex = (this.s[this.i] ^ this.s[this.j]) & 0xff;',
    owner: { runner: 'vitest', name: 'reproduces all 4 expected offsets from one continuous keystream' },
  },
  {
    id: 'verifier-always-accepts',
    fault: 'WEP verifier always accepts',
    evidence: 'Rejection of the deterministic unrepaired tamper',
    file: 'src/wep/wep.ts',
    anchor: '    icvValid: icvReceived === icvComputed,',
    replacement: '    icvValid: true,',
    owner: {
      runner: 'vitest',
      name: 'a deterministic one-bit payload change WITHOUT ICV repair is rejected',
    },
  },
  {
    id: 'crc-repair-bare',
    fault: 'CRC repair term replaced by a bare CRC32(D)',
    evidence: 'Successful forgery with the correct received modification',
    file: 'src/wep/crc32.ts',
    anchor: '  return (crc32(mask) ^ crc32(new Uint8Array(mask.length))) >>> 0;',
    replacement: '  return crc32(mask) >>> 0;',
    owner: {
      runner: 'vitest',
      name: 'that same change WITH the correct repair is accepted AND changes the plaintext',
    },
  },
  {
    id: 'crc-repair-zeroed',
    fault: 'CRC repair term zeroed',
    evidence: 'Successful forgery with the correct received modification',
    file: 'src/wep/crc32.ts',
    anchor: '  return (crc32(mask) ^ crc32(new Uint8Array(mask.length))) >>> 0;',
    replacement: '  return 0;',
    owner: {
      runner: 'vitest',
      name: 'that same change WITH the correct repair is accepted AND changes the plaintext',
    },
  },
  {
    id: 'ptw-fixed-key',
    fault: 'PTW always returns a fixed key',
    evidence: 'Exact recovery across fixtures with different keys',
    file: 'src/wep/attack/ptw.ts',
    anchor: '        candidate: search.candidate,',
    replacement: '        candidate: new Uint8Array(13).fill(7),',
    owner: {
      runner: 'vitest',
      name: 'success A: recovers b1d44702cc988d22f85e172374 from 35000 packets',
    },
  },
  {
    id: 'validation-always-accepts',
    fault: 'Candidate validation always accepts',
    evidence: 'Rejection of a known wrong candidate',
    file: 'src/wep/attack/ptw.ts',
    anchor: `    const ks = keystreamUnder(parsed.iv, candidate, Math.min(need, knownPrefix.length));
    const derived = keystreamPrefixFrom(parsed.encryptedPayload, knownPrefix.subarray(0, ks.length));
    if (!equalBytes(ks, derived)) return { ok: false, checked };
    if (!wepReceive(packet.body, candidate).icvValid) return { ok: false, checked };`,
    replacement:
      '    void keystreamUnder; void keystreamPrefixFrom; void equalBytes; void wepReceive; void parsed; void need; void knownPrefix; void candidate;',
    owner: { runner: 'vitest', name: 'rejects a deliberately wrong candidate' },
  },
  {
    id: 'duplicate-iv-exclusion-removed',
    fault: 'Duplicate-IV exclusion removed',
    evidence: 'Accurate unique voting-sample count',
    file: 'src/wep/attack/ptw.ts',
    anchor: '    seenIv.add(ivHex);',
    replacement: '    void ivHex;',
    owner: { runner: 'vitest', name: 'duplicate IVs do not inflate vote counts' },
  },
  {
    id: 'collision-xor-corrupted',
    fault: 'Collision XOR display corrupted',
    evidence: 'Independent plaintext-XOR equality',
    file: 'src/ui/panel3Collision.ts',
    anchor: '    const cipherXor = xor(ca, cb);',
    // Corrupt one byte of the DISPLAY rather than dropping an operand: dropping
    // `cb` leaves it unused, `tsc --noEmit` fails on noUnusedLocals, and a
    // mutation that does not compile is never a kill.
    replacement: '    const cipherXor = xor(ca, cb);\n    cipherXor[0] ^= 0xff;',
    owner: {
      runner: 'playwright',
      project: 'claims',
      name: 'the displayed XOR equals an independent XOR of the two true payloads',
    },
  },
  {
    id: 'negative-claim-deleted',
    fault: 'Negative-claim text deleted',
    evidence: 'Visible limitation attached to the accepted forgery',
    file: 'src/ui/panel4Forge.ts',
    anchor:
      "  'A valid WEP integrity check does not establish that a message is authentic or unmodified.';",
    replacement: "  '';",
    owner: {
      runner: 'playwright',
      project: 'claims',
      name: 'the negative-claim fixture: every check passes and the property is violated anyway',
    },
  },
  {
    id: 'fixture-icv-check-broken',
    fault: 'Genuine ICV check broken in the forgery fixture',
    evidence: 'Successful construction check within the negative-claim fixture',
    file: 'src/ui/panel4Forge.ts',
    anchor: "text: `0x${forged.icvComputed.toString(16).padStart(8, '0')}` }),",
    replacement: "text: `0x${(forged.icvComputed ^ 1).toString(16).padStart(8, '0')}` }),",
    owner: {
      runner: 'playwright',
      project: 'claims',
      name: 'the negative-claim fixture: every check passes and the property is violated anyway',
    },
  },
];

/** Output that means the run never really executed the code under test. */
const INCONCLUSIVE = [
  /ERR_CONNECTION_REFUSED/,
  /was not able to start/i,
  /Process from config\.webServer/,
  /error TS\d+/,
  /Build failed/i,
  /EADDRINUSE/,
  /No tests found/i,
  /Cannot find module/,
];

function sh(cmd, opts = {}) {
  try {
    const stdout = execSync(cmd, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...opts.env },
      timeout: opts.timeout ?? 900_000,
    });
    return { ok: true, out: stdout };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

/** Hashes of every built asset, so "the mutation reached the bundle" is measured. */
function bundleHashes() {
  const out = {};
  for (const f of readdirSync(DIST_ASSETS).sort()) {
    out[f] = createHash('md5').update(readFileSync(join(DIST_ASSETS, f))).digest('hex').slice(0, 12);
  }
  return out;
}

function hashSummary(h) {
  return Object.entries(h)
    .map(([f, v]) => `${f}=${v}`)
    .join(' ');
}

/**
 * Build exactly the way CI and Playwright's `webServer` do: `npm run build` is
 * `tsc --noEmit && vite build`.
 *
 * Calling `vite build` alone here was a real defect in this runner. Vite strips
 * types without checking them, so a mutation that breaks the TYPECHECK built
 * "successfully", the hash moved, and then the Playwright webServer — which
 * does run `npm run build` — failed to start. The runner reported
 * "build SUCCEEDED" followed by an INCONCLUSIVE red run, which is a confusing
 * way to say DOES NOT BUILD. Same command here, same verdict there.
 */
function build() {
  return sh('npm run build');
}

function runOwner(owner) {
  if (owner.runner === 'vitest') {
    // -t matches the test name; the exit code is the signal.
    return sh(`npx vitest run -t ${JSON.stringify(owner.name)}`);
  }
  // Kill any stray preview, then WAIT FOR THE PORT TO ACTUALLY FREE before
  // handing it to Playwright. With CI=1 the config does not reuse an existing
  // server and --strictPort refuses to move, so a socket still in TIME_WAIT
  // from the previous mutation makes the webServer fail to start — which this
  // runner classifies INCONCLUSIVE rather than counting as a kill. Waiting is
  // the fix; counting it would have been the bug.
  sh('pkill -f "vite preview" || true');
  waitForPortFree(PORT);
  return sh(
    `npx playwright test --project=${owner.project} --retries=0 -g ${JSON.stringify(owner.name)}`,
    { env: { CI: '1' } }
  );
}

/** This lab's pinned Playwright port. */
const PORT = 4732;

/**
 * Block until nothing holds `port`, or give up loudly.
 *
 * A brief wait here is not cosmetic: it is the difference between a mutation
 * check that measured something and one whose server never came up.
 */
function waitForPortFree(port, timeoutMs = 60_000) {
  const started = Date.now();
  for (;;) {
    const held = sh(`lsof -nP -iTCP:${port} -sTCP:LISTEN -t || true`).out.trim();
    if (!held) return true;
    if (Date.now() - started > timeoutMs) {
      console.log(`     (warning: port ${port} still held by pid ${held} after ${timeoutMs}ms)`);
      return false;
    }
    sh(`kill ${held.split('\n').join(' ')} || true`);
    execFileSync('sleep', ['2'], { cwd: ROOT });
  }
}

function diffOf(file) {
  return sh(`git diff --unified=0 -- ${file}`).out.trim();
}

function patch(file, anchor, replacement) {
  const path = join(ROOT, file);
  const src = readFileSync(path, 'utf8');
  const count = src.split(anchor).length - 1;
  if (count !== 1) {
    return { ok: false, reason: `anchor occurs ${count} times in ${file}; it must occur exactly once` };
  }
  writeFileSync(path, src.replace(anchor, replacement));
  return { ok: true };
}

function restore(file) {
  return sh(`git checkout -- ${file}`);
}

const wanted = process.argv.slice(2);
const selected = wanted.length ? MUTATIONS.filter((m) => wanted.includes(m.id)) : MUTATIONS;
if (!selected.length) {
  console.error(`no such mutation. ids: ${MUTATIONS.map((m) => m.id).join(', ')}`);
  process.exit(2);
}

// A dirty tree makes "the source diff is non-empty" meaningless, and a session
// that dies mid-check would strand an inverted condition in it.
const dirty = sh('git status --porcelain -- src/').out.trim();
if (dirty) {
  console.error('src/ has uncommitted changes. Commit the real work BEFORE mutating.\n' + dirty);
  process.exit(2);
}

console.log('Establishing the pre-mutation bundle…');
const buildBefore = build();
if (!buildBefore.ok) {
  console.error('the baseline build failed; nothing below would mean anything\n' + buildBefore.out);
  process.exit(2);
}
const baseHashes = bundleHashes();
console.log(`baseline bundle: ${hashSummary(baseHashes)}\n`);

const results = [];

for (const m of selected) {
  console.log('='.repeat(78));
  console.log(`${m.id} — ${m.fault}`);
  console.log(`  owning test (${m.owner.runner}): ${m.owner.name}`);
  const observed = { id: m.id, fault: m.fault, evidence: m.evidence, owner: m.owner.name };

  // 1. BASELINE — the owning test must pass unmutated, in this same run.
  const baseline = runOwner(m.owner);
  observed.baseline = baseline.ok ? 'PASS' : 'FAIL';
  console.log(`  1. baseline unmutated: ${observed.baseline}`);
  if (!baseline.ok) {
    observed.verdict = 'NO BASELINE';
    observed.detail = baseline.out.slice(-1200);
    results.push(observed);
    continue;
  }

  // 2. PATCHED — and the source diff must be non-empty.
  const applied = patch(m.file, m.anchor, m.replacement);
  if (!applied.ok) {
    observed.verdict = 'PATCH DID NOT APPLY';
    observed.detail = applied.reason;
    console.log(`  2. patch: ${applied.reason}`);
    results.push(observed);
    continue;
  }
  const diff = diffOf(m.file);
  observed.diffLines = diff ? diff.split('\n').length : 0;
  console.log(`  2. source diff: ${observed.diffLines} lines (non-empty: ${diff.length > 0})`);
  if (!diff) {
    restore(m.file);
    observed.verdict = 'PATCH DID NOT APPLY';
    results.push(observed);
    continue;
  }

  // 3. BUILT AND MOVED.
  const built = build();
  observed.build = built.ok ? 'SUCCEEDED' : 'FAILED';
  if (!built.ok) {
    restore(m.file);
    build();
    observed.verdict = 'DOES NOT BUILD';
    observed.detail = built.out.slice(-1200);
    console.log('  3. build: FAILED — DOES NOT BUILD, never a kill');
    results.push(observed);
    continue;
  }
  const mutatedHashes = bundleHashes();
  const moved = Object.keys(mutatedHashes).filter((f) => mutatedHashes[f] !== baseHashes[f]);
  observed.hashesMoved = moved;
  observed.mutatedBundle = hashSummary(mutatedHashes);
  console.log(`  3. build SUCCEEDED; bundle hashes moved: ${moved.length ? moved.join(', ') : 'NONE'}`);
  if (!moved.length) {
    restore(m.file);
    build();
    observed.verdict = 'NO HASH MOVE';
    results.push(observed);
    continue;
  }

  // 4. KILLED — the named owning test must fail, for the right reason.
  const mutated = runOwner(m.owner);
  const inconclusive = INCONCLUSIVE.find((re) => re.test(mutated.out));
  if (mutated.ok) {
    observed.verdict = 'NOT KILLED';
    console.log('  4. owning test: STILL PASSED — not killed');
  } else if (inconclusive) {
    observed.verdict = 'INCONCLUSIVE';
    observed.detail = `red run matched ${inconclusive}`;
    console.log(`  4. owning test: red, but INCONCLUSIVE (${inconclusive})`);
  } else {
    observed.verdict = 'KILLED';
    const line = mutated.out
      .split('\n')
      .find((l) => /AssertionError|expect\(|Error:|✘|×|FAIL/.test(l));
    observed.failedWith = (line ?? '').trim().slice(0, 180);
    console.log(`  4. owning test: FAILED — killed`);
    if (observed.failedWith) console.log(`     ${observed.failedWith}`);
  }

  // 5. RESTORED — put it back immediately, and prove it is green again.
  restore(m.file);
  const afterDiff = diffOf(m.file);
  build();
  const restoredHashes = bundleHashes();
  const same = Object.keys(restoredHashes).every((f) => restoredHashes[f] === baseHashes[f]);
  const green = runOwner(m.owner);
  observed.restored = afterDiff === '' && same;
  observed.greenAgain = green.ok;
  console.log(
    `  5. restored: diff empty=${afterDiff === ''} hash returned=${same} green again=${green.ok}`
  );
  if (!observed.restored || !green.ok) observed.verdict = `${observed.verdict} (RESTORE PROBLEM)`;
  results.push(observed);
}

console.log('\n' + '='.repeat(78));
console.log('OBSERVED RECORDS — written by this run, not typed');
console.log('='.repeat(78));
for (const r of results) {
  console.log(
    [
      r.verdict.padEnd(14),
      r.id.padEnd(32),
      `baseline=${r.baseline ?? '-'}`,
      `diff=${r.diffLines ?? '-'}L`,
      `build=${r.build ?? '-'}`,
      `moved=${(r.hashesMoved ?? []).length}`,
      `restored=${r.restored ?? '-'}`,
      `green=${r.greenAgain ?? '-'}`,
    ].join('  ')
  );
  if (r.failedWith) console.log(`${' '.repeat(16)}killed by: ${r.failedWith}`);
  if (r.detail) console.log(`${' '.repeat(16)}detail: ${String(r.detail).split('\n')[0]}`);
}

const killed = results.filter((r) => r.verdict === 'KILLED').length;
console.log(`\n${killed} of ${results.length} killed.`);
writeFileSync(
  join(ROOT, 'mutation-report.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), baseHashes, results }, null, 2) + '\n'
);
console.log('records written to mutation-report.json');
process.exit(killed === results.length ? 0 : 1);
