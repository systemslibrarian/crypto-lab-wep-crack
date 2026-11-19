/*
 * Offline generator for the single-byte-bias table used by the broadcast
 * attack panel (panel 6). Measures p_{r,k} = Pr(Z_r = k) over many random
 * 16-byte RC4 keys, for output positions r = 1..POSITIONS, and writes the raw
 * counts plus the sample size to src/rc4/bias-table.json.
 *
 * This is the paper's measurement step (AlFardan et al., USENIX 2013, §4.1),
 * at a teaching sample size (2^20, the brief's ceiling) rather than their 2^44.
 * The RC4 here is a standalone copy; src/rc4/bias-table.test.ts re-checks the
 * shipped table against the lab's own RC4 at the strongest-bias positions.
 *
 * Run: node scripts/gen-bias-table.mjs [log2keys] [positions]
 */
import { writeFileSync } from 'node:fs';

const N = 256;
function ksaPrga(key, outLen) {
  const s = new Uint8Array(N);
  for (let i = 0; i < N; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < N; i++) {
    j = (j + s[i] + key[i % key.length]) & 255;
    const t = s[i]; s[i] = s[j]; s[j] = t;
  }
  const out = new Uint8Array(outLen);
  let i = 0; j = 0;
  for (let n = 0; n < outLen; n++) {
    i = (i + 1) & 255;
    j = (j + s[i]) & 255;
    const t = s[i]; s[i] = s[j]; s[j] = t;
    out[n] = s[(s[i] + s[j]) & 255];
  }
  return out;
}

const log2keys = Number(process.argv[2] ?? 20);
const POSITIONS = Number(process.argv[3] ?? 256);
const SAMPLES = 2 ** log2keys;
// counts[r-1][k] over positions r = 1..POSITIONS
const counts = Array.from({ length: POSITIONS }, () => new Uint32Array(N));
const key = new Uint8Array(16);
const crypto = (await import('node:crypto')).webcrypto;
const batch = new Uint8Array(16 * 4096);
let done = 0;
const t0 = Date.now();
while (done < SAMPLES) {
  crypto.getRandomValues(batch);
  const n = Math.min(4096, SAMPLES - done);
  for (let b = 0; b < n; b++) {
    key.set(batch.subarray(b * 16, b * 16 + 16));
    const ks = ksaPrga(key, POSITIONS);
    for (let r = 0; r < POSITIONS; r++) counts[r][ks[r]]++;
  }
  done += n;
  if (done % (1 << 18) === 0) process.stderr.write(`  ${done}/${SAMPLES} (${((Date.now()-t0)/1000).toFixed(0)}s)\n`);
}
const out = {
  note: 'Empirical RC4 single-byte keystream bias counts, Pr(Z_r = k). Measured offline over 2^' +
    log2keys + ' random 16-byte keys. Positions r are 1-indexed (row 0 is Z_1). AlFardan, Bernstein, ' +
    'Paterson, Poettering and Schuldt, "On the Security of RC4 in TLS and WPA" (USENIX Security 2013), ' +
    '§4.1, measured there over 2^44 keys; this is a teaching-scale table.',
  log2keys,
  samples: SAMPLES,
  positions: POSITIONS,
  counts: counts.map((row) => Array.from(row)),
};
writeFileSync(new URL('../src/rc4/bias-table.json', import.meta.url), JSON.stringify(out));
process.stderr.write(`done in ${((Date.now()-t0)/1000).toFixed(0)}s\n`);
