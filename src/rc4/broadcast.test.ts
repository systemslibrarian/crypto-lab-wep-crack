/**
 * The broadcast single-byte-bias attack (AlFardan et al., USENIX 2013, §4.1),
 * as executable claims. A fixed seed makes every run reproducible.
 */
import { describe, expect, it } from 'vitest';
import {
  BIAS_TABLE,
  TLS_FIRST_USABLE_POSITION,
  generateTallies,
  logProbRow,
  positionRange,
  recoverByte,
  recoverPlaintext,
  runBroadcast,
  seededKeySource,
} from './broadcast';
import { Rc4Keystream } from './rc4';

describe('the measured bias table', () => {
  it('is the offline-measured table, 256 positions, with the Z₂→0 bias intact', () => {
    expect(BIAS_TABLE.positions).toBe(256);
    expect(BIAS_TABLE.counts).toHaveLength(256);
    expect(BIAS_TABLE.log2keys).toBeGreaterThanOrEqual(20);
    // Z₂ (row 1) is biased toward 0 at ≈ 2× uniform (Mantin–Shamir, 1/128).
    const z2 = BIAS_TABLE.counts[1][0] / BIAS_TABLE.samples;
    expect(z2 / (1 / 256)).toBeGreaterThan(1.7);
    // Its peak really is at value 0.
    const row = BIAS_TABLE.counts[1];
    expect(row.indexOf(Math.max(...row))).toBe(0);
  });

  it('matches the lab’s own RC4 on a fresh small sample at position 2', () => {
    // Re-measure Z₂=0 with the lab's RC4 over a few thousand keys; the shipped
    // table must agree on the direction and rough strength of the bias.
    const seed = seededKeySource(1);
    let zero = 0;
    const n = 20000;
    for (let i = 0; i < n; i++) if (new Rc4Keystream(seed()).next(2)[1] === 0) zero++;
    const live = zero / n;
    const shipped = BIAS_TABLE.counts[1][0] / BIAS_TABLE.samples;
    expect(live).toBeGreaterThan(1.6 / 256);
    expect(Math.abs(live - shipped)).toBeLessThan(0.002);
  });
});

describe('Algorithm 4, one position', () => {
  it('recovers the plaintext byte at a strongly biased position from tallies alone', () => {
    const secret = new Uint8Array([0x42]);
    const tallies = generateTallies(secret, [2], 50000, seededKeySource(7));
    const row = logProbRow(BIAS_TABLE.counts[1], BIAS_TABLE.samples);
    expect(recoverByte(tallies[0], row)).toBe(0x42);
  });

  it('is secret-free: recoverByte sees only the tally and the distribution', () => {
    // A tally spiked at value v, with Z biased to 0, implies plaintext v.
    const tally = new Int32Array(256);
    tally[0x99] = 1000;
    const row = logProbRow(BIAS_TABLE.counts[1], BIAS_TABLE.samples);
    expect(recoverByte(tally, row)).toBe(0x99);
  });
});

describe('a broadcast run', () => {
  it('recovers the strongly-biased byte with enough sessions, and fails with few', () => {
    const secret = new Uint8Array([0x6d]); // position 2 only
    const strong = runBroadcast(secret, [2], 60000, seededKeySource(3));
    expect(strong.successCount).toBe(1);
    expect(strong.recovered[0]).toBe(0x6d);

    // With only a handful of sessions the bias cannot be seen.
    const weak = runBroadcast(secret, [2], 16, seededKeySource(3));
    expect(weak.successCount).toBe(0);
  });

  it('TLS positions start at 37, skipping the Finished message', () => {
    expect(TLS_FIRST_USABLE_POSITION).toBe(37);
    const tls = positionRange(TLS_FIRST_USABLE_POSITION, 8);
    expect(tls[0]).toBe(37);
    expect(tls).not.toContain(2); // the strong Z₂ bias is unreachable in TLS
    // A short TLS-position run does not recover the strong-bias byte, because
    // position 2 is not in scope — the point of the caveat.
    const secret = new Uint8Array(8).fill(0x41);
    const run = runBroadcast(secret, tls, 20000, seededKeySource(5));
    expect(run.successCount).toBeLessThan(tls.length); // not a clean sweep
  });

  it('recovery uses only the tallies: the same tallies recover the same bytes', () => {
    const secret = new Uint8Array([0x6d]);
    const tallies = generateTallies(secret, [2], 40000, seededKeySource(9));
    const a = recoverPlaintext(tallies, [2]);
    const b = recoverPlaintext(tallies, [2]);
    expect(a[0]).toBe(b[0]);
    expect(a[0]).toBe(0x6d);
  });
});
