import { describe, expect, it } from 'vitest';
import { toHex } from '../bytes';
import { seededRand } from '../traffic';
import { P_EQUAL, pCorrect, pWrong, qi, rankStrongCandidates, strongByteValues, strongIndicator } from './strong';

/** Equation 9, computed directly, as the ground-truth oracle for these tests. */
function strongBytesOf(key: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 1; i < key.length; i++) {
    for (let l = 1; l <= i; l++) {
      let sum = 0;
      for (let k = l; k <= i; k++) sum = (sum + key[k] + 3 + k) & 0xff;
      if (sum === 0) {
        out.push(i);
        break;
      }
    }
  }
  return out;
}

describe('the paper probabilities (equations 7 and 8)', () => {
  it('q_0 is 1 — nothing has been substituted yet', () => {
    expect(qi(0)).toBeCloseTo(1, 10);
  });

  it('q_i decreases with i, because more permutations are being substituted', () => {
    for (let i = 1; i <= 12; i++) expect(qi(i)).toBeLessThan(qi(i - 1));
    // Roughly two thirds survive by the last sum of a 104-bit key.
    expect(qi(12)).toBeGreaterThan(0.6);
    expect(qi(12)).toBeLessThan(0.75);
  });

  it('p_correct exceeds 1/n at every index — this bias IS the attack', () => {
    for (let i = 0; i < 13; i++) {
      expect(pCorrect(i), `index ${i}`).toBeGreaterThan(P_EQUAL);
    }
  });

  it("p_correct at index 0 is near the paper's 1.36/n", () => {
    expect(pCorrect(0) * 256).toBeGreaterThan(1.3);
    expect(pCorrect(0) * 256).toBeLessThan(1.4);
  });

  it('p_correct decays toward 1/n as i grows, so later sums are the hard ones', () => {
    expect(pCorrect(12)).toBeLessThan(pCorrect(0));
    expect(pCorrect(12)).toBeGreaterThan(P_EQUAL);
  });

  it('the 256 probabilities of the normal hypothesis sum to 1', () => {
    for (let i = 0; i < 13; i++) {
      expect(pCorrect(i) + 255 * pWrong(i), `index ${i}`).toBeCloseTo(1, 10);
    }
  });
});

describe('equation 12 recovers a strong key byte', () => {
  it('produces the true value for every strong byte, over many keys', () => {
    const rand = seededRand(0x5eed);
    let keysWithStrongBytes = 0;
    let bytesChecked = 0;
    for (let trial = 0; trial < 2000; trial++) {
      const key = rand(13);
      const strong = strongBytesOf(key);
      if (!strong.length) continue;
      keysWithStrongBytes++;
      for (const i of strong) {
        const values = strongByteValues([...key.subarray(0, i)], i);
        expect(values, `key ${toHex(key)} index ${i}`).toContain(key[i]);
        // At most i values, which is what makes this cheap enough to try.
        expect(values.length).toBeLessThanOrEqual(i);
        bytesChecked++;
      }
    }
    // The sample really contained strong keys rather than passing vacuously.
    expect(keysWithStrongBytes).toBeGreaterThan(100);
    expect(bytesChecked).toBeGreaterThan(100);
  });

  it('index 0 is rejected — Rk[0] can never be a strong key byte', () => {
    expect(() => strongByteValues([], 0)).toThrow();
    // Equation 9's range of l is {1..i}, empty at i = 0.
    const rand = seededRand(11);
    for (let t = 0; t < 200; t++) expect(strongBytesOf(rand(13))).not.toContain(0);
  });

  it('needs exactly the preceding key bytes', () => {
    expect(() => strongByteValues([1, 2], 5)).toThrow(/needs the first 5/);
  });

  it('the l = i case gives Rk[i] = -3 - i', () => {
    expect(strongByteValues([7], 1)).toContain((-3 - 1) & 0xff);
  });
});

describe('the strong-byte detector reads vote counts only', () => {
  it('prefers the equidistributed hypothesis for a flat table', () => {
    // A flat table is the strong-byte signature: errStrong should win, so the
    // difference is negative.
    const counts = new Uint32Array(256).fill(100);
    const ind = strongIndicator(counts, 25600, 6);
    expect(ind.errStrong).toBeLessThan(ind.errNormal);
    expect(ind.difference).toBeLessThan(0);
  });

  it('prefers the normal hypothesis for a table with a clear leader', () => {
    const counts = new Uint32Array(256).fill(100);
    counts[42] = 136; // ~1.36x, the paper's bias
    const ind = strongIndicator(counts, 25600 + 36, 6);
    expect(ind.errNormal).toBeLessThan(ind.errStrong);
    expect(ind.difference).toBeGreaterThan(0);
  });

  it('never nominates index 0', () => {
    const tables = Array.from({ length: 13 }, () => ({
      counts: new Uint32Array(256).fill(10),
      total: 2560,
    }));
    expect(rankStrongCandidates(tables).map((x) => x.sigmaIndex)).not.toContain(0);
    expect(rankStrongCandidates(tables)).toHaveLength(12);
  });

  it('handles an empty table without dividing by zero', () => {
    const ind = strongIndicator(new Uint32Array(256), 0, 3);
    expect(Number.isFinite(ind.difference)).toBe(true);
    expect(ind.difference).toBe(0);
  });

  it('takes no argument through which the key could arrive', () => {
    expect(strongIndicator.length).toBe(3);
    expect(strongByteValues.length).toBe(2);
  });
});
