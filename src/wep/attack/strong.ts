/**
 * Strong key bytes — the PTW paper's section 6.2, equations 7-12.
 *
 * Equation 5's estimator substitutes S_3 for every later intermediate
 * permutation. For part of the key space that substitution is wrong in a
 * specific way: the paper calls those STRONG key bytes, and for one of them the
 * correct value stops leading its vote table at all. Its votes become
 * equidistributed, so collecting more packets does not help — which is why a
 * recovery failure is NOT evidence that the only problem was too few packets.
 *
 * Equation 9. Rk[i] is a strong key byte if there is an l in {1..i} with
 *
 *     sum_{k=l}^{i} ( Rk[k] + 3 + k )  ==  0   (mod 256)
 *
 * Note i >= 1: Rk[0] can never be a strong key byte, because the range of l is
 * empty for i = 0.
 *
 * Equation 12 solves that congruence for Rk[i] given Rk[0..i-1]:
 *
 *     Rk[i]  ==  -3 - i - sum_{j=l}^{i-1} ( Rk[j] + 3 + j )   (mod 256)
 *
 * which leaves at most i possible values — one per l. So an index assumed
 * strong is read off this equation instead of off its (now useless) table.
 *
 * Equations 10 and 11 are how the attacker GUESSES which index is strong,
 * without the key: compare how well each table's vote distribution fits "all
 * values equidistributed" (strong) against "one correct value at p_correct, the
 * rest equidistributed" (normal). Both are computed from the vote counts alone.
 */

/** RC4's modulus, and the paper's n. */
const N = 256;

/**
 * q_i, equation 7 — the probability that replacing every intermediate
 * permutation with S_3 changed nothing.
 *
 *   q_i = (1 - 1/n)^i  *  (1 - i/n)  *  prod_{k=1}^{i} (1 - k/n)
 *
 * The three factors are, in the paper's own order: j never took the value
 * j_{i+3} in an earlier round; i did not take it either; and every S_l[l] along
 * the way is still its original value.
 */
export function qi(i: number): number {
  let product = 1;
  for (let k = 1; k <= i; k++) product *= 1 - k / N;
  return Math.pow(1 - 1 / N, i) * (1 - i / N) * product;
}

/**
 * p_correct_i, equation 8 — the probability that A_i takes the correct value
 * for sigma_i, given q_i. Equation 6 is this with q_i = 1.
 */
export function pCorrect(i: number): number {
  const base = Math.pow(1 - 1 / N, N - 2);
  const q = qi(i);
  return q * base * (2 / N) + (1 - q * base) * ((N - 2) / (N * (N - 1)));
}

/** p_wrong_i: the paper's (1 - p_correct_i) / (n - 1). */
export function pWrong(i: number): number {
  return (1 - pCorrect(i)) / (N - 1);
}

/** p_equal: 1/n, the strong-byte hypothesis. */
export const P_EQUAL = 1 / N;

export interface StrongIndicator {
  readonly sigmaIndex: number;
  readonly errStrong: number;
  readonly errNormal: number;
  /**
   * errStrong - errNormal. NEGATIVE means the equidistributed (strong)
   * hypothesis fits better, so the most-likely-strong index is the SMALLEST.
   */
  readonly difference: number;
}

/**
 * Equations 10 and 11, over one table's vote counts.
 *
 * N_ib is the FRACTION of that table's votes falling on value b, so both sums
 * run over all 256 values and neither needs the key.
 */
export function strongIndicator(counts: Uint32Array, total: number, sigmaIndex: number): StrongIndicator {
  if (total === 0) {
    return { sigmaIndex, errStrong: 0, errNormal: 0, difference: 0 };
  }
  let argmax = 0;
  for (let b = 1; b < N; b++) if (counts[b] > counts[argmax]) argmax = b;

  // Equation 10: sum over all values of (N_ij - p_equal)^2.
  let errStrong = 0;
  for (let b = 0; b < N; b++) {
    const d = counts[b] / total - P_EQUAL;
    errStrong += d * d;
  }

  // Equation 11: (max N_ib - p_correct_i)^2 + sum over the rest of
  // (N_ij - p_wrong_i)^2.
  const pc = pCorrect(sigmaIndex);
  const pw = pWrong(sigmaIndex);
  const lead = counts[argmax] / total - pc;
  let errNormal = lead * lead;
  for (let b = 0; b < N; b++) {
    if (b === argmax) continue;
    const d = counts[b] / total - pw;
    errNormal += d * d;
  }

  return { sigmaIndex, errStrong, errNormal, difference: errStrong - errNormal };
}

/**
 * Indices ordered most-likely-strong first.
 *
 * Index 0 is excluded: equation 9's range of l is empty there, so Rk[0] is
 * never a strong key byte and equation 12 cannot produce a value for it.
 */
export function rankStrongCandidates(
  tables: readonly { readonly counts: Uint32Array; readonly total: number }[]
): StrongIndicator[] {
  return tables
    .map((t, i) => strongIndicator(t.counts, t.total, i))
    .filter((ind) => ind.sigmaIndex >= 1)
    .sort((a, b) => a.difference - b.difference);
}

/**
 * Equation 12: the possible values of Rk[i] when Rk[i] is assumed strong and
 * Rk[0..i-1] are known. At most i values, one per l in {1..i}.
 */
export function strongByteValues(prefix: readonly number[], i: number): number[] {
  if (i < 1 || prefix.length !== i) {
    throw new Error(`strongByteValues needs the first ${i} key bytes; got ${prefix.length}`);
  }
  const values = new Set<number>();
  // Running sum from the right: sum_{j=l}^{i-1} (Rk[j] + 3 + j).
  let tail = 0;
  for (let l = i - 1; l >= 1; l--) {
    tail = (tail + prefix[l] + 3 + l) & 0xff;
    values.add((-3 - i - tail) & 0xff);
  }
  // l = i means the sum is empty: Rk[i] = -3 - i.
  values.add((-3 - i) & 0xff);
  return [...values];
}
