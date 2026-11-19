/**
 * The broadcast single-byte-bias attack — the table-free core.
 *
 * Kept separate from `broadcast.ts` so the attack worker can import the heavy
 * keystream-tallying code without pulling the 394 KB measured bias table into
 * its bundle. The table-bound convenience lives in `broadcast.ts`.
 *
 * AlFardan, Bernstein, Paterson, Poettering and Schuldt, "On the Security of
 * RC4 in TLS and WPA" (USENIX Security 2013), §4.1.
 */
import { Rc4Keystream } from './rc4';

/**
 * In TLS the first 36 bytes of the RC4 keystream encrypt the Handshake Finished
 * message, which is not constant across sessions, so positions 1..36 cannot be
 * attacked in the broadcast model. AlFardan et al., §3.1: "this byte is always
 * used to encrypt a Finished message in TLS, we are unable to exploit it in our
 * attacks." A TLS broadcast attack therefore starts at position 37.
 */
export const TLS_FIRST_USABLE_POSITION = 37;

/**
 * The paper's headline figure, as context for a teaching-scale run. §5.1 states
 * it twice with slightly different counts; this is the first-bullet figure.
 */
export const PAPER_HEADLINE =
  'AlFardan et al. report that with S = 2^26 sessions the first 80 plaintext bytes are recovered ' +
  'at a rate of at least 50% per byte (§5.1; the same section gives this count as 72 where it ' +
  'compares against a restricted character set). This lab runs far fewer sessions.';

/** log p_{r,k} for one position, with add-one smoothing so no term is log(0). */
export function logProbRow(counts: readonly number[], samples: number): Float64Array {
  const row = new Float64Array(256);
  const denom = samples + 256;
  for (let k = 0; k < 256; k++) row[k] = Math.log((counts[k] + 1) / denom);
  return row;
}

/**
 * Algorithm 4 (the single-byte maximum-likelihood attack), one position.
 *
 * `tally[c]` is the number of sessions whose ciphertext byte was c. For a
 * candidate plaintext byte μ the implied keystream value is k = c ⊕ μ, so
 * λ_μ = Σ_k N_{k⊕μ} · log p_{r,k}. The argmax is the ML plaintext byte. Takes
 * no plaintext — only the observed tally and the public distribution.
 */
export function recoverByte(tally: Int32Array | readonly number[], logRow: Float64Array): number {
  let best = -Infinity;
  let bestMu = 0;
  for (let mu = 0; mu < 256; mu++) {
    let lambda = 0;
    for (let k = 0; k < 256; k++) lambda += (tally[k ^ mu] as number) * logRow[k];
    if (lambda > best) {
      best = lambda;
      bestMu = mu;
    }
  }
  return bestMu;
}

/** Recover a whole plaintext from per-position tallies and their log-prob rows. Secret-free. */
export function recoverFromRows(
  tallies: readonly (Int32Array | readonly number[])[],
  rows: readonly Float64Array[],
): Uint8Array {
  if (tallies.length !== rows.length) throw new RangeError('one log-prob row per tally');
  const out = new Uint8Array(tallies.length);
  for (let i = 0; i < tallies.length; i++) out[i] = recoverByte(tallies[i], rows[i]);
  return out;
}

export type KeySource = () => Uint8Array;

/** A 16-byte key source from crypto.getRandomValues. */
export const secureKeySource: KeySource = () => crypto.getRandomValues(new Uint8Array(16));

/**
 * A deterministic 16-byte key source (splitmix64), so a run is reproducible
 * from a seed — the brief's "fixed seed and enough sessions".
 */
export function seededKeySource(seed: number): KeySource {
  const mask = (1n << 64n) - 1n;
  let s = (BigInt(seed) * 0x9e3779b97f4a7c15n + 0x1n) & mask;
  const next = (): bigint => {
    s = (s + 0x9e3779b97f4a7c15n) & mask;
    let z = s;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & mask;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & mask;
    return (z ^ (z >> 31n)) & mask;
  };
  return () => {
    const key = new Uint8Array(16);
    for (let o = 0; o < 16; o += 8) {
      let v = next();
      for (let b = 0; b < 8; b++) {
        key[o + b] = Number(v & 0xffn);
        v >>= 8n;
      }
    }
    return key;
  };
}

/**
 * Per-position ciphertext tallies for a broadcast of `secret` over `sessions`
 * keys — the SENDER's side (it holds the secret and encrypts it). `positions`
 * are 1-indexed keystream positions; secret byte i is encrypted at positions[i].
 */
export function generateTallies(
  secret: Uint8Array,
  positions: readonly number[],
  sessions: number,
  keySource: KeySource,
): Int32Array[] {
  if (secret.length !== positions.length) throw new RangeError('one position per secret byte');
  const maxPos = Math.max(...positions);
  const tallies = positions.map(() => new Int32Array(256));
  for (let n = 0; n < sessions; n++) {
    const z = new Rc4Keystream(keySource()).next(maxPos);
    for (let i = 0; i < positions.length; i++) tallies[i][secret[i] ^ z[positions[i] - 1]]++;
  }
  return tallies;
}

export interface BroadcastResult {
  positions: number[];
  sessions: number;
  recovered: Uint8Array;
  correct: boolean[];
  successCount: number;
}

/** Score a recovery against the secret (the comparison a real attacker cannot make). */
export function scoreRun(secret: Uint8Array, positions: readonly number[], sessions: number, recovered: Uint8Array): BroadcastResult {
  const correct = Array.from(recovered, (b, i) => b === secret[i]);
  return { positions: [...positions], sessions, recovered, correct, successCount: correct.reduce((n, c) => n + (c ? 1 : 0), 0) };
}

/** Consecutive 1-indexed positions of length `len` starting at `start`. */
export function positionRange(start: number, len: number): number[] {
  return Array.from({ length: len }, (_, i) => start + i);
}
