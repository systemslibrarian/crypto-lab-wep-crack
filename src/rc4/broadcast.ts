/**
 * The broadcast single-byte-bias attack, bound to the measured bias table.
 *
 * The attack mechanics are in `broadcast-core.ts` (table-free, so the worker
 * can import them without the 394 KB table). This module adds the measured
 * distribution: `bias-table.json`, produced offline by
 * `scripts/gen-bias-table.mjs` over 2^24 random keys — the paper's §4.1
 * measurement step at a teaching scale (the paper used 2^44).
 *
 * `recoverPlaintext` takes only the per-position ciphertext tallies and this
 * public table; it never sees the plaintext. `runBroadcast` plays both sides
 * for a demo and scores the result.
 *
 * What this reaches, honestly: at the session counts a browser can run (≈2^18),
 * only the strongest biases recover reliably — above all Z_2, biased toward 0
 * at ≈ 1/128 (Mantin–Shamir). That same byte is the one that CANNOT be attacked
 * in TLS, because the first 36 keystream bytes encrypt the Finished message.
 */
import biasTableData from './bias-table.json';
import {
  generateTallies,
  logProbRow,
  recoverFromRows,
  scoreRun,
  type BroadcastResult,
  type KeySource,
} from './broadcast-core';

export * from './broadcast-core';

export interface BiasTable {
  readonly note: string;
  readonly log2keys: number;
  readonly samples: number;
  readonly positions: number;
  /** counts[r-1][k] = number of measured keys with Z_r = k. Row 0 is Z_1. */
  readonly counts: readonly (readonly number[])[];
}

export const BIAS_TABLE = biasTableData as BiasTable;

/** The log-prob rows for a set of 1-indexed positions, from the measured table. */
export function logProbRows(positions: readonly number[], table: BiasTable = BIAS_TABLE): Float64Array[] {
  return positions.map((r) => {
    if (r < 1 || r > table.positions) throw new RangeError(`position ${r} is outside the measured table (1..${table.positions})`);
    return logProbRow(table.counts[r - 1], table.samples);
  });
}

/** Recover a plaintext from per-position tallies, using the measured table. Secret-free. */
export function recoverPlaintext(
  tallies: readonly (Int32Array | readonly number[])[],
  positions: readonly number[],
  table: BiasTable = BIAS_TABLE,
): Uint8Array {
  return recoverFromRows(tallies, logProbRows(positions, table));
}

/** A full demo run: broadcast `secret`, recover from the tallies alone, and score. */
export function runBroadcast(
  secret: Uint8Array,
  positions: readonly number[],
  sessions: number,
  keySource: KeySource,
  table: BiasTable = BIAS_TABLE,
): BroadcastResult {
  const tallies = generateTallies(secret, positions, sessions, keySource);
  const recovered = recoverPlaintext(tallies, positions, table);
  return scoreRun(secret, positions, sessions, recovered);
}
