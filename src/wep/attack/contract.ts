/**
 * The attacker's intake contract. This file is the boundary.
 *
 * The simulated attacker receives CAPTURED BYTES and the PUBLISHED PROFILE
 * ASSUMPTIONS, and nothing else. It must not receive (brief section 5):
 *   - the shared key,
 *   - the generator's seed or state,
 *   - full plaintext,
 *   - a callable reference to the generator or the experiment controller.
 *
 * Note what the type system can and cannot do here. These interfaces make the
 * contract explicit and `buildAttackRequest` is the only sanctioned way to
 * build one, but a structural type cannot stop someone adding a field later —
 * so the boundary is checked three further ways:
 *   - `isolation.test.ts` walks the attacker's real import graph on disk and
 *     fails if a stateful generator module appears in it;
 *   - `assertCaptureOnly` below inspects the actual runtime message, because an
 *     import scan cannot see a field smuggled onto an object;
 *   - `ptw.test.ts` runs the attack from serialised input with no generator in
 *     scope at all.
 * A static import scan presented as proof of isolation is exactly what the
 * brief warns against; it is one guard of several here.
 *
 * AND THE HONEST CAVEAT, which the page repeats: these are EXPERIMENTAL ROLES
 * inside one browser application. Hiding a value behind an interface does not
 * make it inaccessible to a person inspecting their own browser. The separation
 * is real as a matter of data flow — it is what makes the recovery a result
 * rather than a lookup — not as a security boundary.
 */

/** One captured protected body. Public bytes only. */
export interface CapturedPacket {
  /** The whole protected body as it went out: IV || keyId || RC4(payload||ICV). */
  readonly body: Uint8Array;
}

/** The public, declared traffic assumptions. No secrets. */
export interface ProfileAssumptions {
  /** The profile identifier, e.g. 'llc-snap-arp-request-ipv4'. */
  readonly profileId: string;
  /** The bytes the profile says every payload begins with. */
  readonly knownPrefix: Uint8Array;
  /** The payload length the profile declares. */
  readonly payloadLength: number;
  /** The Key ID the attacker expects to parse. */
  readonly keyId: number;
}

/** Resource budgets. The learner sets these; they are not secrets. */
export interface AttackBudget {
  /** Hard cap on packets drawn into the vote. */
  readonly maxPackets: number;
  /** Hard cap on candidate keys constructed and tested. */
  readonly maxCandidates: number;
  /** Wall-clock cap in milliseconds. */
  readonly maxMillis: number;
}

export interface AttackRequest {
  /** Tags every message of this run, so a late reply cannot restore a stale verdict. */
  readonly runId: string;
  /** The declared key size being attacked. Public: the attacker is told. */
  readonly keyBits: 40 | 104;
  readonly profile: ProfileAssumptions;
  readonly budget: AttackBudget;
  /** Packets for the vote. */
  readonly captured: readonly CapturedPacket[];
  /** Reserved distinct-IV packets, for candidate validation only. */
  readonly validation: readonly CapturedPacket[];
}

/** Field names that must never appear in an attack request, at any depth. */
export const FORBIDDEN_FIELDS = [
  'sharedKey',
  'key',
  'secret',
  'plaintext',
  'plain',
  'seed',
  'rand',
  'generator',
  'controller',
  'groundTruth',
  'truth',
  'answer',
] as const;

export class ContractViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContractViolation';
  }
}

/**
 * Inspect an actual runtime message for prohibited content.
 *
 * This looks at the OBJECT, not at the source, because a field added to a
 * payload at a call site is invisible to an import scan. It walks every nested
 * key and rejects any function-valued property outright — a callable is how a
 * generator reference would arrive.
 */
export function assertCaptureOnly(request: unknown): void {
  const seen = new Set<unknown>();
  const walk = (value: unknown, path: string): void => {
    if (value === null || typeof value !== 'object') {
      if (typeof value === 'function') {
        throw new ContractViolation(`callable reference at ${path} — the attacker gets bytes, not functions`);
      }
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const here = `${path}.${k}`;
      const lower = k.toLowerCase();
      for (const bad of FORBIDDEN_FIELDS) {
        if (lower === bad.toLowerCase()) {
          throw new ContractViolation(`prohibited field "${k}" at ${here}`);
        }
      }
      if (typeof v === 'function') {
        throw new ContractViolation(`callable reference at ${here} — the attacker gets bytes, not functions`);
      }
      walk(v, here);
    }
  };
  walk(request, 'request');
}

/**
 * The only sanctioned way to build an attack request.
 *
 * It takes the captured bodies as raw byte arrays — deliberately NOT
 * `GeneratedPacket`, whose `plaintext` field is ground truth. A caller holding
 * generated packets must strip them down to bodies to get here, and that strip
 * is the boundary crossing.
 */
export function buildAttackRequest(args: {
  runId: string;
  keyBits: 40 | 104;
  profile: ProfileAssumptions;
  budget: AttackBudget;
  capturedBodies: readonly Uint8Array[];
  validationBodies: readonly Uint8Array[];
}): AttackRequest {
  const request: AttackRequest = {
    runId: args.runId,
    keyBits: args.keyBits,
    profile: {
      profileId: args.profile.profileId,
      knownPrefix: args.profile.knownPrefix.slice(),
      payloadLength: args.profile.payloadLength,
      keyId: args.profile.keyId,
    },
    budget: args.budget,
    captured: args.capturedBodies.map((body) => ({ body: body.slice() })),
    validation: args.validationBodies.map((body) => ({ body: body.slice() })),
  };
  assertCaptureOnly(request);
  return request;
}

/** The states a bounded run can end in (brief section 7). */
export type AttackState =
  | 'collecting'
  | 'no-usable-samples'
  | 'no-key-within-budget'
  | 'cancelled'
  | 'recovered-candidate'
  | 'experiment-error';

/** Counters, kept separately because they mean different things. */
export interface AttackCounts {
  /** Packets handed to the attacker. */
  readonly supplied: number;
  /** Packets that parsed and yielded enough known keystream. */
  readonly usable: number;
  /** Packets excluded because their IV had already been counted. */
  readonly duplicateIvExcluded: number;
  /** Distinct-IV samples that actually entered the vote. */
  readonly voting: number;
  /** Reserved packets available for validation. */
  readonly validationAvailable: number;
  /** Reserved packets actually checked against the winning candidate. */
  readonly validationChecked: number;
  /** Candidate keys constructed and tested. */
  readonly candidatesTested: number;
}

/**
 * What the attacker returns.
 *
 * `candidate` is a VALIDATED CANDIDATE, not a recovered key. It became a
 * candidate by winning a vote and surviving capture-based validation. Whether
 * it is actually the key is decided outside the attacker, by the experiment
 * controller comparing it byte for byte with ground truth it never shared.
 */
export interface AttackResult {
  readonly runId: string;
  readonly state: AttackState;
  readonly candidate: Uint8Array | null;
  readonly counts: AttackCounts;
  readonly elapsedMillis: number;
  /** Top-ranked vote rows per sigma index, for the inspectable vote tables. */
  readonly voteTables: readonly VoteTableSummary[];
  /**
   * Which limit stopped a bounded run, when one did. Reported because
   * "no key within this budget" means something different depending on whether
   * the candidate cap or the clock ran out first.
   */
  readonly boundBy?: 'candidates' | 'time' | null;
  /** Which of the paper's scenarios produced the candidate, when one did. */
  readonly scenario?: number | null;
  /** The sigma indices that scenario assumed to be strong key bytes. */
  readonly assumedStrong?: readonly number[];
  /** Set when state is 'experiment-error'. */
  readonly error?: string;
}

export interface VoteTableSummary {
  /** Which sigma_i this table votes on. */
  readonly sigmaIndex: number;
  /** The leading values and their vote counts, best first. */
  readonly top: readonly { readonly value: number; readonly votes: number }[];
  /** Total votes cast into this table. */
  readonly totalVotes: number;
}

/** Progress, emitted during a bounded run. */
export interface AttackProgress {
  readonly runId: string;
  readonly phase: 'voting' | 'ranking';
  readonly processed: number;
  readonly total: number;
  readonly candidatesTested: number;
}

export type WorkerInbound =
  | { readonly kind: 'run'; readonly request: AttackRequest }
  | { readonly kind: 'cancel'; readonly runId: string };

export type WorkerOutbound =
  | { readonly kind: 'progress'; readonly progress: AttackProgress }
  | { readonly kind: 'result'; readonly result: AttackResult };
