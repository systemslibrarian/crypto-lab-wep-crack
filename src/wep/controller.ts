/**
 * The experiment controller. It is the ONLY thing that knows the hidden key.
 *
 * This module is deliberately NOT importable by the attacker — the import-graph
 * check in `attack/isolation.test.ts` fails if it ever appears in the worker's
 * graph. Its one job is the final comparison: the attacker returns a validated
 * candidate, and the controller decides whether that candidate IS the key by
 * comparing it byte for byte against ground truth it never shared.
 *
 * A mismatch is an EXPERIMENT FAILURE, not a successful recovery. That
 * distinction is the whole reason this module exists separately: if the
 * attacker could ask "is this the key?", the recovery would be a lookup.
 *
 * The honest caveat, repeated on the page: this is a data-flow separation
 * inside one browser tab. Hiding a value in an interface does not make it
 * inaccessible to a person inspecting their own browser.
 */

import { randomBytes } from './bytes';
import { TrafficGenerator } from './traffic';
import type { GeneratedPacket } from './types';
import { sameKey } from './wep';

export interface SessionOptions {
  /** 13 for the stage-1 104-bit recovery profile. */
  readonly sharedKeyBytes: number;
}

export type Comparison =
  | { readonly kind: 'recovered' }
  | { readonly kind: 'mismatch'; readonly reason: string }
  | { readonly kind: 'no-candidate' };

export class ExperimentController {
  /** Ground truth. Never leaves this object. */
  private readonly sharedKey: Uint8Array;
  private readonly generator: TrafficGenerator;

  constructor(opts: SessionOptions) {
    // A FRESH session key from the browser's cryptographic random source. It is
    // never one of the keys shown in the RC4 or construction walkthroughs: those
    // panels hold their own, and nothing is copied between them.
    this.sharedKey = randomBytes(opts.sharedKeyBytes);
    this.generator = new TrafficGenerator({ sharedKey: this.sharedKey });
  }

  get keyBits(): number {
    return this.sharedKey.length * 8;
  }

  /** Generate traffic. The caller strips these to bodies at the boundary. */
  generate(count: number): GeneratedPacket[] {
    return this.generator.take(count);
  }

  /**
   * The final comparison, byte for byte.
   *
   * Note what this does NOT offer: there is no "is this byte right?" and no way
   * to ask before the attacker has committed to an answer.
   */
  compare(candidate: Uint8Array | null): Comparison {
    if (!candidate) return { kind: 'no-candidate' };
    if (candidate.length !== this.sharedKey.length) {
      return {
        kind: 'mismatch',
        reason: `the candidate is ${candidate.length} bytes; the session key is ${this.sharedKey.length}`,
      };
    }
    if (sameKey(candidate, this.sharedKey)) return { kind: 'recovered' };
    let firstDiff = -1;
    for (let i = 0; i < candidate.length; i++) {
      if (candidate[i] !== this.sharedKey[i]) {
        firstDiff = i;
        break;
      }
    }
    return { kind: 'mismatch', reason: `the candidate first differs at byte ${firstDiff}` };
  }

  /**
   * Ground truth, for the clearly labelled reveal only.
   *
   * Reading this is a REVEAL and the UI marks it as one. It is never reached by
   * the attack path, and nothing it returns counts as recovery.
   */
  revealForDisplay(): Uint8Array {
    return this.sharedKey.slice();
  }
}
