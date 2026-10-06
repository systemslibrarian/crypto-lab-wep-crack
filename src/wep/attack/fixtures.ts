/**
 * Reproducible PTW experiment fixtures.
 *
 * Each is a SEED for the labelled deterministic byte source in
 * `src/wep/traffic.ts`, not a stored answer. The key below is what that seed
 * produces, recorded so a test can assert recovery against it; the attack still
 * runs for real on every execution and nothing reads these keys into the
 * attacker. Deleting the `expectedKeyHex` field would not make the fixtures
 * pass — it would only stop the tests being able to tell.
 *
 * Measured on 2026-10-06, Apple silicon (arm64) under Node 24 / Vitest 5, with
 * scenarios 1-3 and a 200,000-candidate budget. `candidatesTested` is what that
 * run observed; it is recorded as an observation, not asserted as a constant,
 * because the search order is stable but the figure is not a specification.
 */

export interface PtwFixture {
  readonly label: string;
  readonly seed: number;
  readonly packets: number;
  readonly keyBits: 104;
  readonly expectedKeyHex: string;
  /** Observed on the machine and date in this file's header. */
  readonly observedCandidatesTested: number;
}

/** Fixtures that recover, on three independent keys. */
export const PTW_SUCCESS_FIXTURES: readonly PtwFixture[] = [
  {
    label: 'success A',
    seed: 104729,
    packets: 35000,
    keyBits: 104,
    expectedKeyHex: 'b1d44702cc988d22f85e172374',
    observedCandidatesTested: 75,
  },
  {
    label: 'success B',
    seed: 628374,
    packets: 35000,
    keyBits: 104,
    expectedKeyHex: 'b02611fb8fd1907f8c504fc9e6',
    observedCandidatesTested: 183,
  },
  {
    label: 'success C — needs real key ranking, not just the top votes',
    seed: 314187,
    packets: 35000,
    keyBits: 104,
    expectedKeyHex: '18858ea1f204137106da42fb37',
    observedCandidatesTested: 4124,
  },
];

/**
 * A fixture known to EXHAUST its configured search budget.
 *
 * Asserting "no key within this budget" needs an input where that is the real
 * outcome rather than a flaky one; this seed and packet count do not recover
 * within 200,000 candidates, so a 200-candidate budget certainly bounds it.
 */
export const PTW_BUDGET_FIXTURE = {
  label: 'budget exhaustion',
  seed: 209458,
  packets: 25000,
  keyBits: 104 as const,
  maxCandidates: 200,
  expectedKeyHex: '6328a2890cf2582108b8b9f6b3',
};

/**
 * Measured success rate across fresh random keys, same machine and date.
 *
 * These are OBSERVATIONS of this implementation, reported alongside the
 * paper's own published result rather than in place of it. The PTW paper
 * reports ~50% success from fewer than 40,000 packets under ITS stated
 * conditions and with all three scenarios plus a 1,000,000-key limit [R3,
 * section 7]; this row set is a different implementation on different hardware
 * with a smaller budget, so the two are not interchangeable.
 */
export const MEASURED_SUCCESS_RATES: readonly {
  readonly packets: number;
  readonly recovered: number;
  readonly attempted: number;
}[] = [
  { packets: 20000, recovered: 0, attempted: 8 },
  { packets: 40000, recovered: 3, attempted: 8 },
  { packets: 50000, recovered: 10, attempted: 12 },
  { packets: 60000, recovered: 11, attempted: 12 },
  { packets: 70000, recovered: 8, attempted: 8 },
];

export const MEASUREMENT_NOTE =
  'Measured 2026-10-06 on Apple silicon (arm64), Node 24, scenarios 1-3, ' +
  '200,000-candidate budget. Not the paper’s figure and not a guarantee.';
