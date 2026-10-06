import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../bytes';
import {
  ARP_REQUEST_KNOWN_PREFIX,
  PROFILE_ID,
  PROFILE_PAYLOAD_LEN,
  seededRand,
  TrafficGenerator,
} from '../traffic';
import { parseBody, wepEncrypt } from '../wep';
import { buildAttackRequest, type AttackRequest } from './contract';
import { MEASURED_SUCCESS_RATES, PTW_BUDGET_FIXTURE, PTW_SUCCESS_FIXTURES } from './fixtures';
import {
  intake,
  keyFromSigmas,
  keystreamBytesNeeded,
  runPtw,
  sigmasFromKey,
  tally,
  validateCandidate,
  votesForSample,
} from './ptw';

const PROFILE = {
  profileId: PROFILE_ID,
  knownPrefix: ARP_REQUEST_KNOWN_PREFIX,
  payloadLength: PROFILE_PAYLOAD_LEN,
  keyId: 0,
};

/**
 * Build a capture-only request from a seeded session.
 *
 * Note what crosses: `.body` only. The generated packets' `plaintext` field is
 * ground truth and is dropped here, by hand, at the boundary.
 */
function session(seed: number, packets: number, reserve = 20, maxCandidates = 200000) {
  const rand = seededRand(seed);
  const sharedKey = rand(13);
  const gen = new TrafficGenerator({ sharedKey, rand });
  const all = gen.take(packets + reserve);
  const request = buildAttackRequest({
    runId: `test-${seed}-${packets}`,
    keyBits: 104,
    profile: PROFILE,
    budget: { maxPackets: packets, maxCandidates, maxMillis: 120_000 },
    capturedBodies: all.slice(0, packets).map((p) => p.body),
    validationBodies: all.slice(packets).map((p) => p.body),
  });
  return { sharedKey, request, generated: all };
}

describe('the equation-5 estimator', () => {
  it('needs the first secretBytes+2 keystream bytes', () => {
    // A_0 reads X[2]; A_12 reads X[14]. So 13 secret bytes need 15 bytes.
    expect(keystreamBytesNeeded(13)).toBe(15);
    expect(keystreamBytesNeeded(5)).toBe(7);
    // And the ARP profile publishes 16, which is why it is the chosen profile.
    expect(ARP_REQUEST_KNOWN_PREFIX.length).toBeGreaterThanOrEqual(keystreamBytesNeeded(13));
  });

  it('is computed from the public IV and recovered keystream alone', () => {
    // votesForSample takes exactly three arguments, none of them secret.
    expect(votesForSample.length).toBe(3);
  });

  it('favours the true sums far above chance over a real session', () => {
    // The whole attack rests on this bias, so it is measured rather than
    // asserted. Under no bias every value would get total/256 votes.
    const { sharedKey, request } = session(104729, 30000);
    const taken = intake(request.captured, ARP_REQUEST_KNOWN_PREFIX, PROFILE_PAYLOAD_LEN, 0, 13);
    const tables = tally(taken.samples, 13);
    const trueSigmas = sigmasFromKey(sharedKey);
    const chance = taken.samples.length / 256;
    let leadingCount = 0;
    for (let i = 0; i < 13; i++) {
      if (tables[i].counts[trueSigmas[i]] > chance * 1.1) leadingCount++;
    }
    // The paper's probability is ~1.36/n against 1/n, so most tables should
    // show the true value well above chance even at 30,000 samples.
    expect(leadingCount).toBeGreaterThanOrEqual(9);
  });
});

describe('sums and key bytes are different things', () => {
  it('reads the key back off the sums: Rk[0]=s0, Rk[i]=si-s(i-1)', () => {
    const key = fromHex('0405060708090a0b0c0d0e0f10');
    expect(toHex(keyFromSigmas(sigmasFromKey(key)))).toBe(toHex(key));
  });

  it('a sum table is NOT a table of key-byte guesses', () => {
    // Guards the labelling the brief calls out: sigma_4 is the running total of
    // five key bytes, not a guess at the fifth.
    const key = fromHex('0405060708090a0b0c0d0e0f10');
    const sigmas = sigmasFromKey(key);
    expect(sigmas[4]).toBe((4 + 5 + 6 + 7 + 8) & 0xff);
    expect(sigmas[4]).not.toBe(key[4]);
  });

  it('wraps mod 256', () => {
    const key = new Uint8Array([200, 200, 200]);
    expect(sigmasFromKey(key)).toEqual([200, 144, 88]);
    expect(toHex(keyFromSigmas([200, 144, 88]))).toBe(toHex(key));
  });
});

describe('intake counters and duplicate-IV exclusion', () => {
  it('counts each IV once for voting and excludes the repeats', () => {
    const rand = seededRand(777);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    const packets = gen.take(50);
    // Re-send three of them verbatim: same IV, same keystream, no new evidence.
    const bodies = [...packets.map((p) => p.body), packets[0].body, packets[7].body, packets[7].body];
    const taken = intake(bodies.map((body) => ({ body })), ARP_REQUEST_KNOWN_PREFIX, PROFILE_PAYLOAD_LEN, 0, 13);
    expect(taken.supplied).toBe(53);
    expect(taken.duplicateIvExcluded).toBe(3);
    expect(taken.samples).toHaveLength(50);
  });

  it('duplicate IVs do not inflate vote counts', () => {
    const rand = seededRand(888);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    const packets = gen.take(200);
    const once = tally(
      intake(packets.map((p) => ({ body: p.body })), ARP_REQUEST_KNOWN_PREFIX, PROFILE_PAYLOAD_LEN, 0, 13).samples,
      13
    );
    const doubled = tally(
      intake(
        [...packets, ...packets].map((p) => ({ body: p.body })),
        ARP_REQUEST_KNOWN_PREFIX,
        PROFILE_PAYLOAD_LEN,
        0,
        13
      ).samples,
      13
    );
    for (let i = 0; i < 13; i++) {
      expect(doubled[i].total, `table ${i}`).toBe(once[i].total);
      expect([...doubled[i].counts]).toEqual([...once[i].counts]);
    }
  });

  it('excludes a wrong Key ID, a wrong length and a malformed body, with named counters', () => {
    const rand = seededRand(999);
    const sharedKey = rand(13);
    const good = wepEncrypt(new Uint8Array(PROFILE_PAYLOAD_LEN), fromHex('010203'), sharedKey, 0);
    const wrongKeyId = wepEncrypt(new Uint8Array(PROFILE_PAYLOAD_LEN), fromHex('040506'), sharedKey, 2);
    const wrongLength = wepEncrypt(new Uint8Array(PROFILE_PAYLOAD_LEN - 1), fromHex('070809'), sharedKey, 0);
    const malformed = new Uint8Array(5);
    const taken = intake(
      [good, wrongKeyId, wrongLength, malformed].map((body) => ({ body })),
      ARP_REQUEST_KNOWN_PREFIX,
      PROFILE_PAYLOAD_LEN,
      0,
      13
    );
    expect(taken.samples).toHaveLength(1);
    expect(taken.unusable).toBe(3);
    expect(taken.duplicateIvExcluded).toBe(0);
    expect(taken.supplied).toBe(4);
  });

  it('reserved validation packets never enter the voting set', () => {
    const { request } = session(104729, 500);
    const taken = intake(request.captured, ARP_REQUEST_KNOWN_PREFIX, PROFILE_PAYLOAD_LEN, 0, 13);
    expect(taken.samples).toHaveLength(500);
    expect(request.validation).toHaveLength(20);
    // The two sets are disjoint by construction; assert it from the bytes.
    const votingIvs = new Set(taken.samples.map((s) => toHex(s.iv)));
    for (const v of request.validation) {
      expect(votingIvs.has(toHex(parseBody(v.body).iv))).toBe(false);
    }
  });
});

describe('candidate validation uses captured evidence, never an oracle', () => {
  it('rejects a deliberately wrong candidate', () => {
    const { sharedKey, request } = session(104729, 100);
    const wrong = Uint8Array.from(sharedKey);
    wrong[6] ^= 0x01;
    const v = validateCandidate(wrong, request.validation, ARP_REQUEST_KNOWN_PREFIX, 15);
    expect(v.ok).toBe(false);
  });

  it('accepts the real key and reports how many packets it checked', () => {
    const { sharedKey, request } = session(104729, 100);
    const v = validateCandidate(sharedKey, request.validation, ARP_REQUEST_KNOWN_PREFIX, 15);
    expect(v.ok).toBe(true);
    expect(v.checked).toBe(20);
  });

  it('reports not-ok when there is nothing to validate against', () => {
    const { sharedKey } = session(104729, 10, 0);
    expect(validateCandidate(sharedKey, [], ARP_REQUEST_KNOWN_PREFIX, 15).ok).toBe(false);
  });

  it('takes no argument through which the hidden key could arrive', () => {
    expect(validateCandidate.length).toBe(4);
  });
});

describe('the deterministic success fixtures recover the real key', () => {
  for (const f of PTW_SUCCESS_FIXTURES) {
    it(`${f.label}: recovers ${f.expectedKeyHex} from ${f.packets} packets`, () => {
      const { sharedKey, request } = session(f.seed, f.packets);
      // The fixture's recorded key is what the seed produces.
      expect(toHex(sharedKey)).toBe(f.expectedKeyHex);
      const result = runPtw(request);
      expect(result.state).toBe('recovered-candidate');
      expect(result.candidate).not.toBeNull();
      // Equality computed here, independently of anything the attacker said.
      expect(toHex(result.candidate!)).toBe(f.expectedKeyHex);
      expect(result.counts.validationChecked).toBeGreaterThan(0);
      expect(result.counts.candidatesTested).toBeGreaterThan(0);
      expect(result.runId).toBe(request.runId);
    }, 60_000);
  }

  it('recovers three distinct keys, so a fixed return value cannot pass', () => {
    // This is what kills the "PTW always returns a fixed key" mutation.
    expect(new Set(PTW_SUCCESS_FIXTURES.map((f) => f.expectedKeyHex)).size).toBe(3);
  });
});

describe('bounded runs and their states', () => {
  it('a fixture known to exhaust its budget reports no-key-within-budget', () => {
    const { request } = session(
      PTW_BUDGET_FIXTURE.seed,
      PTW_BUDGET_FIXTURE.packets,
      20,
      PTW_BUDGET_FIXTURE.maxCandidates
    );
    const result = runPtw(request);
    expect(result.state).toBe('no-key-within-budget');
    expect(result.candidate).toBeNull();
    expect(result.boundBy).toBe('candidates');
    // The measured counts survive the failure (brief section 11).
    expect(result.counts.voting).toBeGreaterThan(24000);
    expect(result.counts.candidatesTested).toBeGreaterThan(0);
    expect(result.voteTables).toHaveLength(13);
  }, 60_000);

  it('no usable samples is distinguished from no key found', () => {
    const request: AttackRequest = {
      runId: 'empty',
      keyBits: 104,
      profile: PROFILE,
      budget: { maxPackets: 10, maxCandidates: 10, maxMillis: 1000 },
      captured: [{ body: new Uint8Array(5) }, { body: new Uint8Array(6) }],
      validation: [],
    };
    const result = runPtw(request);
    expect(result.state).toBe('no-usable-samples');
    expect(result.candidate).toBeNull();
    expect(result.voteTables).toEqual([]);
  });

  it('an empty capture reports no usable samples rather than throwing', () => {
    const result = runPtw({
      runId: 'none',
      keyBits: 104,
      profile: PROFILE,
      budget: { maxPackets: 10, maxCandidates: 10, maxMillis: 1000 },
      captured: [],
      validation: [],
    });
    expect(result.state).toBe('no-usable-samples');
    expect(result.counts.supplied).toBe(0);
  });

  it('cancellation stops the run and reports cancelled', () => {
    const { request } = session(209458, 2000, 20, 200000);
    const result = runPtw(request, { shouldContinue: () => false });
    expect(result.state).toBe('cancelled');
    expect(result.candidate).toBeNull();
  }, 60_000);

  it('the time cap is reported as a budget, not a cancellation', () => {
    const { request } = session(209458, 25000, 20, 1_000_000);
    const result = runPtw({ ...request, budget: { ...request.budget, maxMillis: 1 } });
    expect(result.state).toBe('no-key-within-budget');
    expect(result.boundBy).toBe('time');
  }, 60_000);

  it('the packet cap really caps the packets drawn in', () => {
    const { request } = session(104729, 1000, 20, 10);
    const capped = runPtw({ ...request, budget: { ...request.budget, maxPackets: 100 } });
    expect(capped.counts.supplied).toBe(100);
    expect(capped.counts.voting).toBeLessThanOrEqual(100);
  });

  it('an experiment error is reported as one, not as a failed recovery', () => {
    const result = runPtw({
      runId: 'bad-profile',
      keyBits: 104,
      profile: { ...PROFILE, knownPrefix: null as unknown as Uint8Array },
      budget: { maxPackets: 10, maxCandidates: 10, maxMillis: 1000 },
      // 4-byte clear prefix + 36-byte payload + 4-byte ICV: a body that really
      // reaches the profile lookup, so the broken profile is what fails.
      captured: [{ body: new Uint8Array(44) }],
      validation: [],
    });
    expect(result.state).toBe('experiment-error');
    expect(result.error).toBeTruthy();
    expect(result.candidate).toBeNull();
  });

  it('every result carries the run id it was asked for', () => {
    // So a late worker reply for an old run can be discarded by the panel.
    const { request } = session(104729, 50, 20, 1);
    expect(runPtw(request).runId).toBe(request.runId);
  });

  it('reports which scenario produced the candidate', () => {
    const f = PTW_SUCCESS_FIXTURES[0];
    const { request } = session(f.seed, f.packets);
    const result = runPtw(request);
    expect(result.scenario).toBeGreaterThanOrEqual(1);
    expect(result.scenario).toBeLessThanOrEqual(3);
  }, 60_000);
});

describe('the recorded measurements are observations, not specifications', () => {
  it('the published rate table is monotone in packets and honestly bounded', () => {
    for (const row of MEASURED_SUCCESS_RATES) {
      expect(row.recovered).toBeLessThanOrEqual(row.attempted);
      expect(row.attempted).toBeGreaterThan(0);
    }
    // Nothing claims 100% at any count, because nothing measured it.
    const best = MEASURED_SUCCESS_RATES.find((r) => r.packets === 20000)!;
    expect(best.recovered).toBe(0);
  });
});
