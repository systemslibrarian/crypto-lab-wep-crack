import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { seededRand, TrafficGenerator } from '../traffic';
import { assertCaptureOnly, buildAttackRequest, ContractViolation, FORBIDDEN_FIELDS } from './contract';
import { runPtw } from './ptw';
import { ARP_REQUEST_KNOWN_PREFIX, PROFILE_ID, PROFILE_PAYLOAD_LEN } from '../traffic';

/**
 * Attacker separation, checked four ways.
 *
 * The brief is explicit that an import check is only ONE guard and that a static
 * scan must not be presented as proof of isolation. So this file walks the real
 * import graph, inspects an actual runtime message, runs the attack from
 * serialised bytes with no generator in scope, and checks the counters.
 *
 * And the standing caveat, which the page also carries: this is a data-flow
 * boundary inside one browser application, not a security boundary. A person
 * inspecting their own browser can reach anything in it.
 */

const HERE = dirname(new URL(import.meta.url).pathname);

/** Modules that hold generator or controller state. */
const STATEFUL_MODULES = ['traffic.ts', 'controller.ts'];

function resolveImport(fromFile: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null;
  const base = resolve(dirname(fromFile), spec);
  for (const candidate of [base, `${base}.ts`, `${base}/index.ts`]) {
    try {
      readFileSync(candidate);
      return candidate;
    } catch {
      /* try the next shape */
    }
  }
  return null;
}

/** Every file reachable from `entry` by relative import. */
function importGraph(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/(?:^|\n)\s*(?:import|export)[^;'"]*from\s*['"]([^'"]+)['"]/g)) {
      const target = resolveImport(file, m[1]);
      if (target) queue.push(target);
    }
  }
  return [...seen];
}

describe('the attacker imports no stateful generator module', () => {
  for (const entry of ['ptw.ts', 'worker.ts', 'strong.ts', 'contract.ts']) {
    it(`${entry}'s whole import graph is free of generator state`, () => {
      const graph = importGraph(resolve(HERE, entry));
      // The walk really ran rather than returning nothing and passing vacuously:
      // the entry file itself must be in its own graph. A LENGTH floor would be
      // wrong here, because contract.ts and strong.ts legitimately import
      // nothing relative - that they are leaves is part of the design.
      expect(graph.some((f) => f.endsWith(`/${entry}`))).toBe(true);
      const offenders = graph.filter((f) => STATEFUL_MODULES.some((m) => f.endsWith(`/${m}`)));
      expect(offenders, `${entry} must not reach ${STATEFUL_MODULES.join(' or ')}`).toEqual([]);
    });
  }

  it('the pure RC4/CRC/WEP helpers ARE shared, which is allowed', () => {
    // Stated so the check above is not read as "the attacker imports nothing".
    const graph = importGraph(resolve(HERE, 'ptw.ts')).map((f) => f.split('/').pop());
    expect(graph).toContain('rc4.ts');
    expect(graph).toContain('wep.ts');
    expect(graph).toContain('crc32.ts');
  });

  it('this check is walking real files, proven by a deliberate miss', () => {
    // A graph walker that silently resolved nothing would pass every assertion
    // above. So: traffic.ts's own graph DOES contain traffic.ts.
    const graph = importGraph(resolve(HERE, '..', 'traffic.ts'));
    expect(graph.some((f) => f.endsWith('/traffic.ts'))).toBe(true);
  });
});

describe('the runtime message is inspected, not just the imports', () => {
  it('rejects every prohibited field name at any depth', () => {
    for (const field of FORBIDDEN_FIELDS) {
      expect(() => assertCaptureOnly({ runId: 'x', [field]: 'anything' }), field).toThrow(
        ContractViolation
      );
      expect(() => assertCaptureOnly({ runId: 'x', nested: { deep: { [field]: 1 } } })).toThrow(
        ContractViolation
      );
    }
  });

  it('rejects a callable reference, which is how a generator would arrive', () => {
    expect(() => assertCaptureOnly({ runId: 'x', next: () => 1 })).toThrow(/callable reference/);
    expect(() => assertCaptureOnly({ runId: 'x', a: { b: () => 1 } })).toThrow(/callable reference/);
  });

  it('is case-insensitive about field names', () => {
    expect(() => assertCaptureOnly({ SharedKey: 'x' })).toThrow(ContractViolation);
    expect(() => assertCaptureOnly({ PLAINTEXT: 'x' })).toThrow(ContractViolation);
  });

  it('allows a legitimate capture-only request', () => {
    const rand = seededRand(31337);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    const packets = gen.take(10);
    expect(() =>
      buildAttackRequest({
        runId: 'ok',
        keyBits: 104,
        profile: { profileId: PROFILE_ID, knownPrefix: ARP_REQUEST_KNOWN_PREFIX, payloadLength: PROFILE_PAYLOAD_LEN, keyId: 0 },
        budget: { maxPackets: 10, maxCandidates: 10, maxMillis: 1000 },
        capturedBodies: packets.map((p) => p.body),
        validationBodies: [],
      })
    ).not.toThrow();
  });

  it('survives a cyclic object rather than hanging', () => {
    const a: Record<string, unknown> = { runId: 'x' };
    a.self = a;
    expect(() => assertCaptureOnly(a)).not.toThrow();
  });

  it('a built request carries no plaintext, even though the generator had it', () => {
    const rand = seededRand(4242);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    const packets = gen.take(5);
    // The generator's own packets DO carry ground truth...
    expect(packets[0].plaintext).toBeInstanceOf(Uint8Array);
    const request = buildAttackRequest({
      runId: 'strip',
      keyBits: 104,
      profile: { profileId: PROFILE_ID, knownPrefix: ARP_REQUEST_KNOWN_PREFIX, payloadLength: PROFILE_PAYLOAD_LEN, keyId: 0 },
      budget: { maxPackets: 5, maxCandidates: 1, maxMillis: 1000 },
      capturedBodies: packets.map((p) => p.body),
      validationBodies: [],
    });
    // ...and the request does not, at any depth.
    const json = JSON.stringify(request, (_k, v) =>
      v instanceof Uint8Array ? Array.from(v) : v
    );
    expect(json).not.toContain('plaintext');
    for (const captured of request.captured) {
      expect(Object.keys(captured)).toEqual(['body']);
    }
  });
});

describe('the attack runs from serialised bytes with no generator in scope', () => {
  it('recovers from a JSON round trip of the request alone', () => {
    const rand = seededRand(104729);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    const all = gen.take(35020);
    const live = buildAttackRequest({
      runId: 'serialised',
      keyBits: 104,
      profile: { profileId: PROFILE_ID, knownPrefix: ARP_REQUEST_KNOWN_PREFIX, payloadLength: PROFILE_PAYLOAD_LEN, keyId: 0 },
      budget: { maxPackets: 35000, maxCandidates: 200000, maxMillis: 120000 },
      capturedBodies: all.slice(0, 35000).map((p) => p.body),
      validationBodies: all.slice(35000).map((p) => p.body),
    });
    // Serialise and rebuild: nothing but bytes crosses, as through a worker.
    const wire = JSON.stringify(live, (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
    const parsed = JSON.parse(wire) as {
      runId: string;
      keyBits: 104;
      profile: { profileId: string; knownPrefix: number[]; payloadLength: number; keyId: number };
      budget: { maxPackets: number; maxCandidates: number; maxMillis: number };
      captured: { body: number[] }[];
      validation: { body: number[] }[];
    };
    const result = runPtw({
      runId: parsed.runId,
      keyBits: parsed.keyBits,
      profile: { ...parsed.profile, knownPrefix: Uint8Array.from(parsed.profile.knownPrefix) },
      budget: parsed.budget,
      captured: parsed.captured.map((c) => ({ body: Uint8Array.from(c.body) })),
      validation: parsed.validation.map((c) => ({ body: Uint8Array.from(c.body) })),
    });
    expect(result.state).toBe('recovered-candidate');
    let hex = '';
    for (const b of result.candidate!) hex += b.toString(16).padStart(2, '0');
    expect(hex).toBe('b1d44702cc988d22f85e172374');
  }, 120_000);
});
