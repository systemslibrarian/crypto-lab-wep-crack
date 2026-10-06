import { describe, expect, it } from 'vitest';
import { bytesToPrintable, equalBytes, toHex } from './bytes';
import {
  ARP_REQUEST_KNOWN_PREFIX,
  buildArpRequestPayload,
  findIvCollision,
  IV_SPACE,
  LLC_SNAP_LEN,
  PROFILE_PAYLOAD_LEN,
  seededRand,
  TrafficGenerator,
} from './traffic';
import { parseBody, wepEncrypt, wepReceive } from './wep';

describe('the stage-1 traffic profile [R3 section 5]', () => {
  it('begins with the published LLC/SNAP and ARP-request bytes', () => {
    // LLC/SNAP: AA AA 03 00 00 00 08 06. ARP request header: 00 01 08 00 06 04 00 01.
    expect(toHex(ARP_REQUEST_KNOWN_PREFIX)).toBe('aaaa030000000806' + '0001080006040001');
    expect(ARP_REQUEST_KNOWN_PREFIX).toHaveLength(16);
    expect(toHex(ARP_REQUEST_KNOWN_PREFIX.subarray(0, LLC_SNAP_LEN))).toBe('aaaa030000000806');
  });

  it('ends the ARP header with opcode 01 — a request, not a reply', () => {
    // A reply's last byte would be 02. Panel 5's profile is requests only.
    expect(ARP_REQUEST_KNOWN_PREFIX[15]).toBe(0x01);
  });

  it('produces a 36-byte payload: 8 LLC/SNAP plus a 28-byte ARP request', () => {
    expect(PROFILE_PAYLOAD_LEN).toBe(36);
    const payload = buildArpRequestPayload(0, seededRand(1));
    expect(payload).toHaveLength(36);
  });

  it('every payload really carries the known prefix', () => {
    const rand = seededRand(2);
    for (let seq = 0; seq < 50; seq++) {
      const payload = buildArpRequestPayload(seq, rand);
      expect(equalBytes(payload.subarray(0, 16), ARP_REQUEST_KNOWN_PREFIX), `seq ${seq}`).toBe(true);
    }
  });

  it('keeps the address fields well formed and varying', () => {
    const rand = seededRand(3);
    const a = buildArpRequestPayload(0, rand);
    const b = buildArpRequestPayload(1, rand);
    // Sender/target IPs are in 192.168.1.0/24 and the two packets differ.
    expect([...a.subarray(22, 26)].slice(0, 3)).toEqual([192, 168, 1]);
    expect([...a.subarray(32, 36)].slice(0, 3)).toEqual([192, 168, 1]);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('leaves the target MAC zero, as an ARP request does', () => {
    const payload = buildArpRequestPayload(0, seededRand(4));
    expect([...payload.subarray(26, 32)]).toEqual([0, 0, 0, 0, 0, 0]);
  });
});

describe('the generator', () => {
  it('produces packets the genuine receiver accepts', () => {
    const rand = seededRand(5);
    const sharedKey = rand(13);
    const gen = new TrafficGenerator({ sharedKey, rand });
    for (const packet of gen.take(25)) {
      const r = wepReceive(packet.body, sharedKey);
      expect(r.icvValid).toBe(true);
      expect(toHex(r.payload)).toBe(toHex(packet.plaintext));
    }
  });

  it('draws a fresh 3-byte IV per packet and reports its key size', () => {
    const rand = seededRand(6);
    const gen40 = new TrafficGenerator({ sharedKey: rand(5), rand });
    expect(gen40.keyBits).toBe(40);
    const gen104 = new TrafficGenerator({ sharedKey: rand(13), rand });
    expect(gen104.keyBits).toBe(104);
    for (const p of gen104.take(10)) expect(p.iv).toHaveLength(3);
  });

  it('counts what it produced', () => {
    const rand = seededRand(7);
    const gen = new TrafficGenerator({ sharedKey: rand(13), rand });
    expect(gen.count).toBe(0);
    gen.take(12);
    expect(gen.count).toBe(12);
    gen.next();
    expect(gen.count).toBe(13);
  });

  it('rejects an invalid Key ID at construction, not at the first packet', () => {
    const rand = seededRand(8);
    expect(() => new TrafficGenerator({ sharedKey: rand(13), keyId: 7, rand })).toThrow();
  });

  it('writes the Key ID into the upper two bits of the clear prefix', () => {
    const rand = seededRand(9);
    const gen = new TrafficGenerator({ sharedKey: rand(13), keyId: 1, rand });
    expect(parseBody(gen.next().body).keyId).toBe(1);
  });
});

describe('the IV policy is uniform with replacement, and never rigged', () => {
  it('uses the full 24-bit space', () => {
    expect(IV_SPACE).toBe(16777216);
  });

  it('spreads IVs across the whole space rather than a shrunken one', () => {
    // A shrunken space is one of the things the brief forbids, so it is
    // measured: 4000 draws from 2^24 should show a wide spread in every byte.
    const rand = seededRand(10);
    const gen = new TrafficGenerator({ sharedKey: rand(13), rand });
    const seenPerByte = [new Set<number>(), new Set<number>(), new Set<number>()];
    for (const p of gen.take(4000)) {
      for (let b = 0; b < 3; b++) seenPerByte[b].add(p.iv[b]);
    }
    for (let b = 0; b < 3; b++) {
      expect(seenPerByte[b].size, `IV byte ${b}`).toBeGreaterThan(200);
    }
  });

  it('collides at roughly the birthday rate, neither planted nor suppressed', () => {
    // Expected duplicate pairs among n draws from N is about n^2/(2N).
    // At n = 20000, N = 2^24 that is about 11.9. A planted collision would
    // show up far earlier; a shrunken space far more often.
    const rand = seededRand(12345);
    const gen = new TrafficGenerator({ sharedKey: rand(13), rand });
    const packets = gen.take(20000);
    const seen = new Map<string, number>();
    let duplicates = 0;
    for (const p of packets) {
      const hex = toHex(p.iv);
      if (seen.has(hex)) duplicates++;
      seen.set(hex, p.index);
    }
    const expected = (20000 * 20000) / (2 * IV_SPACE);
    expect(duplicates).toBeGreaterThan(expected / 4);
    expect(duplicates).toBeLessThan(expected * 4);
  });

  it('reports no collision when there is none, rather than inventing one', () => {
    const rand = seededRand(13);
    const gen = new TrafficGenerator({ sharedKey: rand(13), rand });
    // Ten packets will essentially never collide in a 2^24 space.
    expect(findIvCollision(gen.take(10))).toBeNull();
  });

  it('finds a real collision and names both positions', () => {
    const iv = new Uint8Array([1, 2, 3]);
    const found = findIvCollision([
      { index: 0, iv: new Uint8Array([9, 9, 9]) },
      { index: 1, iv },
      { index: 2, iv: new Uint8Array([8, 8, 8]) },
      { index: 3, iv },
    ]);
    expect(found).toEqual({ first: 1, second: 3, ivHex: '010203' });
  });
});

describe('a collision really does expose the plaintext XOR', () => {
  it('C1 XOR C2 equals P1 XOR P2 over the aligned payload bytes', () => {
    const rand = seededRand(14);
    const sharedKey = rand(13);
    // Force the same IV on two packets by driving the construction directly:
    // this is a FIXTURE of the relationship, not a change to the generator.
    const gen = new TrafficGenerator({ sharedKey, rand });
    const p1 = gen.next();
    const p2 = gen.next();
    const sameIv = p1.iv;
    const b2 = wepEncrypt(p2.plaintext, sameIv, sharedKey);
    const c1 = parseBody(p1.body).encryptedPayload;
    const c2 = parseBody(b2).encryptedPayload;
    for (let i = 0; i < c1.length; i++) {
      expect(c1[i] ^ c2[i], `byte ${i}`).toBe(p1.plaintext[i] ^ p2.plaintext[i]);
    }
    expect(bytesToPrintable(p1.plaintext)).not.toBe('');
  });
});
