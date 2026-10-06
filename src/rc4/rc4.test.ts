import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../wep/bytes';
import { invert, ksa, ksaPartial, N, Rc4KeyError, Rc4Keystream, rc4Apply } from './rc4';
import { RFC6229_ROW_COUNT, RFC6229_VECTORS } from './vectors';

describe('RC4 against the RFC 6229 published vectors [R1]', () => {
  // One test per vector row, named by its RFC provenance, so a failure says
  // WHICH published row disagreed rather than "RC4 broken".
  for (const v of RFC6229_VECTORS) {
    describe(v.source, () => {
      it(`reproduces all ${v.at.length} expected offsets from one continuous keystream`, () => {
        const key = fromHex(v.keyHex);
        expect(key.length * 8).toBe(v.keyBits);
        // ONE generator for the whole row. The offsets are stream positions, so
        // this also proves the PRGA state carries across calls — a per-chunk
        // re-key matches offset 0 and fails offset 240.
        const stream = new Rc4Keystream(key);
        for (const row of v.at) {
          expect(stream.offset).toBeLessThanOrEqual(row.offset);
          stream.skip(row.offset - stream.offset);
          expect(toHex(stream.next(16)), `offset ${row.offset}`).toBe(row.hex);
        }
      });
    });
  }

  it('covers 24 published expected-byte rows across 6 keys and 3 key sizes', () => {
    expect(RFC6229_ROW_COUNT).toBe(24);
    expect(new Set(RFC6229_VECTORS.map((v) => v.keyBits))).toEqual(new Set([40, 64, 128]));
    // Two independent key families, per the file's own note.
    expect(RFC6229_VECTORS.filter((v) => v.source.includes('section 2'))).toHaveLength(3);
    expect(RFC6229_VECTORS.filter((v) => v.source.includes('section 3'))).toHaveLength(3);
  });

  it('reads offset 256 as a stream position, not a block boundary', () => {
    // Deliberately redundant with the loop above, because this is the specific
    // misreading the vector file warns about: 256 is byte 256 of one stream.
    const v = RFC6229_VECTORS[0];
    const key = fromHex(v.keyHex);
    const flat = new Rc4Keystream(key).next(272);
    expect(toHex(flat.subarray(256, 272))).toBe(v.at[3].hex);
    // And the same bytes are NOT what a fresh keying produces.
    expect(toHex(new Rc4Keystream(key).next(16))).not.toBe(v.at[3].hex);
  });
});

describe('the RC4 core input contract (not the WEP rule)', () => {
  it('accepts every key length the published vectors need', () => {
    for (const len of [5, 8, 16]) {
      expect(() => new Rc4Keystream(new Uint8Array(len).fill(1))).not.toThrow();
    }
  });

  it('accepts the 8- and 16-byte WEP per-packet key lengths', () => {
    for (const len of [8, 16]) {
      expect(() => new Rc4Keystream(new Uint8Array(len).fill(2))).not.toThrow();
    }
  });

  it('accepts a 1-byte and a 256-byte key — RC4 admits both', () => {
    expect(() => new Rc4Keystream(new Uint8Array([7]))).not.toThrow();
    expect(() => new Rc4Keystream(new Uint8Array(256).fill(9))).not.toThrow();
  });

  it('rejects an empty key and an over-long key, by the RC4 contract', () => {
    expect(() => new Rc4Keystream(new Uint8Array(0))).toThrow(Rc4KeyError);
    expect(() => new Rc4Keystream(new Uint8Array(257))).toThrow(Rc4KeyError);
  });

  it('does NOT impose the WEP 5/13-byte shared-key rule', () => {
    // The brief (section 4) names this as a mistake to avoid: pushing WEP's key
    // restriction into the RC4 core makes the published vectors unrunnable.
    for (const len of [1, 2, 3, 4, 6, 7, 11, 20, 32]) {
      expect(() => new Rc4Keystream(new Uint8Array(len).fill(3))).not.toThrow();
    }
  });
});

describe('RC4 internals used by the attack and the animation', () => {
  it('ksa returns a permutation of 0..255', () => {
    const s = ksa(fromHex('0102030405'));
    expect(new Set(s)).toHaveLength(N);
  });

  it('records one trace step per KSA round, each holding its own snapshot', () => {
    const trace: Parameters<typeof ksa>[1] = [];
    ksa(fromHex('cafebabe'), trace);
    expect(trace).toHaveLength(N);
    // Snapshots must be copies: aliasing one array would make the animation
    // show the final permutation at every step.
    expect(trace![0].s).not.toBe(trace![1].s);
    expect(toHex(trace![0].s)).not.toBe(toHex(trace![255].s));
  });

  it("reproduces the PTW paper's own worked KSA example for key CA FE BA BE", () => {
    // [R3] section 3: "if the key CA FE BA BE is used, S_0 is the identity
    // permutation and j_0 = 0. After the first key byte has been processed,
    // j_1 = 202 and S_1[0] = 202, S_1[202] = 0, and S_1[x] = x otherwise."
    const { s, j } = ksaPartial(fromHex('cafebabe'), 1);
    expect(j).toBe(202);
    expect(s[0]).toBe(202);
    expect(s[202]).toBe(0);
    for (let x = 0; x < N; x++) if (x !== 0 && x !== 202) expect(s[x]).toBe(x);
  });

  it('ksaPartial(key, 256) agrees with the full ksa', () => {
    const key = fromHex('0102030405060708');
    expect(toHex(ksaPartial(key, 256).s)).toBe(toHex(ksa(key)));
  });

  it('ksaPartial(key, 0) is the identity permutation with j = 0', () => {
    const { s, j } = ksaPartial(fromHex('aabbcc'), 0);
    expect(j).toBe(0);
    for (let x = 0; x < N; x++) expect(s[x]).toBe(x);
  });

  it('invert really inverts: P[i] = j <=> Pinv[j] = i', () => {
    const s = ksa(fromHex('deadbeef'));
    const inv = invert(s);
    for (let i = 0; i < N; i++) expect(inv[s[i]]).toBe(i);
  });

  it('rc4Apply is its own inverse (the property panel 4 exploits)', () => {
    const key = fromHex('0102030405');
    const msg = fromHex('00112233445566778899aabbccddeeff');
    expect(toHex(rc4Apply(key, rc4Apply(key, msg)))).toBe(toHex(msg));
  });

  it('starts at the first keystream byte — no RC4-drop', () => {
    // A dropped prefix would change the construction this lab attacks, so it is
    // pinned by a published vector rather than left to a comment.
    const v = RFC6229_VECTORS[0];
    expect(toHex(rc4Apply(fromHex(v.keyHex), new Uint8Array(16)))).toBe(v.at[0].hex);
  });
});
