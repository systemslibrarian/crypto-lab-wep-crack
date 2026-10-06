import { describe, expect, it } from 'vitest';
import { fromHex, textToBytes, toHex, xor } from './bytes';
import {
  CRC32_POLY_NORMAL,
  CRC32_POLY_REFLECTED,
  crc32,
  crc32Bitwise,
  icvDelta,
  le32,
  readLe32,
} from './crc32';

describe('CRC-32 published check values [R5]', () => {
  it('CRC32("123456789") = 0xCBF43926', () => {
    expect(crc32(textToBytes('123456789')) >>> 0).toBe(0xcbf43926);
  });

  it('CRC32("") = 0', () => {
    expect(crc32(new Uint8Array(0))).toBe(0);
  });

  it('uses the reflected representation of the IEEE polynomial', () => {
    expect(CRC32_POLY_REFLECTED).toBe(0xedb88320);
    expect(CRC32_POLY_NORMAL).toBe(0x04c11db7);
    // The two really are bit reversals of one another, asserted rather than
    // stated in a comment.
    let rev = 0;
    for (let b = 0; b < 32; b++) if ((CRC32_POLY_NORMAL >>> b) & 1) rev |= 1 << (31 - b);
    expect(rev >>> 0).toBe(CRC32_POLY_REFLECTED);
  });
});

describe('CRC-32 against an independent reference route', () => {
  it('the table-driven and bit-at-a-time routines agree on the check value', () => {
    expect(crc32Bitwise(textToBytes('123456789')) >>> 0).toBe(0xcbf43926);
  });

  it('they agree on 300 pseudorandom inputs of varied length', () => {
    // A fixed LCG, so this is a reproducible fixture rather than a flaky test.
    let x = 0x12345678;
    const nextByte = (): number => {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      return (x >>> 16) & 0xff;
    };
    for (let n = 0; n < 300; n++) {
      const len = n % 71;
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = nextByte();
      expect(crc32(data), `length ${len}`).toBe(crc32Bitwise(data));
    }
  });
});

describe('little-endian ICV serialisation', () => {
  it('serialises the check value low byte first', () => {
    expect(toHex(le32(0xcbf43926))).toBe('2639f4cb');
  });

  it('round-trips through readLe32', () => {
    for (const v of [0, 1, 0xcbf43926, 0xffffffff, 0x80000000]) {
      expect(readLe32(le32(v))).toBe(v >>> 0);
    }
  });

  it('reads a field at an offset', () => {
    expect(readLe32(fromHex('aaaa2639f4cb'), 2)).toBe(0xcbf43926);
  });
});

describe('the affine CRC difference — the forgery identity', () => {
  // CRC32(P XOR D) XOR CRC32(P) = CRC32(D) XOR CRC32(zeros(n)) = icvDelta(D)
  const lengths = [1, 2, 3, 4, 7, 8, 15, 16, 36, 64, 100];

  it('holds across many payload lengths and masks', () => {
    let x = 0xc0ffee11;
    const nextByte = (): number => {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      return (x >>> 16) & 0xff;
    };
    let checked = 0;
    for (const n of lengths) {
      for (let trial = 0; trial < 12; trial++) {
        const p = new Uint8Array(n);
        const d = new Uint8Array(n);
        for (let i = 0; i < n; i++) p[i] = nextByte();
        for (let i = 0; i < n; i++) d[i] = nextByte();
        expect((crc32(xor(p, d)) ^ crc32(p)) >>> 0, `n=${n} trial=${trial}`).toBe(icvDelta(d));
        checked++;
      }
    }
    expect(checked).toBe(lengths.length * 12);
  });

  it('a bare CRC32(D) is NOT the correction term', () => {
    // The brief says so in as many words, and one of the mutations in
    // scripts/mutations.mjs makes exactly this substitution. If the two ever
    // agreed, that mutation would be unkillable.
    const p = textToBytes('a payload of some particular length');
    const d = new Uint8Array(p.length);
    d[3] = 0x40;
    expect(icvDelta(d)).not.toBe(crc32(d));
    expect((crc32(xor(p, d)) ^ crc32(p)) >>> 0).toBe(icvDelta(d));
  });

  it('the zero mask corrects nothing', () => {
    expect(icvDelta(new Uint8Array(36))).toBe(0);
  });

  it('the correction depends only on the mask, never on the payload', () => {
    // This is the attacker's whole advantage, so it is asserted directly: two
    // unrelated payloads of the same length take the SAME correction.
    const d = fromHex('00000000000000ff00000000');
    const p1 = textToBytes('aaaaaaaaaaaa');
    const p2 = textToBytes('zzzzzzzzzzzz');
    expect(p1.length).toBe(d.length);
    expect((crc32(xor(p1, d)) ^ crc32(p1)) >>> 0).toBe((crc32(xor(p2, d)) ^ crc32(p2)) >>> 0);
  });

  it('is affine AT A FIXED LENGTH only — a shorter mask is a different term', () => {
    // Panel 4 is same-length-only for this reason, and the UI says so.
    const d16 = new Uint8Array(16);
    d16[0] = 1;
    const d8 = new Uint8Array(8);
    d8[0] = 1;
    expect(icvDelta(d16)).not.toBe(icvDelta(d8));
  });
});
