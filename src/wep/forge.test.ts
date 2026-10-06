import { describe, expect, it } from 'vitest';
import { bytesToPrintable, equalBytes, fromHex, textToBytes, toHex, xor } from './bytes';
import { crc32, icvDelta, le32 } from './crc32';
import { ForgeError, forge, singleBitMask, targetedMask, xorMaskAt } from './forge';
import { parseBody, wepEncrypt, wepReceive } from './wep';

const KEY104 = fromHex('0405060708090a0b0c0d0e0f10');
const IV = fromHex('0a1b2c');
const ORIGINAL = textToBytes('transfer 100 to account 0001');

/** The deterministic tamper used as the §4.1c mutation control. */
const TAMPER_BYTE = 9;
const TAMPER_BIT = 0;

describe('the forgery controls (brief section 9)', () => {
  it('an unmodified packet is accepted', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    expect(wepReceive(body, KEY104).icvValid).toBe(true);
  });

  it('a deterministic one-bit payload change WITHOUT ICV repair is rejected', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const mask = singleBitMask(ORIGINAL.length, TAMPER_BYTE, TAMPER_BIT);
    const r = wepReceive(forge(body, mask).bodyWithoutRepair, KEY104);
    expect(r.icvValid).toBe(false);
    expect(r.icvReceived).not.toBe(r.icvComputed);
  });

  it('that same change WITH the correct repair is accepted AND changes the plaintext', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const mask = singleBitMask(ORIGINAL.length, TAMPER_BYTE, TAMPER_BIT);
    const r = wepReceive(forge(body, mask).body, KEY104);
    expect(r.icvValid).toBe(true);
    // Accepted is not the whole claim: the received message must really differ.
    expect(equalBytes(r.payload, ORIGINAL)).toBe(false);
    expect(toHex(r.payload)).toBe(toHex(xor(ORIGINAL, mask)));
  });
});

describe('the repair term is computed without the key or the plaintext', () => {
  it('forge() is reached with a captured body and a mask, and nothing else', () => {
    // Enforced by the signature; asserted here so a future argument cannot be
    // added quietly. forge.length is its declared arity.
    expect(forge.length).toBe(2);
  });

  it('the correction equals the real ICV change, derived independently', () => {
    const mask = xorMaskAt(ORIGINAL.length, 9, fromHex('ff00aa'));
    const f = forge(wepEncrypt(ORIGINAL, IV, KEY104), mask);
    // Independent re-derivation from the ground-truth plaintext, which the
    // attacker never saw: the real difference between the two CRCs.
    expect(f.icvDelta).toBe((crc32(xor(ORIGINAL, mask)) ^ crc32(ORIGINAL)) >>> 0);
    expect(toHex(f.icvDeltaBytes)).toBe(toHex(le32(f.icvDelta)));
  });

  it('a bare CRC32(D) repair would NOT be accepted', () => {
    // The brief names this substitution; mutation 3 in scripts/mutations.mjs
    // makes it. This test is why that mutation dies.
    const mask = xorMaskAt(ORIGINAL.length, 4, fromHex('5a'));
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const parsed = parseBody(body);
    const wrongRepair = new Uint8Array([
      ...body.subarray(0, 4),
      ...xor(parsed.encryptedPayload, mask),
      ...xor(parsed.encryptedIcv, le32(crc32(mask))),
    ]);
    expect(wepReceive(wrongRepair, KEY104).icvValid).toBe(false);
    // While the correct term is accepted, same mask, same packet.
    expect(wepReceive(forge(body, mask).body, KEY104).icvValid).toBe(true);
  });

  it('a zeroed repair term would NOT be accepted', () => {
    // Mutation 3's other half.
    const mask = xorMaskAt(ORIGINAL.length, 4, fromHex('5a'));
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const parsed = parseBody(body);
    const noRepair = new Uint8Array([
      ...body.subarray(0, 4),
      ...xor(parsed.encryptedPayload, mask),
      ...parsed.encryptedIcv,
    ]);
    expect(wepReceive(noRepair, KEY104).icvValid).toBe(false);
  });
});

describe('forgery succeeds across many masks, offsets and payload lengths', () => {
  it('every repaired packet is accepted and every one changes the message', () => {
    let x = 0xbeef1234;
    const nextByte = (): number => {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      return (x >>> 16) & 0xff;
    };
    let accepted = 0;
    for (const len of [1, 4, 16, 28, 36, 64]) {
      const payload = new Uint8Array(len);
      for (let i = 0; i < len; i++) payload[i] = nextByte();
      const body = wepEncrypt(payload, IV, KEY104);
      for (let trial = 0; trial < 8; trial++) {
        const mask = new Uint8Array(len);
        // At least one non-zero byte, so the message really changes.
        mask[trial % len] = (nextByte() | 1) & 0xff;
        for (let i = 0; i < len; i++) if (nextByte() & 1) mask[i] ^= nextByte();
        const r = wepReceive(forge(body, mask).body, KEY104);
        expect(r.icvValid, `len ${len} trial ${trial}`).toBe(true);
        expect(toHex(r.payload)).toBe(toHex(xor(payload, mask)));
        accepted++;
      }
    }
    expect(accepted).toBe(48);
  });
});

describe('targeted modification uses an ASSUMPTION, never ground truth', () => {
  it('a correct assumption produces the attacker\'s intended text', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const offset = 9;
    const assumed = textToBytes('100');
    const desired = textToBytes('999');
    expect(bytesToPrintable(ORIGINAL.subarray(offset, offset + 3))).toBe('100');
    const r = wepReceive(forge(body, targetedMask(ORIGINAL.length, offset, assumed, desired)).body, KEY104);
    expect(r.icvValid).toBe(true);
    expect(bytesToPrintable(r.payload)).toBe('transfer 999 to account 0001');
  });

  it('a WRONG assumption is still accepted — it just lands elsewhere', () => {
    // The honest half of the lesson: the ICV check cannot tell the difference,
    // so acceptance says nothing about whether the attacker aimed correctly.
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const mask = targetedMask(ORIGINAL.length, 9, textToBytes('XXX'), textToBytes('999'));
    const r = wepReceive(forge(body, mask).body, KEY104);
    expect(r.icvValid).toBe(true);
    expect(bytesToPrintable(r.payload)).not.toBe('transfer 999 to account 0001');
    expect(equalBytes(r.payload, ORIGINAL)).toBe(false);
  });

  it('rejects a different-length targeted change', () => {
    expect(() => targetedMask(ORIGINAL.length, 9, textToBytes('100'), textToBytes('9999'))).toThrow(
      ForgeError
    );
  });
});

describe('same-length only, enforced at the boundary', () => {
  it('rejects a mask that is not the payload length', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    expect(() => forge(body, new Uint8Array(ORIGINAL.length - 1))).toThrow(ForgeError);
    expect(() => forge(body, new Uint8Array(ORIGINAL.length + 1))).toThrow(/affine at a FIXED length/);
  });

  it('rejects a change running past the payload', () => {
    expect(() => xorMaskAt(10, 8, fromHex('aabbcc'))).toThrow(/same-length only/);
  });

  it('rejects a negative offset and an out-of-range bit', () => {
    expect(() => xorMaskAt(10, -1, fromHex('aa'))).toThrow(ForgeError);
    expect(() => singleBitMask(10, 0, 8)).toThrow(ForgeError);
    expect(() => singleBitMask(10, 10, 0)).toThrow(ForgeError);
  });

  it('leaves the clear IV and Key ID prefix untouched', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const f = forge(body, singleBitMask(ORIGINAL.length, 0, 1));
    expect(toHex(f.body.subarray(0, 4))).toBe(toHex(body.subarray(0, 4)));
    expect(f.body).toHaveLength(body.length);
  });

  it('the zero mask is accepted and changes nothing — delta is zero', () => {
    const body = wepEncrypt(ORIGINAL, IV, KEY104);
    const f = forge(body, new Uint8Array(ORIGINAL.length));
    expect(f.icvDelta).toBe(0);
    expect(toHex(f.body)).toBe(toHex(body));
    expect(icvDelta(new Uint8Array(ORIGINAL.length))).toBe(0);
  });
});
