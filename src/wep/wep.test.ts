import { describe, expect, it } from 'vitest';
import { keystream } from '../rc4/rc4';
import { bytesToPrintable, concatBytes, fromHex, textToBytes, toHex, xor } from './bytes';
import { crc32, le32 } from './crc32';
import { BODY_FIXTURES, RFC6229_KS_IV010203_KEY104, RFC6229_KS_IV010203_KEY40 } from './fixtures';
import {
  assertSharedKey,
  icvFor,
  keyIdByte,
  keystreamPrefixFrom,
  parseBody,
  perPacketKey,
  WepFormatError,
  wepEncrypt,
  wepReceive,
} from './wep';
import { WEP_MIN_BODY_LEN } from './types';

const KEY40 = fromHex('0405060708');
const KEY104 = fromHex('0405060708090a0b0c0d0e0f10');
const IV = fromHex('010203');

describe('the independently sourced protected-body fixtures', () => {
  for (const f of BODY_FIXTURES) {
    describe(f.label, () => {
      it('is built from a keystream RFC 6229 publishes, not from this lab', () => {
        // The per-packet key really is an RFC 6229 test key, which is what makes
        // the fixture external. Asserted so the claim cannot rot.
        const rc4key = perPacketKey(fromHex(f.ivHex), fromHex(f.sharedKeyHex));
        const published =
          rc4key.length === 8 ? RFC6229_KS_IV010203_KEY40 : RFC6229_KS_IV010203_KEY104;
        expect(toHex(keystream(rc4key, 32))).toBe(published);
      });

      it("agrees with CPython zlib.crc32 on the payload's ICV", () => {
        expect(crc32(textToBytes(f.payloadText))).toBe(f.icvFromZlib);
      });

      it('is reproduced byte for byte by wepEncrypt', () => {
        const body = wepEncrypt(
          textToBytes(f.payloadText),
          fromHex(f.ivHex),
          fromHex(f.sharedKeyHex),
          f.keyId
        );
        expect(toHex(body)).toBe(f.expectedBodyHex);
      });

      it('is accepted by the one receiver, returning the original payload', () => {
        const r = wepReceive(fromHex(f.expectedBodyHex), fromHex(f.sharedKeyHex));
        expect(r.icvValid).toBe(true);
        expect(bytesToPrintable(r.payload)).toBe(f.payloadText);
      });
    });
  }

  it('covers both shared-key sizes', () => {
    expect(BODY_FIXTURES.map((f) => fromHex(f.sharedKeyHex).length).sort((a, b) => a - b)).toEqual([5, 13]);
  });
});

describe('WEP serialisation details [R4]', () => {
  it('prepends the IV to the shared key, giving an 8- or 16-byte RC4 key', () => {
    expect(toHex(perPacketKey(IV, KEY40))).toBe('0102030405060708');
    expect(perPacketKey(IV, KEY40)).toHaveLength(8);
    expect(perPacketKey(IV, KEY104)).toHaveLength(16);
  });

  it('does NOT put the Key ID byte in the RC4 key', () => {
    // Same IV and shared key, different Key ID: the keystream must be identical,
    // so the two bodies differ in exactly the one clear byte.
    const a = wepEncrypt(textToBytes('same payload'), IV, KEY104, 0);
    const b = wepEncrypt(textToBytes('same payload'), IV, KEY104, 2);
    expect(toHex(a.subarray(4))).toBe(toHex(b.subarray(4)));
    expect(a[3]).not.toBe(b[3]);
  });

  it('puts the Key ID in the upper two bits of its byte', () => {
    expect(keyIdByte(0)).toBe(0x00);
    expect(keyIdByte(1)).toBe(0x40);
    expect(keyIdByte(2)).toBe(0x80);
    expect(keyIdByte(3)).toBe(0xc0);
    for (const id of [0, 1, 2, 3]) expect(parseBody(wepEncrypt(textToBytes('x'), IV, KEY104, id)).keyId).toBe(id);
  });

  it('leaves the six reserved bits zero in the stage-1 profile', () => {
    for (const id of [0, 1, 2, 3]) {
      expect(parseBody(wepEncrypt(textToBytes('x'), IV, KEY104, id)).reservedBits).toBe(0);
    }
  });

  it('rejects a Key ID outside 0..3', () => {
    expect(() => keyIdByte(4)).toThrow(WepFormatError);
    expect(() => keyIdByte(-1)).toThrow(WepFormatError);
  });

  it('serialises the ICV little-endian', () => {
    const payload = textToBytes('123456789');
    expect(toHex(icvFor(payload))).toBe('2639f4cb');
    expect(toHex(icvFor(payload))).not.toBe('cbf43926');
  });

  it('computes the ICV over the plaintext payload, not the ciphertext', () => {
    const payload = textToBytes('a payload');
    const body = wepEncrypt(payload, IV, KEY104);
    const parsed = parseBody(body);
    const ks = keystream(perPacketKey(IV, KEY104), parsed.encrypted.length);
    const plain = xor(parsed.encrypted, ks);
    expect(toHex(plain)).toBe(toHex(concatBytes(payload, le32(crc32(payload)))));
  });
});

describe('the shared-key rule lives in the WEP wrapper', () => {
  it('accepts exactly 5 and 13 bytes', () => {
    expect(assertSharedKey(new Uint8Array(5))).toBe(40);
    expect(assertSharedKey(new Uint8Array(13))).toBe(104);
  });

  it('rejects every other length, naming the supported profile', () => {
    for (const len of [0, 1, 4, 6, 8, 12, 14, 16, 32]) {
      expect(() => assertSharedKey(new Uint8Array(len))).toThrow(WepFormatError);
    }
    expect(() => assertSharedKey(new Uint8Array(8))).toThrow(/5 bytes \(40-bit\) or 13 bytes \(104-bit\)/);
  });

  it('says plainly that the restriction is WEP\'s and not RC4\'s', () => {
    expect(() => assertSharedKey(new Uint8Array(8))).toThrow(/the restriction is WEP's/);
  });
});

describe('round trips and strict parsing', () => {
  it('round-trips payloads of many lengths under both key sizes', () => {
    for (const key of [KEY40, KEY104]) {
      for (const len of [0, 1, 4, 16, 36, 100, 255]) {
        const payload = new Uint8Array(len);
        for (let i = 0; i < len; i++) payload[i] = (i * 37 + 11) & 0xff;
        const r = wepReceive(wepEncrypt(payload, IV, key), key);
        expect(r.icvValid, `len ${len}`).toBe(true);
        expect(toHex(r.payload)).toBe(toHex(payload));
      }
    }
  });

  it('a zero-length payload gives the shortest legal body', () => {
    const body = wepEncrypt(new Uint8Array(0), IV, KEY104);
    expect(body).toHaveLength(WEP_MIN_BODY_LEN);
    expect(wepReceive(body, KEY104).icvValid).toBe(true);
  });

  it('rejects a body too short for its clear prefix and encrypted ICV', () => {
    for (const len of [0, 1, 3, 4, 6, 7]) {
      expect(() => parseBody(new Uint8Array(len)), `len ${len}`).toThrow(WepFormatError);
    }
    expect(() => parseBody(new Uint8Array(7))).toThrow(/at least 8 bytes/);
  });

  it('rejects before slicing or decrypting', () => {
    // The guard is in parseBody, which wepReceive calls FIRST, so a short body
    // never reaches RC4.
    expect(() => wepReceive(new Uint8Array(5), KEY104)).toThrow(WepFormatError);
  });

  it('rejects an IV of the wrong length at the wrapper', () => {
    expect(() => wepEncrypt(textToBytes('x'), fromHex('0102'), KEY104)).toThrow(WepFormatError);
    expect(() => wepEncrypt(textToBytes('x'), fromHex('01020304'), KEY104)).toThrow(WepFormatError);
  });

  it('the wrong shared key fails the ICV check rather than throwing', () => {
    const body = wepEncrypt(textToBytes('a payload'), IV, KEY104);
    const wrong = fromHex('0405060708090a0b0c0d0e0f11');
    const r = wepReceive(body, wrong);
    expect(r.icvValid).toBe(false);
    expect(r.icvReceived).not.toBe(r.icvComputed);
  });
});

describe('the attacker-side keystream derivation', () => {
  it('recovers keystream from a captured body and the public expected prefix', () => {
    const prefix = fromHex('aaaa030000000806');
    const payload = concatBytes(prefix, textToBytes('and then some tail bytes'));
    const body = wepEncrypt(payload, IV, KEY104);
    const parsed = parseBody(body);
    const ks = keystreamPrefixFrom(parsed.encryptedPayload, prefix);
    // Independently: the same bytes from the real per-packet key.
    expect(toHex(ks)).toBe(toHex(keystream(perPacketKey(IV, KEY104), prefix.length)));
  });
});
