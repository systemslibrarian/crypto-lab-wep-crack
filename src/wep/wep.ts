/**
 * The WEP construction: protected-body build, parse, and the ONE receiver.
 *
 * What is modelled (brief section 3): the WEP PROTECTED BODY — the clear
 * IV/Key ID field and the encrypted payload/ICV. What is NOT modelled: the
 * 802.11 MAC header, the outer frame check sequence, radio metadata,
 * retransmissions, and physical capture. This is not a complete on-air frame
 * and it is not a capture-file format.
 *
 * Construction, per IEEE 802.11-1997 WEP as implemented in Linux
 * `net/mac80211/wep.c` [R4] (read at master, 2026-10-06; `ieee80211_wep_encrypt`
 * and `ieee80211_wep_encrypt_data`, which carry the comment
 * `data = RC4(data | CRC32(data))`):
 *
 *   protected body = IV(3) || keyIdByte(1) || RC4_{IV||sharedKey}( payload || LE32(CRC32(payload)) )
 *
 * Four details that are easy to get wrong, each checked by a test:
 *   - the RC4 per-packet key is IV PREPENDED to the shared key, so 8 or 16
 *     bytes (`memcpy(rc4key, iv, 3); memcpy(rc4key + 3, key, keylen)`);
 *   - the Key ID byte is TRANSMITTED but is NOT part of the RC4 key;
 *   - the Key ID sits in the UPPER TWO BITS of its byte (`*iv++ = keyidx << 6`);
 *   - the ICV is serialised LITTLE-ENDIAN (`cpu_to_le32(~crc32_le(~0, ...))`).
 *
 * THE 5/13-BYTE SHARED-KEY RESTRICTION IS ENFORCED HERE, and only here. The
 * generic RC4 core in `src/rc4/rc4.ts` keeps its own wider contract, because
 * the published RC4 vectors need 5-, 8- and 16-byte keys.
 */

import { Rc4Keystream, rc4Apply } from '../rc4/rc4';
import { concatBytes, equalBytes, xor } from './bytes';
import { crc32, le32, readLe32 } from './crc32';
import {
  type ParsedBody,
  type ReceiveResult,
  WEP_CLEAR_PREFIX_LEN,
  WEP_ICV_LEN,
  WEP_IV_LEN,
  WEP_MIN_BODY_LEN,
  WEP_SHARED_KEY_BYTES,
  type WepKeyBits,
} from './types';

export class WepFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WepFormatError';
  }
}

/** The supported shared-key sizes, as a sentence the UI can print. */
export const SUPPORTED_KEY_PROFILE = '5 bytes (40-bit) or 13 bytes (104-bit)';

/**
 * The WEP wrapper's shared-key rule.
 *
 * Rejected at the wrapper with an explanation naming the supported profile
 * (brief section 11). Note what is NOT said: nothing here constrains RC4.
 */
export function assertSharedKey(sharedKey: Uint8Array): WepKeyBits {
  if (sharedKey.length === 5) return 40;
  if (sharedKey.length === 13) return 104;
  throw new WepFormatError(
    `WEP takes a shared key of ${SUPPORTED_KEY_PROFILE}; got ${sharedKey.length} bytes. ` +
      `RC4 itself accepts this length — the restriction is WEP's.`
  );
}

export function sharedKeyBytesFor(bits: WepKeyBits): number {
  return WEP_SHARED_KEY_BYTES[bits];
}

export function assertIv(iv: Uint8Array): void {
  if (iv.length !== WEP_IV_LEN) {
    throw new WepFormatError(`a WEP IV is ${WEP_IV_LEN} bytes; got ${iv.length}`);
  }
}

/** The Key ID occupies the upper two bits; stage 1 uses zero reserved bits. */
export function keyIdByte(keyId: number): number {
  if (!Number.isInteger(keyId) || keyId < 0 || keyId > 3) {
    throw new WepFormatError(`a WEP Key ID is 0..3; got ${keyId}`);
  }
  return (keyId << 6) & 0xff;
}

/**
 * The RC4 per-packet key: IV prepended to the shared key.
 *
 * 8 bytes for the 40-bit profile, 16 for the 104-bit one. The Key ID byte is
 * deliberately absent — it is transmitted, not keyed.
 */
export function perPacketKey(iv: Uint8Array, sharedKey: Uint8Array): Uint8Array {
  assertIv(iv);
  assertSharedKey(sharedKey);
  return concatBytes(iv, sharedKey);
}

/** The ICV: CRC-32 of the PLAINTEXT payload, serialised little-endian. */
export function icvFor(payload: Uint8Array): Uint8Array {
  return le32(crc32(payload));
}

/** Build a protected body. */
export function wepEncrypt(
  payload: Uint8Array,
  iv: Uint8Array,
  sharedKey: Uint8Array,
  keyId = 0
): Uint8Array {
  const rc4key = perPacketKey(iv, sharedKey);
  const plain = concatBytes(payload, icvFor(payload));
  return concatBytes(iv, new Uint8Array([keyIdByte(keyId)]), rc4Apply(rc4key, plain));
}

/**
 * Parse a protected body. Strict, and it rejects BEFORE slicing or decrypting
 * (brief section 11).
 */
export function parseBody(body: Uint8Array): ParsedBody {
  if (body.length < WEP_MIN_BODY_LEN) {
    throw new WepFormatError(
      `a protected body is at least ${WEP_MIN_BODY_LEN} bytes ` +
        `(${WEP_CLEAR_PREFIX_LEN}-byte clear prefix + ${WEP_ICV_LEN}-byte encrypted ICV); ` +
        `got ${body.length}`
    );
  }
  const keyIdByteValue = body[WEP_IV_LEN];
  const encrypted = body.subarray(WEP_CLEAR_PREFIX_LEN);
  return {
    iv: body.slice(0, WEP_IV_LEN),
    keyIdByte: keyIdByteValue,
    keyId: (keyIdByteValue >>> 6) & 0x03,
    reservedBits: keyIdByteValue & 0x3f,
    encrypted,
    encryptedPayload: encrypted.subarray(0, encrypted.length - WEP_ICV_LEN),
    encryptedIcv: encrypted.subarray(encrypted.length - WEP_ICV_LEN),
  };
}

/**
 * THE receiver. There is one of these and every packet goes through it —
 * unmodified, forged, or malformed (brief section 8.2).
 *
 * No second permissive path, no forced success, no UI-only validity flag. The
 * forged packet in panel 4 is accepted by exactly this function, which is the
 * only reason its acceptance means anything.
 */
export function wepReceive(body: Uint8Array, sharedKey: Uint8Array): ReceiveResult {
  const parsed = parseBody(body);
  const rc4key = perPacketKey(parsed.iv, sharedKey);
  const plain = rc4Apply(rc4key, parsed.encrypted);
  const payload = plain.subarray(0, plain.length - WEP_ICV_LEN);
  const icvReceived = readLe32(plain, plain.length - WEP_ICV_LEN);
  const icvComputed = crc32(payload);
  return {
    icvValid: icvReceived === icvComputed,
    payload: payload.slice(),
    icvReceived,
    icvComputed,
  };
}

/**
 * The keystream prefix an attacker derives from a captured body and the public
 * expected plaintext prefix: KS = C XOR P_expected.
 *
 * No key and no ground truth involved — just XOR against bytes the traffic
 * profile publishes. This is the attacker's only route to keystream.
 */
export function keystreamPrefixFrom(
  encryptedPayload: Uint8Array,
  expectedPrefix: Uint8Array
): Uint8Array {
  return xor(encryptedPayload.subarray(0, expectedPrefix.length), expectedPrefix);
}

/**
 * Keystream bytes under a candidate per-packet key — for candidate validation.
 * Used by the attacker, which is legitimate: the IV is public and the candidate
 * is the attacker's own guess.
 */
export function keystreamUnder(iv: Uint8Array, candidate: Uint8Array, length: number): Uint8Array {
  return new Rc4Keystream(concatBytes(iv, candidate)).next(length);
}

/** Byte-for-byte key comparison, for the experiment controller only. */
export function sameKey(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}
