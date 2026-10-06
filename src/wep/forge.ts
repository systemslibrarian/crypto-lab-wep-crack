/**
 * Message modification with ICV repair — panel 4, and the lab's negative claim.
 *
 * The attacker has a captured protected body and NOTHING ELSE: no key, no
 * plaintext. It wants the receiver to accept a body whose decrypted payload
 * differs from the original.
 *
 * Two facts combine:
 *   1. RC4 is a stream cipher, so XORing a mask D into the CIPHERTEXT XORs the
 *      same D into the plaintext the receiver recovers.
 *   2. The initialised/finalised CRC-32 is AFFINE at a fixed length, so the
 *      change the modification makes to the ICV is a function of D alone:
 *        CRC32(P XOR D) XOR CRC32(P) = CRC32(D) XOR CRC32(zeros(n)) = icvDelta(D)
 *      and the encrypted ICV can be corrected by XORing LE32(icvDelta(D)) into
 *      it — again without the key, because the keystream cancels.
 *
 * So:
 *   forgedEncryptedPayload = encryptedPayload XOR D
 *   forgedEncryptedICV     = encryptedICV XOR LE32(icvDelta(D))
 *
 * SAME-LENGTH MODIFICATIONS ONLY. The identity is affine at a FIXED length; a
 * mask of a different length is a different correction term, so panel 4 keeps
 * the payload length fixed and says so.
 *
 * Nothing in this file takes a key or a plaintext as an argument. That is not a
 * stylistic choice — it is the claim the panel makes, and the signature is where
 * it is enforced.
 *
 * Original analysis of WEP message modification: Borisov, Goldberg and Wagner,
 * "Intercepting Mobile Communications: The Insecurity of 802.11", MobiCom 2001
 * [R7].
 */

import { concatBytes, xor } from './bytes';
import { icvDelta, le32 } from './crc32';
import { parseBody } from './wep';
import { WEP_CLEAR_PREFIX_LEN } from './types';

export class ForgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForgeError';
  }
}

export interface Forgery {
  /** The modified protected body, ready for the genuine receiver. */
  readonly body: Uint8Array;
  /** The same modification with NO ICV repair — the control. */
  readonly bodyWithoutRepair: Uint8Array;
  /** The mask applied, for display. */
  readonly mask: Uint8Array;
  /** The correction term, as a 32-bit value and as its 4 serialised bytes. */
  readonly icvDelta: number;
  readonly icvDeltaBytes: Uint8Array;
}

/**
 * A same-length mask that places arbitrary bytes at `offset`.
 *
 * This is the attacker's primitive: it needs no key and no plaintext. The
 * receiver's recovered payload changes by exactly these bytes, wherever they
 * land, whether or not the attacker knows what was there before.
 */
export function xorMaskAt(payloadLength: number, offset: number, maskBytes: Uint8Array): Uint8Array {
  if (!Number.isInteger(offset) || offset < 0) throw new ForgeError(`offset must be >= 0; got ${offset}`);
  if (offset + maskBytes.length > payloadLength) {
    throw new ForgeError(
      `a ${maskBytes.length}-byte change at offset ${offset} runs past the ` +
        `${payloadLength}-byte payload - panel 4 is same-length only`
    );
  }
  const mask = new Uint8Array(payloadLength);
  mask.set(maskBytes, offset);
  return mask;
}

/**
 * A mask aimed at turning ASSUMED plaintext bytes into chosen ones.
 *
 * `assumed` is the attacker's ASSUMPTION about what those bytes are - not
 * knowledge, and not read from the generator. This is how real WEP message
 * modification worked: a predictable header, a guessed field. If the assumption
 * is wrong the mask still applies and the receiver still accepts the repaired
 * packet; it simply lands on different bytes than the attacker intended, which
 * `forge.test.ts` asserts directly.
 *
 * `desired` and `assumed` must be the same length, because the identity is
 * affine only at a fixed length.
 */
export function targetedMask(
  payloadLength: number,
  offset: number,
  assumed: Uint8Array,
  desired: Uint8Array
): Uint8Array {
  if (assumed.length !== desired.length) {
    throw new ForgeError(
      `a targeted change is same-length only: assumed ${assumed.length} bytes, ` +
        `desired ${desired.length}`
    );
  }
  return xorMaskAt(payloadLength, offset, xor(assumed, desired));
}

/** A mask that flips one bit, for the deterministic tamper control. */
export function singleBitMask(payloadLength: number, byteIndex: number, bit: number): Uint8Array {
  if (byteIndex < 0 || byteIndex >= payloadLength) {
    throw new ForgeError(`byteIndex must be 0..${payloadLength - 1}; got ${byteIndex}`);
  }
  if (bit < 0 || bit > 7) throw new ForgeError(`bit must be 0..7; got ${bit}`);
  const mask = new Uint8Array(payloadLength);
  mask[byteIndex] = 1 << bit;
  return mask;
}

/**
 * Apply `mask` to a captured body, with and without the ICV repair.
 *
 * `body` is a captured protected body. `mask` is the same length as its
 * payload. No key, no plaintext — see the file header.
 */
export function forge(body: Uint8Array, mask: Uint8Array): Forgery {
  const parsed = parseBody(body);
  if (mask.length !== parsed.encryptedPayload.length) {
    throw new ForgeError(
      `the mask must match the payload length exactly (${parsed.encryptedPayload.length} bytes); ` +
        `got ${mask.length}. The CRC difference identity is affine at a FIXED length.`
    );
  }
  const clear = body.subarray(0, WEP_CLEAR_PREFIX_LEN);
  const modifiedPayload = xor(parsed.encryptedPayload, mask);

  const delta = icvDelta(mask);
  const deltaBytes = le32(delta);
  const repairedIcv = xor(parsed.encryptedIcv, deltaBytes);

  return {
    body: concatBytes(clear, modifiedPayload, repairedIcv),
    bodyWithoutRepair: concatBytes(clear, modifiedPayload, parsed.encryptedIcv),
    mask,
    icvDelta: delta,
    icvDeltaBytes: deltaBytes,
  };
}
