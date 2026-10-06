/** Shared shapes for the WEP construction and the attack intake. */

/** The two shared-key sizes WEP defines. Named by their marketing bit counts. */
export type WepKeyBits = 40 | 104;

export const WEP_IV_LEN = 3;
/** The clear prefix is the 3-byte IV plus one Key ID/reserved byte. */
export const WEP_KEYID_LEN = 1;
export const WEP_CLEAR_PREFIX_LEN = WEP_IV_LEN + WEP_KEYID_LEN;
export const WEP_ICV_LEN = 4;
/** Shortest legal protected body: prefix + encrypted ICV, zero-length payload. */
export const WEP_MIN_BODY_LEN = WEP_CLEAR_PREFIX_LEN + WEP_ICV_LEN;

export const WEP_SHARED_KEY_BYTES: Record<WepKeyBits, number> = { 40: 5, 104: 13 };

/** A parsed WEP protected body. Nothing here is secret. */
export interface ParsedBody {
  readonly iv: Uint8Array;
  readonly keyIdByte: number;
  /** The Key ID, from the upper two bits of its byte. */
  readonly keyId: number;
  /** The lower six reserved bits, which stage 1 requires to be zero. */
  readonly reservedBits: number;
  /** Still encrypted: RC4(payload || ICV). */
  readonly encrypted: Uint8Array;
  /** Still encrypted: just the payload part. */
  readonly encryptedPayload: Uint8Array;
  /** Still encrypted: just the 4 ICV bytes. */
  readonly encryptedIcv: Uint8Array;
}

/** What the receiver reports. There is exactly one of these code paths. */
export interface ReceiveResult {
  /** Did the genuine WEP ICV check pass? */
  readonly icvValid: boolean;
  /** The decrypted payload. Present whether or not the ICV checked out. */
  readonly payload: Uint8Array;
  /** The ICV carried in the packet, and the one the receiver computed. */
  readonly icvReceived: number;
  readonly icvComputed: number;
}

/**
 * One generated packet, as the GENERATOR sees it — ground truth included.
 *
 * This type never crosses the worker boundary. `CapturedPacket` is what the
 * attacker gets, and it is a strict subset: see `attack/contract.ts`.
 */
export interface GeneratedPacket {
  readonly index: number;
  readonly iv: Uint8Array;
  readonly keyIdByte: number;
  readonly body: Uint8Array;
  /** Ground truth. The attacker must never receive this. */
  readonly plaintext: Uint8Array;
}
