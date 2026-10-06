/**
 * The stage-1 traffic profile and the generator. ALL TRAFFIC IS SYNTHETIC.
 *
 * Nothing in this lab accepts bytes from a real network. There is no radio
 * capture, no monitor mode, no injection and no capture-file import, and that
 * is a deliberate scope boundary rather than an unfinished feature (brief
 * section 2). `src/wep/attack/contract.ts` documents the intake seam a future
 * frame parser would use; stage-1 protected bodies are NOT a capture format.
 *
 * THE PROFILE (brief section 5, after [R3] section 5): an LLC/SNAP header
 * followed by an Ethernet/IPv4 ARP request. The PTW paper explains why this is
 * the realistic source of known plaintext — ARP packets are a fixed size, are
 * rarely rate-limited, and their first 16 cleartext bytes are constant:
 *
 *   AA AA 03 00 00 00 08 06   00 01 08 00 06 04 00 01
 *   \---- LLC/SNAP (8) ----/  \----- ARP header (8) -----/
 *
 * Because this exhibit omits MAC headers, the PACKET CLASS IS A PUBLIC,
 * DECLARED PROPERTY of the generated profile. The attacker is told "these are
 * ARP requests under this profile" — it does not identify them from fields the
 * model does not have, and it is never handed the addresses. The remaining
 * address fields are well formed and vary per packet, and they are ground
 * truth: they reach the attacker only inside ciphertext.
 */

import { concatBytes, randomBytes } from './bytes';
import type { GeneratedPacket, WepKeyBits } from './types';
import { keyIdByte, wepEncrypt } from './wep';

/** The 16 predictable cleartext bytes an ARP request begins with. */
export const ARP_REQUEST_KNOWN_PREFIX = new Uint8Array([
  0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
]);

/** The LLC/SNAP prefix is 8 bytes; a full ARP request body is 28. */
export const LLC_SNAP_LEN = 8;
export const ARP_REQUEST_LEN = 28;
export const PROFILE_PAYLOAD_LEN = LLC_SNAP_LEN + ARP_REQUEST_LEN;

/** The public identifier the attacker receives instead of a packet class guess. */
export const PROFILE_ID = 'llc-snap-arp-request-ipv4';

export const PROFILE_DESCRIPTION =
  'LLC/SNAP header followed by an Ethernet/IPv4 ARP request: 36 payload bytes, ' +
  'of which the first 16 are fixed by the profile.';

/**
 * The IV policy, stated because it is a choice and not a law.
 *
 * Independent uniform 24-bit IVs WITH REPLACEMENT, from the browser's
 * cryptographic random source. Random IVs can collide well before the space is
 * exhausted; a single uninterrupted counter can instead traverse its space with
 * no repetition at all before wrapping. A 24-bit field does not by itself
 * oblige an early birthday collision — the POLICY decides that, which is why
 * this one is named on the page.
 *
 * The space is never shrunk and no collision is ever planted. Panel 3 reports
 * NO COLLISION OBSERVED YET for as long as that is the truth.
 */
export const IV_POLICY =
  'independent uniform 24-bit IVs drawn with replacement from crypto.getRandomValues';

export const IV_SPACE = 2 ** 24;

/** Build one profile payload. The address fields vary and are ground truth. */
export function buildArpRequestPayload(seq: number, rand: (n: number) => Uint8Array): Uint8Array {
  const tail = new Uint8Array(PROFILE_PAYLOAD_LEN - ARP_REQUEST_KNOWN_PREFIX.length);
  // Sender MAC (6) then sender IP (4), target MAC (6, zero in a request) then
  // target IP (4). Well formed, varying, and never passed to the attacker.
  const senderMac = rand(6);
  tail.set(senderMac, 0);
  tail.set([192, 168, 1, 1 + (seq % 250)], 6);
  tail.set([0, 0, 0, 0, 0, 0], 10);
  tail.set([192, 168, 1, 1 + ((seq * 7 + 3) % 250)], 16);
  return concatBytes(ARP_REQUEST_KNOWN_PREFIX, tail);
}

export interface GeneratorOptions {
  readonly sharedKey: Uint8Array;
  readonly keyId?: number;
  /** Deterministic byte source — for LABELLED fixtures only. */
  readonly rand?: (n: number) => Uint8Array;
}

/**
 * The traffic generator. Holds the session key; the attacker never sees it.
 *
 * This module is stateful and is therefore BANNED from the attacker's import
 * graph (brief section 5). `attack/isolation.test.ts` checks that at the file
 * level and the worker contract checks it at runtime.
 */
export class TrafficGenerator {
  private readonly sharedKey: Uint8Array;
  private readonly keyIdValue: number;
  private readonly rand: (n: number) => Uint8Array;
  private produced = 0;

  constructor(opts: GeneratorOptions) {
    this.sharedKey = opts.sharedKey;
    this.keyIdValue = opts.keyId ?? 0;
    this.rand = opts.rand ?? randomBytes;
    // Fail fast on a bad key rather than at the first packet.
    keyIdByte(this.keyIdValue);
  }

  get keyBits(): WepKeyBits {
    return this.sharedKey.length === 5 ? 40 : 104;
  }

  get count(): number {
    return this.produced;
  }

  /** One packet under a freshly drawn IV. */
  next(): GeneratedPacket {
    const iv = this.rand(3);
    const plaintext = buildArpRequestPayload(this.produced, this.rand);
    const body = wepEncrypt(plaintext, iv, this.sharedKey, this.keyIdValue);
    const packet: GeneratedPacket = {
      index: this.produced,
      iv,
      keyIdByte: keyIdByte(this.keyIdValue),
      body,
      plaintext,
    };
    this.produced++;
    return packet;
  }

  /** `n` packets. */
  take(n: number): GeneratedPacket[] {
    const out: GeneratedPacket[] = [];
    for (let i = 0; i < n; i++) out.push(this.next());
    return out;
  }
}

/** A labelled deterministic byte source, for reproducible fixtures only. */
export function seededRand(seed: number): (n: number) => Uint8Array {
  let x = seed >>> 0 || 1;
  return (n: number): Uint8Array => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      // xorshift32 — reproducible, and labelled a fixture source wherever used.
      x ^= x << 13;
      x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5;
      x >>>= 0;
      out[i] = (x >>> 8) & 0xff;
    }
    return out;
  };
}

/** The first repeated IV in a packet list, or null. Never planted. */
export function findIvCollision(
  packets: readonly { readonly index: number; readonly iv: Uint8Array }[]
): { readonly first: number; readonly second: number; readonly ivHex: string } | null {
  const seen = new Map<string, number>();
  for (const p of packets) {
    let hex = '';
    for (const b of p.iv) hex += b.toString(16).padStart(2, '0');
    const prior = seen.get(hex);
    if (prior !== undefined) return { first: prior, second: p.index, ivHex: hex };
    seen.set(hex, p.index);
  }
  return null;
}
