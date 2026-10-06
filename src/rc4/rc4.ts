/**
 * RC4 — hand-rolled, inspectable, and the teaching subject of this lab.
 *
 * Hand-rolled on purpose (master template §0.1): the point of panel 1 is that a
 * reader can open this file and see the whole cipher. There is no RC4 in
 * WebCrypto and a library would hide the two loops the lab exists to show.
 *
 * THIS IS THE GENERIC RC4 CORE AND IT HAS ITS OWN INPUT CONTRACT: a key of
 * 1..256 bytes, which is what RC4 itself admits and what the RFC 6229 vectors
 * need (5, 8 and 16 bytes among them). The 5/13-byte WEP restriction is NOT a
 * property of RC4 and is enforced one layer up, in `src/wep/wep.ts`. Pushing
 * that rule down here would make the published vectors unrunnable, which is the
 * mistake the brief names in §4.
 *
 * No RC4-drop and no other modification: WEP uses ordinary RC4 from the first
 * keystream byte, and a dropped prefix would change the construction the rest
 * of this lab attacks.
 *
 * Reference: R. Rivest's RC4, as published; test vectors from RFC 6229 [R1].
 */

/** RC4 operates over a 256-byte permutation; every index and sum is mod 256. */
export const N = 256;

/** The RC4 core's own input contract. Not the WEP shared-key rule. */
export const RC4_MIN_KEY_BYTES = 1;
export const RC4_MAX_KEY_BYTES = 256;

export class Rc4KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Rc4KeyError';
  }
}

function assertKey(key: Uint8Array): void {
  if (key.length < RC4_MIN_KEY_BYTES || key.length > RC4_MAX_KEY_BYTES) {
    throw new Rc4KeyError(
      `RC4 takes a key of ${RC4_MIN_KEY_BYTES}-${RC4_MAX_KEY_BYTES} bytes; got ${key.length}. ` +
        `(The 5/13-byte restriction belongs to the WEP wrapper, not to RC4.)`
    );
  }
}

/** One recorded KSA iteration, for the panel-1 animation. */
export interface KsaStep {
  /** The loop counter i for this iteration. */
  readonly i: number;
  /** j before this iteration's update. */
  readonly jBefore: number;
  /** j after `j = j + S[i] + K[i mod len] mod 256`. */
  readonly jAfter: number;
  /** The key byte mixed in at this step, and where it came from. */
  readonly keyByte: number;
  readonly keyIndex: number;
  /** S[i] as read before the swap — the addend, worth seeing separately. */
  readonly sAtI: number;
  /** The permutation AFTER the swap. A copy: the animation must not alias S. */
  readonly s: Uint8Array;
}

/** One recorded PRGA iteration. */
export interface PrgaStep {
  readonly i: number;
  readonly j: number;
  /** S[i] and S[j] after the swap. */
  readonly sAtI: number;
  readonly sAtJ: number;
  /** The output index `S[i] + S[j] mod 256` and the byte read from it. */
  readonly outIndex: number;
  readonly out: number;
  readonly s: Uint8Array;
}

/**
 * The key-scheduling algorithm. Returns the permutation after all 256 rounds.
 *
 * `trace` is optional and costs a 256-byte copy per step, so the UI asks for it
 * and nothing else does.
 */
export function ksa(key: Uint8Array, trace?: KsaStep[]): Uint8Array {
  assertKey(key);
  const s = new Uint8Array(N);
  for (let i = 0; i < N; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < N; i++) {
    const keyIndex = i % key.length;
    const keyByte = key[keyIndex];
    const sAtI = s[i];
    const jBefore = j;
    j = (j + sAtI + keyByte) & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
    if (trace) trace.push({ i, jBefore, jAfter: j, keyByte, keyIndex, sAtI, s: s.slice() });
  }
  return s;
}

/**
 * The KSA stopped after `rounds` iterations, with the running j.
 *
 * This is what the PTW attack needs: `ksaPartial(iv, 3)` is exactly the paper's
 * (S_3, j_3), the state after the three PUBLIC key bytes and before any secret
 * one. Equation 5 of [R3] is written in those terms.
 */
export function ksaPartial(key: Uint8Array, rounds: number): { s: Uint8Array; j: number } {
  assertKey(key);
  if (rounds < 0 || rounds > N) throw new Rc4KeyError(`rounds must be 0..${N}; got ${rounds}`);
  const s = new Uint8Array(N);
  for (let i = 0; i < N; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < rounds; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
  }
  return { s, j };
}

/**
 * A live PRGA, so the keystream can be drawn in chunks without restarting.
 *
 * RFC 6229 lists bytes at offsets 240, 256, 496 and so on, which are positions
 * in ONE continuous stream rather than independent blocks. A generator that
 * re-keyed per chunk would agree with the vector at offset 0 and disagree with
 * every later one, so `src/rc4/rc4.test.ts` reads those offsets through a
 * single `Rc4Keystream` to prove the state carries across calls.
 */
export class Rc4Keystream {
  private readonly s: Uint8Array;
  private i = 0;
  private j = 0;
  /** Bytes emitted so far — the stream offset of the next byte. */
  public offset = 0;

  constructor(key: Uint8Array) {
    this.s = ksa(key);
  }

  /** The next `count` keystream bytes, continuing from wherever we are. */
  next(count: number, trace?: PrgaStep[]): Uint8Array {
    const out = new Uint8Array(count);
    for (let k = 0; k < count; k++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + this.s[this.i]) & 0xff;
      const t = this.s[this.i];
      this.s[this.i] = this.s[this.j];
      this.s[this.j] = t;
      const outIndex = (this.s[this.i] + this.s[this.j]) & 0xff;
      out[k] = this.s[outIndex];
      if (trace) {
        trace.push({
          i: this.i,
          j: this.j,
          sAtI: this.s[this.i],
          sAtJ: this.s[this.j],
          outIndex,
          out: out[k],
          s: this.s.slice(),
        });
      }
      this.offset++;
    }
    return out;
  }

  /** Discard `count` bytes. Used only to reach a vector's offset. */
  skip(count: number): void {
    this.next(count);
  }
}

/** The first `length` keystream bytes under `key`. */
export function keystream(key: Uint8Array, length: number): Uint8Array {
  return new Rc4Keystream(key).next(length);
}

/**
 * RC4 applied to `data`. Encryption and decryption are the same operation,
 * which is the property panel 4's forgery turns against the construction.
 */
export function rc4Apply(key: Uint8Array, data: Uint8Array): Uint8Array {
  const ks = keystream(key, data.length);
  const out = new Uint8Array(data.length);
  for (let k = 0; k < data.length; k++) out[k] = data[k] ^ ks[k];
  return out;
}

/** The inverse permutation of `p`. PTW's equation 5 needs S_3^-1. */
export function invert(p: Uint8Array): Uint8Array {
  const inv = new Uint8Array(N);
  for (let k = 0; k < N; k++) inv[p[k]] = k;
  return inv;
}
