/** Byte/hex helpers shared across the lab. No crypto lives here. */

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
  if (clean.length && !/^[0-9a-fA-F]+$/.test(clean)) throw new Error(`not hex: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Spaced hex, for display. */
export function toHexSpaced(bytes: Uint8Array, groupsOf = 1): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += groupsOf) {
    parts.push(toHex(bytes.subarray(i, i + groupsOf)));
  }
  return parts.join(' ');
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * Fresh bytes from the browser's cryptographic random source.
 *
 * Every live key and IV in this lab comes through here (brief §8.1). A
 * deterministic generator appears only in clearly labelled test fixtures.
 */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** UTF-8 text as bytes, and back. */
export function textToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToPrintable(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
  return s;
}
