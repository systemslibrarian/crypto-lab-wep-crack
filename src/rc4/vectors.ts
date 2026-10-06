/**
 * RFC 6229 test vectors for RC4 — expected outputs, held immutable.
 *
 * Source: J. Strombergson and S. Josefsson, "Test Vectors for the Stream Cipher
 * RC4", RFC 6229, May 2011 [R1]. Transcribed from the authoritative text at
 * https://www.rfc-editor.org/rfc/rfc6229.txt (fetched 2026-10-06), not from a
 * secondary listing and NOT computed by this lab's own RC4 — a vector a lab
 * generates for itself tests nothing.
 *
 * Two independent key families appear in the RFC and both are used here, so a
 * vector failure cannot be a quirk of one family: section 2's keys ascend
 * (0x0102030405...) and section 3's are the nested 0x...3222772a set.
 *
 * THE OFFSETS ARE POSITIONS IN ONE CONTINUOUS KEYSTREAM, not cipher blocks —
 * RC4 is a stream cipher and has none. Reading offset 240 means generating 240
 * bytes and continuing, which is why `rc4.test.ts` drives each row through a
 * single `Rc4Keystream`: a generator that silently re-keyed per chunk would
 * match at offset 0 and fail at every later offset.
 */

export interface Rc4Vector {
  /** Where in RFC 6229 this row appears. */
  readonly source: string;
  readonly keyBits: number;
  readonly keyHex: string;
  /** Stream offset in bytes -> the 16 expected bytes beginning there. */
  readonly at: ReadonlyArray<{ readonly offset: number; readonly hex: string }>;
}

export const RFC6229_VECTORS: readonly Rc4Vector[] = [
  {
    source: 'RFC 6229 section 2, 40-bit key',
    keyBits: 40,
    keyHex: '0102030405',
    at: [
      { offset: 0, hex: 'b2396305f03dc027ccc3524a0a1118a8' },
      { offset: 16, hex: '6982944f18fc82d589c403a47a0d0919' },
      { offset: 240, hex: '28cb1132c96ce286421dcaadb8b69eae' },
      { offset: 256, hex: '1cfcf62b03eddb641d77dfcf7f8d8c93' },
    ],
  },
  {
    source: 'RFC 6229 section 2, 64-bit key',
    keyBits: 64,
    keyHex: '0102030405060708',
    at: [
      { offset: 0, hex: '97ab8a1bf0afb96132f2f67258da15a8' },
      { offset: 16, hex: '8263efdb45c4a18684ef87e6b19e5b09' },
      { offset: 240, hex: '9636ebc9841926f4f7d1f362bddf6e18' },
      { offset: 256, hex: 'd0a990ff2c05fef5b90373c9ff4b870a' },
    ],
  },
  {
    source: 'RFC 6229 section 2, 128-bit key',
    keyBits: 128,
    keyHex: '0102030405060708090a0b0c0d0e0f10',
    at: [
      { offset: 0, hex: '9ac7cc9a609d1ef7b2932899cde41b97' },
      { offset: 16, hex: '5248c4959014126a6e8a84f11d1a9e1c' },
      { offset: 240, hex: '065902e4b620f6cc36c8589f66432f2b' },
      { offset: 256, hex: 'd39d566bc6bce3010768151549f3873f' },
    ],
  },
  {
    source: 'RFC 6229 section 3, 40-bit key',
    keyBits: 40,
    keyHex: '833222772a',
    at: [
      { offset: 0, hex: '80ad97bdc973df8a2e879e92a497efda' },
      { offset: 16, hex: '20f060c2f2e5126501d3d4fea10d5fc0' },
      { offset: 240, hex: 'faa148e99046181fec6b2085f3b20ed9' },
      { offset: 256, hex: 'f0daf5bab3d596839857846f73fbfe5a' },
    ],
  },
  {
    source: 'RFC 6229 section 3, 64-bit key',
    keyBits: 64,
    keyHex: '641910833222772a',
    at: [
      { offset: 0, hex: 'bbf609de9413172d07660cb680716926' },
      { offset: 16, hex: '46101a6dab43115d6c522b4fe93604a9' },
      { offset: 240, hex: 'cbe1fff21c96f3eef61e8fe0542cbdf0' },
      { offset: 256, hex: '347938bffa4009c512cfb4034b0dd1a7' },
    ],
  },
  {
    source: 'RFC 6229 section 3, 128-bit key',
    keyBits: 128,
    keyHex: 'ebb46227c6cc8b37641910833222772a',
    at: [
      { offset: 0, hex: '720c94b63edf44e131d950ca211a5a30' },
      { offset: 16, hex: 'c366fdeacf9ca80436be7c358424d20b' },
      { offset: 240, hex: 'b3394a40aabf75cba42282ef25a0059f' },
      { offset: 256, hex: '4847d81da4942dbc249defc48c922b9f' },
    ],
  },
];

/** Total expected-byte rows across every vector. Reported on panel 1. */
export const RFC6229_ROW_COUNT = RFC6229_VECTORS.reduce((n, v) => n + v.at.length, 0);
