/**
 * Independently sourced WEP protected-body fixtures.
 *
 * The brief (section 9) forbids computing a fixture's expected ciphertext with
 * this lab's own encryptor: a round trip alone conceals matching encoder and
 * decoder mistakes. So every expected byte below comes from OUTSIDE this repo.
 *
 * PROVENANCE, and why it is airtight:
 *
 * 1. THE KEYSTREAM IS PUBLISHED. A WEP per-packet key is `IV || sharedKey`, so
 *    with IV = 01 02 03 the 40-bit profile's RC4 key is
 *    0x0102030405060708 and the 104-bit profile's is
 *    0x0102030405060708090a0b0c0d0e0f10 — which are, byte for byte, RFC 6229
 *    section 2's 64-bit and 128-bit test keys [R1]. The RFC therefore publishes
 *    these two profiles' keystreams outright. The bytes used here are its
 *    offset-0 and offset-16 rows, transcribed from
 *    https://www.rfc-editor.org/rfc/rfc6229.txt (fetched 2026-10-06).
 *
 * 2. THE ICV COMES FROM AN INDEPENDENT IMPLEMENTATION. 0x846b6f88 is the output
 *    of CPython 3's `zlib.crc32(b'WEP protected body test.')` — the zlib
 *    reflected IEEE CRC-32, a named external implementation, run on
 *    2026-10-06. It is pinned as a literal here rather than computed, so this
 *    lab's `crc32()` is being CHECKED against it rather than consulted.
 *
 * 3. THE SERIALISATION IS THE REFERENCE'S. The field order, the Key ID in the
 *    upper two bits, the IV-prepended RC4 key and the little-endian ICV are all
 *    as Linux `net/mac80211/wep.c` [R4] writes them, read at master on
 *    2026-10-06.
 *
 * So `wep.test.ts` asserting `wepEncrypt(...) === EXPECTED_BODY` is a real
 * external agreement check: every byte on the right-hand side was produced by
 * the RFC and by zlib, and none of it by `src/wep/wep.ts`.
 */

/** RFC 6229 section 2, 64-bit key 0x0102030405060708 — bytes 0..31. */
export const RFC6229_KS_IV010203_KEY40 =
  '97ab8a1bf0afb96132f2f67258da15a8' + '8263efdb45c4a18684ef87e6b19e5b09';

/** RFC 6229 section 2, 128-bit key 0x0102030405060708090a0b0c0d0e0f10 — bytes 0..31. */
export const RFC6229_KS_IV010203_KEY104 =
  '9ac7cc9a609d1ef7b2932899cde41b97' + '5248c4959014126a6e8a84f11d1a9e1c';

export interface BodyFixture {
  readonly label: string;
  readonly provenance: string;
  readonly ivHex: string;
  readonly keyId: number;
  readonly sharedKeyHex: string;
  readonly payloadText: string;
  /** From CPython `zlib.crc32`, not from this lab. */
  readonly icvFromZlib: number;
  /** The whole expected protected body, derived from (1) and (2) above. */
  readonly expectedBodyHex: string;
}

export const BODY_FIXTURES: readonly BodyFixture[] = [
  {
    label: '40-bit profile, IV 01:02:03, Key ID 0',
    provenance:
      'ciphertext = RFC 6229 section 2 64-bit keystream XOR (payload || LE32(zlib.crc32(payload)))',
    ivHex: '010203',
    keyId: 0,
    sharedKeyHex: '0405060708',
    payloadText: 'WEP protected body test.',
    icvFromZlib: 0x846b6f88,
    expectedBodyHex:
      '01020300' + 'c0eeda3b80ddd615579182173cfa77c7e61acfaf20b7d5a80c80ec62',
  },
  {
    label: '104-bit profile, IV 01:02:03, Key ID 0',
    provenance:
      'ciphertext = RFC 6229 section 2 128-bit keystream XOR (payload || LE32(zlib.crc32(payload)))',
    ivHex: '010203',
    keyId: 0,
    sharedKeyHex: '0405060708090a0b0c0d0e0f10',
    payloadText: 'WEP protected body test.',
    icvFromZlib: 0x846b6f88,
    expectedBodyHex:
      '01020300' + 'cd829cba10ef7183d7f05cfca9c479f83631e4e1f5676644e6e5ef75',
  },
];
