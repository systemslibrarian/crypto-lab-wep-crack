/**
 * Panel 3 — IV collision and keystream reuse.
 *
 * Generates traffic under one key using the DECLARED IV policy and watches for a
 * genuinely repeated IV. Until one happens it says NO COLLISION OBSERVED YET and
 * reports how many packets it has actually seen. The IV space is never shrunk
 * and no collision is ever planted.
 *
 * When a collision does occur, the panel XORs the aligned ciphertext payload
 * bytes to get the XOR of the two plaintexts — keeping the encrypted ICV out of
 * that display, because it is not plaintext. That XOR does not identify either
 * message on its own, so the learner supplies a crib, the panel derives
 * candidate bytes in the other message, and candidates stay marked as
 * assumptions until a separate ground-truth reveal confirms them. Revealed
 * bytes are marked revealed and never counted as attacker recovery.
 */

import {
  bytesToPrintable,
  randomBytes,
  textToBytes,
  toHex,
  toHexSpaced,
  xor,
} from '../wep/bytes';
import {
  buildChatterPayload,
  CHATTER_PROFILE_DESCRIPTION,
  DISCLOSED_CRIBS,
  findIvCollision,
  IV_POLICY,
  IV_SPACE,
  TrafficGenerator,
} from '../wep/traffic';
import type { GeneratedPacket } from '../wep/types';
import { parseBody } from '../wep/wep';
import { byteBlock, card, clear, details, el, field, note, statusRegion, verdict } from './dom';

const BATCH = 2000;
const MAX_PACKETS = 120000;

interface Collision {
  readonly a: GeneratedPacket;
  readonly b: GeneratedPacket;
  readonly ivHex: string;
  readonly observedAfter: number;
}

export function renderPanel3(host: HTMLElement): void {
  clear(host);

  let sharedKey = randomBytes(13);
  let generator = new TrafficGenerator({ sharedKey, payloadFor: buildChatterPayload });
  let packets: GeneratedPacket[] = [];
  let collision: Collision | null = null;
  let revealed = false;

  const status = statusRegion('coll-status');
  const result = el('div', { id: 'coll-result' });
  const cribInput = el('input', { type: 'text', id: 'coll-crib', spellcheck: 'false' }) as HTMLInputElement;
  cribInput.value = DISCLOSED_CRIBS[0];
  const cribPicker = el('select', { id: 'coll-crib-pick' }) as HTMLSelectElement;
  cribPicker.append(el('option', { value: '', text: 'Disclosed openings\u2026' }));
  for (const c of DISCLOSED_CRIBS) cribPicker.append(el('option', { value: c, text: c }));
  const cribOffset = el('input', { type: 'number', id: 'coll-offset', value: '0', min: '0', max: '35' }) as HTMLInputElement;

  const btnGenerate = el('button', { class: 'btn btn-primary', type: 'button', text: `Generate ${BATCH.toLocaleString()} more packets` });
  const btnReset = el('button', { class: 'btn', type: 'button', text: 'New session' });
  const btnReveal = el('button', { class: 'btn btn-danger', type: 'button', text: 'Reveal ground truth' });

  function renderStatus(): void {
    clear(status);
    const expectedPairs = (packets.length * packets.length) / (2 * IV_SPACE);
    status.append(
      el('div', {}, [
        collision
          ? verdict('alarm', 'IV COLLISION OBSERVED', { 'data-claim': 'collision-state' })
          : verdict('neutral', 'NO COLLISION OBSERVED YET', { 'data-claim': 'collision-state' }),
      ]),
      el('div', { class: 'counts' }, [
        el('dl', {}, [
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Packets generated' }),
            el('dd', { id: 'coll-count', text: packets.length.toLocaleString() }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Distinct IVs seen' }),
            el('dd', { id: 'coll-distinct', text: new Set(packets.map((p) => toHex(p.iv))).size.toLocaleString() }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Expected repeats at this count' }),
            el('dd', { text: expectedPairs.toFixed(1) }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'IV space' }),
            el('dd', { text: `2^24 = ${IV_SPACE.toLocaleString()}` }),
          ]),
        ]),
      ])
    );
    if (!collision) {
      status.append(
        el('p', {
          class: 'hint',
          text:
            `That is the honest observation, not a failure. With ${IV_POLICY}, a repeat ` +
            `becomes likely around a few thousand packets — the "expected repeats" figure ` +
            `above is n²/2N, and it is what you should compare the real count against.`,
        })
      );
    }
  }

  function renderCollision(): void {
    clear(result);
    if (!collision) return;
    const { a, b, observedAfter } = collision;
    const ca = parseBody(a.body).encryptedPayload;
    const cb = parseBody(b.body).encryptedPayload;
    // The encrypted ICV is deliberately NOT in this display: it is not plaintext.
    const cipherXor = xor(ca, cb);
    const plainXor = xor(a.plaintext, b.plaintext);

    result.append(
      el('h4', { text: 'The two packets that shared an IV' }),
      el('div', { class: 'counts' }, [
        el('dl', {}, [
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Repeated IV' }),
            el('dd', { id: 'coll-iv', text: toHexSpaced(a.iv) }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Packet positions' }),
            el('dd', { id: 'coll-positions', text: `#${a.index.toLocaleString()} and #${b.index.toLocaleString()}` }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'Observed after' }),
            el('dd', { text: `${observedAfter.toLocaleString()} packets` }),
          ]),
        ]),
      ]),
      el('h4', { text: 'XOR the two ciphertexts and the keystream cancels' }),
      el('p', {
        class: 'hint',
        text:
          'Same IV and same shared key means the same RC4 key, which means the same ' +
          'keystream S. C1 = P1 XOR S and C2 = P2 XOR S, so C1 XOR C2 = P1 XOR P2. The ' +
          'key never enters that calculation, and neither does any secret.',
      }),
      byteBlock('C1 XOR C2   (payload bytes only — the encrypted ICV is not plaintext)', cipherXor),
      note('neutral', [
        el('p', {
          text:
            'This on its own identifies neither message. It is a relationship between ' +
            'them. To get actual bytes you have to assume something about one side.',
        }),
      ])
    );

    // The crib. An ASSUMPTION, labelled as one.
    let crib: Uint8Array;
    try {
      crib = /^[0-9a-fA-F\s]+$/.test(cribInput.value) && cribInput.value.replace(/\s/g, '').length % 2 === 0
        ? Uint8Array.from(cribInput.value.replace(/\s/g, '').match(/../g)!.map((h) => parseInt(h, 16)))
        : textToBytes(cribInput.value);
    } catch {
      crib = textToBytes(cribInput.value);
    }
    const offset = Math.max(0, Math.min(Number(cribOffset.value) || 0, cipherXor.length - 1));
    const span = Math.min(crib.length, cipherXor.length - offset);
    const derived = xor(cipherXor.subarray(offset, offset + span), crib.subarray(0, span));

    result.append(
      el('h4', { text: 'Drag a crib across it' }),
      el('p', {
        class: 'hint',
        text:
          'Assume you know some bytes of ONE message at some offset. XOR them into the ' +
          'relationship above and you get the corresponding bytes of the OTHER message. ' +
          'Whether that assumption is right is a separate question, and the panel does ' +
          'not pretend to answer it.',
      }),
      el('div', { class: 'controls' }, [
        field('Pick a disclosed opening', cribPicker),
        field('Assumed bytes in packet 1 (hex or text)', cribInput),
        field('At payload offset', cribOffset),
      ]),
      el('p', {
        class: 'hint',
        text:
          'The openings this profile can use are disclosed above \u2014 a protocol\u2019s fixed ' +
          'phrases usually are public. Which one a given packet carries is NOT disclosed, so ' +
          'a pick can be wrong, and when it is the panel says so rather than quietly ' +
          'correcting you.',
      }),
      byteBlock(`ASSUMED BYTES IN #${a.index} AT OFFSET ${offset}`, crib.subarray(0, span)),
      el('div', {}, [
        verdict('neutral', 'CANDIDATE BYTES — UNVERIFIED', { 'data-claim': 'crib-state' }),
      ]),
      byteBlock(`CANDIDATE BYTES IN #${b.index} AT OFFSET ${offset}`, derived),
      el('p', {
        class: 'hint',
        id: 'coll-candidate-text',
        text: `As text: “${bytesToPrintable(derived)}”`,
      }),
      note('neutral', [
        el('p', {
          text:
            'These are candidates, not recovered bytes. They are exactly as correct as ' +
            'the assumption that produced them. Nothing behind this interface looked at ' +
            'the generator’s plaintext to make them.',
        }),
      ])
    );

    // The separate ground-truth reveal, marked as revealed.
    if (revealed) {
      const trueSpan = b.plaintext.subarray(offset, offset + span);
      const correct = toHex(trueSpan) === toHex(derived);
      result.append(
        el('h4', { text: 'Ground truth (revealed, not recovered)' }),
        el('div', {}, [
          verdict(correct ? 'pass' : 'fail', correct ? 'YOUR CANDIDATE WAS RIGHT' : 'YOUR CANDIDATE WAS WRONG', {
            'data-claim': 'crib-check',
          }),
        ]),
        byteBlock(`REVEALED TRUE BYTES IN #${b.index}`, trueSpan),
        byteBlock('REVEALED P1 XOR P2, FOR COMPARISON', plainXor),
        note('alarm', [
          el('p', {
            text:
              'This came from the experiment controller, not from the attack. It is ' +
              'marked revealed because it is: an attacker on a real network would have ' +
              'no such button, and nothing shown here counts as recovery.',
          }),
        ])
      );
    } else {
      result.append(
        el('p', { class: 'hint' }, [
          document.createTextNode('You can check your candidate against the generator’s real plaintext. '),
          document.createTextNode('That is a reveal, not an attack — it will be labelled as one.'),
        ]),
        btnReveal
      );
    }
  }

  function grow(): void {
    const target = Math.min(packets.length + BATCH, MAX_PACKETS);
    while (packets.length < target) packets.push(generator.next());
    if (!collision) {
      const found = findIvCollision(packets);
      if (found) {
        collision = {
          a: packets[found.first],
          b: packets[found.second],
          ivHex: found.ivHex,
          observedAfter: packets.length,
        };
      }
    }
    btnGenerate.disabled = packets.length >= MAX_PACKETS;
    renderStatus();
    renderCollision();
  }

  btnGenerate.addEventListener('click', grow);
  btnReveal.addEventListener('click', () => {
    revealed = true;
    renderCollision();
  });
  btnReset.addEventListener('click', () => {
    sharedKey = randomBytes(13);
    generator = new TrafficGenerator({ sharedKey, payloadFor: buildChatterPayload });
    packets = [];
    collision = null;
    revealed = false;
    btnGenerate.disabled = false;
    renderStatus();
    renderCollision();
  });
  for (const control of [cribInput, cribOffset]) control.addEventListener('input', renderCollision);
  cribPicker.addEventListener('change', () => {
    if (!cribPicker.value) return;
    cribInput.value = cribPicker.value;
    renderCollision();
  });

  host.append(
    el('h2', { text: 'The same IV twice' }),
    el('p', {
      text:
        'WEP’s IV is 24 bits and travels in the clear. Reuse one under the same shared ' +
        'key and you reuse the whole RC4 keystream — and two messages encrypted with the ' +
        'same keystream leak their relationship to anyone who can XOR.',
    }),
    note('neutral', [
      el('p', {
        text:
          `Traffic for this panel: ${CHATTER_PROFILE_DESCRIPTION} ` +
          `IV policy for this session: ${IV_POLICY}. Stated because it is a choice, not a ` +
          `law. Random IVs can repeat long before the space is exhausted; a single ` +
          `uninterrupted counter could instead cross its whole space without repeating. ` +
          `A 24-bit field does not by itself oblige an early collision — the policy decides.`,
      }),
    ]),
    card([
      el('div', { class: 'controls' }, [btnGenerate, btnReset]),
      el('p', {
        class: 'hint',
        text:
          'Nothing here is rigged: the IV space is the full 2^24, the draws come from the ' +
          'browser’s cryptographic random source, and no collision is inserted. If ' +
          'none has happened yet, the panel says so.',
      }),
      status,
      result,
    ]),
    details('Why this is the same lesson as a two-time pad', [
      el('p', {}, [
        document.createTextNode(
          'Any stream cipher has this property — the construction barely matters. '
        ),
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-otp-vault/', target: '_blank', rel: 'noopener noreferrer', text: 'OTP Vault' }),
        document.createTextNode(
          ' works the reasoning through on a two-time pad, where the keystream is a stand-in rather than a real cipher. '
        ),
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-chacha20-stream/', target: '_blank', rel: 'noopener noreferrer', text: 'ChaCha20 Stream' }),
        document.createTextNode(
          ' does it with a modern stream cipher and a reused nonce. And '
        ),
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-nonce-guard/', target: '_blank', rel: 'noopener noreferrer', text: 'Nonce Guard' }),
        document.createTextNode(
          ' shows AES-GCM nonce reuse breaking confidentiality AND authentication together, by recovering the GHASH authentication key — so this is not only ever a plaintext problem.'
        ),
      ]),
      el('p', {
        text:
          'What makes WEP worse than any of those is not the cipher. It is that the IV is ' +
          'only 24 bits wide, so the collision is not an operator mistake you can avoid — ' +
          'it is a scheduled event.',
      }),
    ])
  );

  renderStatus();
  renderCollision();
}
