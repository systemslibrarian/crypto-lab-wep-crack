/**
 * Panel 4 — change a message and repair the ICV.
 *
 * This panel is the lab's NEGATIVE-CLAIM EVIDENCE FIXTURE (master template
 * 4.1d). It reaches a state where every check the page performs reports
 * success and the named security property is violated anyway:
 *
 *   - the genuine WEP receiver's ICV check PASSES on the altered packet;
 *   - the message the receiver recovered is DIFFERENT from the one sent;
 *   - and the negative claim is on screen beside both.
 *
 * The verdict therefore reads ICV VALID - AND FORGED, styled as an alarm,
 * because the cryptographic check succeeding is the bad news.
 *
 * The unrepaired tamper is a separate CONTROL, shown first. It establishes that
 * the verifier can reject; it is not the evidence fixture, and the page says so.
 */

import { bytesToPrintable, equalBytes, randomBytes, textToBytes, toHex } from '../wep/bytes';
import { forge, singleBitMask, targetedMask, xorMaskAt } from '../wep/forge';
import { wepEncrypt, wepReceive } from '../wep/wep';
import { WEP_CLEAR_PREFIX_LEN, WEP_ICV_LEN } from '../wep/types';
import { byteBlock, card, clear, details, el, field, note, verdict } from './dom';

/** The sentence this lab is required to state and to prove. */
export const NEGATIVE_CLAIM =
  'A valid WEP integrity check does not establish that a message is authentic or unmodified.';

const ORIGINAL_TEXT = 'transfer 100 to account 0001';
/** The deterministic control tamper: one bit, fixed, so a test can name it. */
const TAMPER_BYTE = 9;
const TAMPER_BIT = 0;

export function renderPanel4(host: HTMLElement): void {
  clear(host);

  let sharedKey = randomBytes(13);
  let iv = randomBytes(3);
  const msgInput = el('textarea', { id: 'forge-msg', rows: '2', spellcheck: 'false' }) as HTMLTextAreaElement;
  msgInput.value = ORIGINAL_TEXT;
  const assumedInput = el('input', { type: 'text', id: 'forge-assumed', spellcheck: 'false' }) as HTMLInputElement;
  assumedInput.value = '100';
  const desiredInput = el('input', { type: 'text', id: 'forge-desired', spellcheck: 'false' }) as HTMLInputElement;
  desiredInput.value = '999';
  const offsetInput = el('input', { type: 'number', id: 'forge-offset', value: '9', min: '0' }) as HTMLInputElement;

  const btnNewSession = el('button', { class: 'btn', type: 'button', text: 'New key + IV' });
  const out = el('div', { id: 'forge-out' });

  function render(): void {
    clear(out);
    const payload = textToBytes(msgInput.value);
    if (payload.length === 0) {
      out.append(note('neutral', [el('p', { text: 'Type a message to protect.' })]));
      return;
    }
    const body = wepEncrypt(payload, iv, sharedKey);
    const sent = wepReceive(body, sharedKey);

    // ── The control: tamper with NO repair ──────────────────────────────
    const controlMask = singleBitMask(payload.length, Math.min(TAMPER_BYTE, payload.length - 1), TAMPER_BIT);
    const controlForgery = forge(body, controlMask);
    const controlReceived = wepReceive(controlForgery.bodyWithoutRepair, sharedKey);

    // ── The fixture: the same kind of change WITH the repair ────────────
    let mask: Uint8Array;
    let maskError: string | null = null;
    const offset = Math.max(0, Number(offsetInput.value) || 0);
    try {
      const assumed = textToBytes(assumedInput.value);
      const desired = textToBytes(desiredInput.value);
      mask =
        assumed.length > 0 && assumed.length === desired.length
          ? targetedMask(payload.length, offset, assumed, desired)
          : xorMaskAt(payload.length, Math.min(offset, payload.length - 1), new Uint8Array([0x01]));
      if (assumed.length !== desired.length) {
        maskError =
          `The replacement has to be the same length as what it replaces ` +
          `(${assumed.length} vs ${desired.length} bytes) — the CRC identity is affine ` +
          `at a FIXED length, so panel 4 is same-length only. Falling back to a one-bit flip.`;
      }
    } catch (e) {
      mask = singleBitMask(payload.length, 0, 0);
      maskError = e instanceof Error ? e.message : String(e);
    }
    const forgery = forge(body, mask);
    const forged = wepReceive(forgery.body, sharedKey);
    const changed = !equalBytes(forged.payload, payload);

    out.append(
      el('h4', { text: 'What went out' }),
      byteBlock('ORIGINAL PROTECTED BODY', body, [
        { from: 0, to: WEP_CLEAR_PREFIX_LEN, cls: 'b-clear' },
        { from: body.length - WEP_ICV_LEN, to: body.length, cls: 'b-icv' },
      ]),
      el('div', {}, [
        verdict(sent.icvValid ? 'pass' : 'fail', sent.icvValid ? 'ICV CHECK PASSED' : 'ICV CHECK FAILED', {
          'data-claim': 'forge-original',
        }),
      ]),
      el('p', { class: 'hint', id: 'forge-original-text', text: `Receiver read: “${bytesToPrintable(sent.payload)}”` }),

      // ── Control ─────────────────────────────────────────────────────
      el('h3', { text: 'Control: change a bit and leave the ICV alone' }),
      el('p', {
        class: 'hint',
        text:
          `Flipping bit ${TAMPER_BIT} of payload byte ${Math.min(TAMPER_BYTE, payload.length - 1)} ` +
          `and sending the ICV untouched. The receiver recomputes CRC-32 over what it ` +
          `decrypted, gets a different answer, and rejects.`,
      }),
      el('div', { id: 'forge-control-verdict' }, [
        verdict(controlReceived.icvValid ? 'alarm' : 'fail', controlReceived.icvValid ? 'UNEXPECTEDLY ACCEPTED' : 'ICV CHECK FAILED — REJECTED', {
          'data-claim': 'forge-control',
        }),
      ]),
      note('neutral', [
        el('p', {
          text:
            'This is a control, not the result. All it shows is that the verifier works ' +
            'and really can say no. Keep it in mind for the next section, where the same ' +
            'verifier says yes to a message that was also changed.',
        }),
      ])
    );

    if (maskError) {
      out.append(note('bad', [el('p', { text: maskError })]));
    }

    out.append(
      // ── The fixture ──────────────────────────────────────────────────
      el('h3', { text: 'Now repair the ICV without the key' }),
      el('p', {
        text:
          'CRC-32 with a fixed initial register and final XOR is affine at a fixed ' +
          'length, so the change your modification makes to the check value depends on ' +
          'the modification ALONE. Not on the message, and not on the key.',
      }),
      el('div', { class: 'bytes' }, [
        el('span', { text: 'CRC32(P XOR D) XOR CRC32(P)  =  CRC32(D) XOR CRC32(zeros(n))' }),
      ]),
      el('div', { class: 'controls' }, [
        field('Bytes you ASSUME are there', assumedInput),
        field('What to put instead', desiredInput),
        field('At payload offset', offsetInput),
      ]),
      byteBlock('XOR MASK D  (same length as the payload)', mask, [
        { from: offset, to: offset + Math.max(1, textToBytes(desiredInput.value).length), cls: 'b-changed' },
      ]),
      el('p', {
        class: 'hint',
        id: 'forge-delta',
        text:
          `Correction term: CRC32(D) XOR CRC32(zeros(${mask.length})) = ` +
          `0x${forgery.icvDelta.toString(16).padStart(8, '0')}, serialised little-endian as ` +
          `${toHex(forgery.icvDeltaBytes)}. XOR that into the encrypted ICV and the keystream ` +
          `cancels out of the correction too.`,
      }),
      byteBlock('FORGED PROTECTED BODY', forgery.body, [
        { from: 0, to: WEP_CLEAR_PREFIX_LEN, cls: 'b-clear' },
        { from: WEP_CLEAR_PREFIX_LEN + offset, to: WEP_CLEAR_PREFIX_LEN + offset + Math.max(1, textToBytes(desiredInput.value).length), cls: 'b-changed' },
        { from: forgery.body.length - WEP_ICV_LEN, to: forgery.body.length, cls: 'b-icv' },
      ]),

      el('h4', { text: 'Through the same receiver' }),
      el('div', { class: 'counts' }, [
        el('dl', {}, [
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'ICV carried in the forged packet' }),
            el('dd', { id: 'forge-icv-received', text: `0x${forged.icvReceived.toString(16).padStart(8, '0')}` }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'ICV the receiver computed' }),
            el('dd', { id: 'forge-icv-computed', text: `0x${forged.icvComputed.toString(16).padStart(8, '0')}` }),
          ]),
        ]),
      ]),
      el('div', { id: 'forge-verdict' }, [
        forged.icvValid && changed
          ? verdict('alarm', 'ICV VALID — AND FORGED', { 'data-claim': 'forge-fixture' })
          : forged.icvValid
            ? verdict('pass', 'ICV VALID — MESSAGE UNCHANGED', { 'data-claim': 'forge-fixture' })
            : verdict('fail', 'ICV CHECK FAILED', { 'data-claim': 'forge-fixture' }),
      ]),
      el('p', { class: 'hint' }, [
        el('span', { id: 'forge-sent-text', text: `Sent:     “${bytesToPrintable(payload)}”` }),
        el('br', {}),
        el('span', { id: 'forge-received-text', text: `Received: “${bytesToPrintable(forged.payload)}”` }),
      ]),
      el('div', { id: 'forge-changed' }, [
        verdict(changed ? 'alarm' : 'neutral', changed ? 'RECEIVED MESSAGE DIFFERS FROM THE ONE SENT' : 'RECEIVED MESSAGE IS UNCHANGED', {
          'data-claim': 'forge-changed',
        }),
      ]),

      // The negative claim, visible IN this state, not behind a disclosure.
      el('p', { class: 'negative-claim', id: 'negative-claim', 'data-claim': 'negative-claim', text: NEGATIVE_CLAIM }),
      note('neutral', [
        el('p', {
          text:
            'Read "the receiver accepted it" narrowly: it means the modelled WEP ' +
            'integrity check accepted it. It does not mean every higher-layer ' +
            'application or network policy would — a forged ARP request still has to ' +
            'make sense to whatever reads it next.',
        }),
      ])
    );

    // The honest half: a wrong assumption is accepted too.
    const assumed = textToBytes(assumedInput.value);
    if (assumed.length > 0 && offset + assumed.length <= payload.length) {
      const actuallyThere = payload.subarray(offset, offset + assumed.length);
      const guessedRight = equalBytes(assumed, actuallyThere);
      out.append(
        note(guessedRight ? 'neutral' : 'alarm', [
          el('p', {
            id: 'forge-assumption',
            text: guessedRight
              ? `Your assumption about offset ${offset} happened to be right, so the ` +
                `change landed where you aimed it. That is a property of your guess, ` +
                `not of the attack.`
              : `Your assumption about offset ${offset} was WRONG — the bytes there are ` +
                `“${bytesToPrintable(actuallyThere)}”, not “${bytesToPrintable(assumed)}”. ` +
                `The forged packet was accepted anyway. The ICV check cannot tell the ` +
                `difference, which is precisely the point: acceptance says nothing about ` +
                `whether the attacker aimed correctly, or at all.`,
          }),
        ])
      );
    }
  }

  btnNewSession.addEventListener('click', () => {
    sharedKey = randomBytes(13);
    iv = randomBytes(3);
    render();
  });
  for (const control of [msgInput, assumedInput, desiredInput, offsetInput]) {
    control.addEventListener('input', render);
  }

  host.append(
    el('h2', { text: 'Change a message the receiver will still accept' }),
    el('p', {
      text:
        'WEP checks integrity with a CRC-32 — an error-detecting code with no key, built ' +
        'to catch line noise. Encrypting it does not give it a key. Because the cipher is ' +
        'a stream cipher and the CRC is linear, an attacker who cannot read the message ' +
        'can still change it and fix up the check value to match.',
    }),
    card([el('div', { class: 'controls' }, [btnNewSession]), field('Message to protect', msgInput), out]),
    details('The algebra, in full', [
      el('p', {
        text:
          'The conventional initialised and finalised CRC-32 is affine at a fixed length: ' +
          'CRC32(P XOR D) XOR CRC32(P) = CRC32(D) XOR CRC32(zeros(n)). That zeros(n) term ' +
          'is what cancels the fixed initialisation and finalisation offset, and it is not ' +
          'optional — a bare CRC32(D) is the WRONG correction for this CRC convention and ' +
          'the receiver rejects it. One of this lab’s mutation checks makes exactly ' +
          'that substitution to prove the test catches it.',
      }),
      el('p', {
        text:
          'Then, because RC4 is a stream cipher, XORing D into the ciphertext XORs D into ' +
          'the plaintext the receiver recovers; and XORing LE32 of the correction into the ' +
          'encrypted ICV corrects the ICV the receiver recomputes. The keystream cancels ' +
          'in both places, so no key is needed anywhere.',
      }),
      el('p', {
        text:
          'Modifications here are same-length only, because the identity holds at a fixed ' +
          'length. A length change is a different correction term and this panel refuses it.',
      }),
      el('p', {}, [
        document.createTextNode('WEP message modification was first analysed in Borisov, Goldberg and Wagner, '),
        el('a', {
          href: 'https://people.eecs.berkeley.edu/~daw/research/wireless.html',
          target: '_blank',
          rel: 'noopener noreferrer',
          text: 'Intercepting Mobile Communications: The Insecurity of 802.11',
        }),
        document.createTextNode(' (MobiCom 2001).'),
      ]),
      el('p', {}, [
        document.createTextNode('The fix is not a better checksum bolted on. It is authenticated encryption — a MAC over the ciphertext, with its own key. '),
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-aes-modes/', target: '_blank', rel: 'noopener noreferrer', text: 'AES Modes' }),
        document.createTextNode(' works through which modes give you that and which do not; note that not every AES mode provides integrity either. '),
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-padding-oracle/', target: '_blank', rel: 'noopener noreferrer', text: 'Padding Oracle' }),
        document.createTextNode(' is another case of a protocol’s use of cryptography failing rather than its cipher.'),
      ]),
    ])
  );

  render();
}
