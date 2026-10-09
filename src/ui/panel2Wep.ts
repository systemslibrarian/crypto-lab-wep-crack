/**
 * Panel 2 — wrap it in WEP.
 *
 * Shows how the IV, the shared key, the plaintext, the CRC and the serialised
 * protected body relate, then steps the receiver's GENUINE verification. Both
 * shared-key sizes work here; the RC4 key length is labelled separately,
 * because they are different quantities and conflating them is the mistake.
 */

import { fromHex, randomBytes, textToBytes, toHex, toHexSpaced } from '../wep/bytes';
import { crc32 } from '../wep/crc32';
import {
  WEP_CLEAR_PREFIX_LEN,
  WEP_ICV_LEN,
  WEP_IV_LEN,
  type WepKeyBits,
} from '../wep/types';
import {
  SUPPORTED_KEY_PROFILE,
  icvFor,
  parseBody,
  perPacketKey,
  sharedKeyBytesFor,
  wepEncrypt,
  wepReceive,
} from '../wep/wep';
import { byteBlock, card, clear, details, el, field, note, statusRegion, verdict } from './dom';

export function renderPanel2(host: HTMLElement): void {
  clear(host);

  const keySizeSelect = el('select', { id: 'wep-keysize' }) as HTMLSelectElement;
  keySizeSelect.append(
    el('option', { value: '104', text: '104-bit (13-byte shared key)' }),
    el('option', { value: '40', text: '40-bit (5-byte shared key)' })
  );
  const keyInput = el('input', { type: 'text', id: 'wep-key', spellcheck: 'false', maxlength: '26' }) as HTMLInputElement;
  const ivInput = el('input', { type: 'text', id: 'wep-iv', spellcheck: 'false', maxlength: '6' }) as HTMLInputElement;
  const keyIdSelect = el('select', { id: 'wep-keyid' }) as HTMLSelectElement;
  for (const id of [0, 1, 2, 3]) keyIdSelect.append(el('option', { value: String(id), text: `Key ID ${id}` }));
  const msgInput = el('textarea', { id: 'wep-msg', rows: '2', spellcheck: 'false' }) as HTMLTextAreaElement;
  msgInput.value = 'meet me at the usual place';

  const newKeyBtn = el('button', { class: 'btn', type: 'button', text: 'New key + IV' });
  const out = el('div', { id: 'wep-out' });
  const inputError = statusRegion('wep-input-error');
  keyInput.setAttribute('aria-describedby', 'wep-input-error');
  ivInput.setAttribute('aria-describedby', 'wep-input-error');

  function regenerate(): void {
    const bits = Number(keySizeSelect.value) as WepKeyBits;
    keyInput.value = toHex(randomBytes(sharedKeyBytesFor(bits)));
    keyInput.maxLength = sharedKeyBytesFor(bits) * 2;
    ivInput.value = toHex(randomBytes(WEP_IV_LEN));
  }

  function render(): void {
    clear(out);
    clear(inputError);
    keyInput.setAttribute('aria-invalid', 'false');
    ivInput.setAttribute('aria-invalid', 'false');
    const bits = Number(keySizeSelect.value) as WepKeyBits;
    let sharedKey: Uint8Array;
    let iv: Uint8Array;
    try {
      sharedKey = fromHex(keyInput.value.trim());
    } catch {
      keyInput.setAttribute('aria-invalid', 'true');
      inputError.append(note('bad', [el('p', { text: 'Use complete hex bytes for the shared key, for example 0405060708.' })]));
      return;
    }
    try {
      iv = fromHex(ivInput.value.trim());
    } catch {
      ivInput.setAttribute('aria-invalid', 'true');
      inputError.append(note('bad', [el('p', { text: 'Use exactly three complete hex bytes for the IV, for example 010203.' })]));
      return;
    }

    // The WEP wrapper's rule, enforced where it belongs and explained here.
    const expected = sharedKeyBytesFor(bits);
    if (sharedKey.length !== expected) {
      keyInput.setAttribute('aria-invalid', 'true');
      inputError.append(
        note('bad', [
          verdict('fail', 'REJECTED BY THE WEP WRAPPER', { 'data-claim': 'wrapper-reject' }),
          el('p', {
            text:
              `WEP takes a shared key of ${SUPPORTED_KEY_PROFILE}. This one is ` +
              `${sharedKey.length} bytes, so the wrapper refuses it. RC4 itself would ` +
              `accept this length quite happily — the restriction is WEP’s, not the cipher’s.`,
          }),
        ])
      );
      return;
    }
    if (iv.length !== WEP_IV_LEN) {
      ivInput.setAttribute('aria-invalid', 'true');
      inputError.append(note('bad', [el('p', { text: `A WEP IV is exactly ${WEP_IV_LEN} bytes (6 hex characters).` })]));
      return;
    }
    keyInput.setAttribute('aria-invalid', 'false');
    ivInput.setAttribute('aria-invalid', 'false');

    const keyId = Number(keyIdSelect.value);
    const payload = textToBytes(msgInput.value);
    const rc4key = perPacketKey(iv, sharedKey);
    const icv = icvFor(payload);
    const body = wepEncrypt(payload, iv, sharedKey, keyId);
    const parsed = parseBody(body);
    const received = wepReceive(body, sharedKey);

    out.append(
      el('h4', { text: '1 — the per-packet key' }),
      el('p', {
        class: 'hint',
        text:
          `The 3-byte IV is PREPENDED to the shared key, giving a ${rc4key.length}-byte ` +
          `(${rc4key.length * 8}-bit) RC4 key. Note the two numbers: a ${bits}-bit WEP ` +
          `shared key makes a ${rc4key.length * 8}-bit RC4 key. The Key ID byte is ` +
          `transmitted but is NOT part of the key.`,
      }),
      byteBlock('RC4 PER-PACKET KEY  =  IV || SHARED KEY', rc4key, [
        { from: 0, to: WEP_IV_LEN, cls: 'b-clear' },
      ]),

      el('h4', { text: '2 — the integrity check value' }),
      el('p', {
        class: 'hint',
        text:
          `CRC-32 of the PLAINTEXT payload, serialised little-endian. CRC-32 is an ` +
          `error-detecting code: it was designed to catch accidental corruption, and it ` +
          `has no key. Remember that for panel 4.`,
      }),
      byteBlock(
        `ICV  =  LE32(CRC32(payload))  =  LE32(0x${crc32(payload).toString(16).padStart(8, '0')})`,
        icv
      ),

      el('h4', { text: '3 — encrypt payload and ICV together' }),
      byteBlock('PLAINTEXT PAYLOAD || ICV', new Uint8Array([...payload, ...icv]), [
        { from: payload.length, to: payload.length + WEP_ICV_LEN, cls: 'b-icv' },
      ]),
      byteBlock(
        'PROTECTED BODY  =  IV || keyIdByte || RC4(payload || ICV)',
        body,
        [
          { from: 0, to: WEP_IV_LEN, cls: 'b-clear' },
          { from: WEP_IV_LEN, to: WEP_CLEAR_PREFIX_LEN, cls: 'b-known' },
          { from: body.length - WEP_ICV_LEN, to: body.length, cls: 'b-icv' },
        ]
      ),
      el('div', { class: 'legend' }, [
        el('span', { class: 'b-clear', text: '■ IV (sent in clear)' }),
        el('span', { class: 'b-known', text: '■ Key ID byte (in clear)' }),
        el('span', { class: 'b-icv', text: '■ encrypted ICV' }),
      ]),

      el('h4', { text: '4 — what a listener can read without the key' }),
      note('neutral', [
        el('p', {
          text:
            `The IV is public by design — the receiver needs it to rebuild the same RC4 ` +
            `key. So anyone watching gets IV ${toHexSpaced(parsed.iv)} and Key ID ` +
            `${parsed.keyId} for free. That is not a flaw on its own; it becomes one in ` +
            `panel 3, when the same IV turns up twice, and in panel 5, where the public ` +
            `IV is the first three bytes of every RC4 key.`,
        }),
      ]),

      el('h4', { text: '5 — the receiver verifies, for real' }),
      el('p', {
        class: 'hint',
        text:
          'Decrypt, split off the last four bytes, recompute CRC-32 over the payload and ' +
          'compare. This is the only receiver in this lab: the forged packet in panel 4 ' +
          'goes through exactly this code.',
      }),
      el('div', { class: 'counts' }, [
        el('dl', {}, [
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'ICV carried in the packet' }),
            el('dd', { id: 'wep-icv-received', text: `0x${received.icvReceived.toString(16).padStart(8, '0')}` }),
          ]),
          el('div', { class: 'count-row' }, [
            el('dt', { text: 'ICV the receiver computed' }),
            el('dd', { id: 'wep-icv-computed', text: `0x${received.icvComputed.toString(16).padStart(8, '0')}` }),
          ]),
        ]),
      ]),
      el('div', { id: 'wep-verdict' }, [
        verdict(received.icvValid ? 'pass' : 'fail', received.icvValid ? 'ICV CHECK PASSED' : 'ICV CHECK FAILED', {
          'data-claim': 'wep-icv',
        }),
      ]),
      note('neutral', [
        el('p', {
          text:
            'Read that verdict narrowly. The decrypted payload matches its accompanying ' +
            'checksum. That does not establish who sent the message or whether it was ' +
            'altered. Panel 4 shows why.',
        }),
      ]),
      el('p', {
        class: 'hint',
        id: 'wep-recovered',
        text: `Receiver recovered: “${new TextDecoder().decode(received.payload)}”`,
      })
    );
  }

  keySizeSelect.addEventListener('change', () => {
    regenerate();
    render();
  });
  newKeyBtn.addEventListener('click', () => {
    regenerate();
    render();
  });
  for (const control of [keyInput, ivInput, msgInput]) {
    control.addEventListener('input', render);
  }
  keyIdSelect.addEventListener('change', render);

  host.append(
    el('h2', { text: 'Wrap it in WEP' }),
    el('p', {
      text:
        'WEP’s job is to take a message, a shared key everyone on the network knows, ' +
        'and a per-packet initialisation vector, and produce something safe to send. It ' +
        'gets two of those three steps wrong, and this panel is where you can see all ' +
        'three in one place.',
    }),
    note('neutral', [
      el('p', {
        text:
          'What is modelled here is the WEP PROTECTED BODY: the clear IV and Key ID ' +
          'field, and the encrypted payload and ICV. The 802.11 MAC header, the outer ' +
          'frame check sequence and the radio itself are not modelled at all. This is ' +
          'not a complete on-air frame and it is not a capture-file format.',
      }),
    ]),
    card([el('div', { class: 'controls' }, [
      field('Shared key size', keySizeSelect),
      field('WEP shared key (hex)', keyInput),
      field('IV (3 bytes, hex)', ivInput),
      field('Key ID', keyIdSelect),
      newKeyBtn,
    ]), field('Message', msgInput), inputError, out]),
    details('The serialisation details, and where each one comes from', [
      el('p', {}, [
        document.createTextNode(
          'Four details are easy to get backwards. The RC4 key is IV-PREPENDED, not ' +
            'appended. The Key ID sits in the UPPER TWO BITS of its byte, and this ' +
            'profile leaves the other six at zero. The ICV is LITTLE-ENDIAN. And the ' +
            'encrypted ICV is not the 802.11 frame check sequence — that is a separate ' +
            'field on a real frame, outside this model. All four follow Linux’s '
        ),
        el('a', {
          href: 'https://github.com/torvalds/linux/blob/master/net/mac80211/wep.c',
          target: '_blank',
          rel: 'noopener noreferrer',
          text: 'net/mac80211/wep.c',
        }),
        document.createTextNode(
          ', whose own comment for this construction reads data = RC4(data | CRC32(data)).'
        ),
      ]),
      el('p', {
        text:
          'Panel 5 targets the 104-bit profile. Both sizes construct and verify here, ' +
          'but stage-1 key recovery is wired for 13-byte shared keys only.',
      }),
    ])
  );

  regenerate();
  render();
}
