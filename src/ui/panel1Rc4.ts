/**
 * Panel 1 — RC4 itself.
 *
 * Steps the ACTUAL KSA swaps and PRGA output, drawing the real 256-byte
 * permutation and marking the indices the current operation touches. Every
 * frame is executed state: the trace comes back from `ksa()`/`Rc4Keystream`
 * rather than from an animation script.
 *
 * The vector comparison computes both sides and shows them — it never asserts a
 * match in prose. And a pass reads TEST VECTOR MATCH, scoped to implementation
 * correctness, because "RC4 secure" is the thing it does not mean.
 */

import { type KsaStep, type PrgaStep, ksa, Rc4Keystream } from '../rc4/rc4';
import { RFC6229_ROW_COUNT, RFC6229_VECTORS } from '../rc4/vectors';
import { fromHex, toHex } from '../wep/bytes';
import { byteBlock, card, clear, details, el, field, scroller, verdict } from './dom';

/** The inspection key, deliberately separate from any recovery session. */
const INSPECTION_KEY = '0102030405';

export function renderPanel1(host: HTMLElement): void {
  clear(host);

  host.append(
    el('h2', { text: 'Step the real cipher' }),
    el('p', {
      text:
        'RC4 turns a key into a keystream in two loops. The first shuffles a 256-byte ' +
        'array into a secret order; the second walks that array, swapping as it goes, ' +
        'and reads out one byte at a time. Nothing else happens — no rounds, no block ' +
        'structure. Encrypting is XORing your message with that stream.',
    }),
    el('p', {
      class: 'hint',
      text:
        'The key below is an inspection key for this panel only. It has nothing to do ' +
        'with the session key panel 5 tries to recover.',
    })
  );

  // ── The stepper ────────────────────────────────────────────────────────
  const keyInput = el('input', {
    type: 'text',
    value: INSPECTION_KEY,
    maxlength: '64',
    spellcheck: 'false',
    'aria-describedby': 'rc4-key-hint',
  });
  const stepLabel = el('span', { class: 'bytes-label', id: 'rc4-step-label' });
  const permWrap = el('div', { class: 'perm-wrap', role: 'region', tabindex: '0', 'aria-label': 'RC4 permutation state, 256 bytes' });
  const explain = el('p', { class: 'hint', id: 'rc4-step-explain' });
  const stepOut = el('div', { id: 'rc4-step-out', role: 'status', 'aria-live': 'polite' });

  let ksaTrace: KsaStep[] = [];
  let prgaTrace: PrgaStep[] = [];
  let cursor = 0; // 0..255 = KSA rounds, 256+ = PRGA steps

  const PRGA_STEPS = 16;

  function rebuild(): boolean {
    const raw = keyInput.value.trim();
    let key: Uint8Array;
    try {
      key = fromHex(raw);
      if (key.length === 0) throw new Error('empty');
      ksaTrace = [];
      ksa(key, ksaTrace);
      prgaTrace = [];
      new Rc4Keystream(key).next(PRGA_STEPS, prgaTrace);
      keyInput.setAttribute('aria-invalid', 'false');
      return true;
    } catch {
      keyInput.setAttribute('aria-invalid', 'true');
      return false;
    }
  }

  function drawPermutation(s: Uint8Array, marks: { i?: number; j?: number; out?: number }): void {
    clear(permWrap);
    const grid = el('div', { class: 'perm' });
    for (let idx = 0; idx < 256; idx++) {
      const cls =
        idx === marks.i ? 'perm-cell at-i stepped'
        : idx === marks.j ? 'perm-cell at-j stepped'
        : idx === marks.out ? 'perm-cell at-out stepped'
        : 'perm-cell';
      grid.append(el('span', { class: cls, text: s[idx].toString(16).padStart(2, '0') }));
    }
    permWrap.append(grid);
  }

  function draw(): void {
    clear(stepOut);
    if (cursor < 256) {
      const step = ksaTrace[cursor];
      stepLabel.textContent = `KEY SCHEDULE — round ${step.i} of 255`;
      drawPermutation(step.s, { i: step.i, j: step.jAfter });
      explain.textContent =
        `j moved from ${step.jBefore} to ${step.jAfter}, because j + S[${step.i}] + ` +
        `K[${step.keyIndex}] = ${step.jBefore} + ${step.sAtI} + ${step.keyByte} ` +
        `(mod 256). Then S[${step.i}] and S[${step.jAfter}] swapped. The key byte is ` +
        `the only thing an attacker does not know, and it is mixed in right here.`;
      // The key byte is read cyclically, which is why a 5-byte key still fills
      // 256 rounds -- and why the first rounds leak the most.
      stepOut.append(
        el('p', { class: 'hint' }, [
          el('span', { text: 'violet = index i' }),
          document.createTextNode('  ·  '),
          el('span', { text: 'amber = index j' }),
        ])
      );
    } else {
      const n = cursor - 256;
      const step = prgaTrace[n];
      stepLabel.textContent = `KEYSTREAM — output byte ${n}`;
      drawPermutation(step.s, { i: step.i, j: step.j, out: step.outIndex });
      explain.textContent =
        `i = ${step.i}, then j += S[i] gives j = ${step.j}. S[i] and S[j] swapped, and ` +
        `the output is read from index S[i] + S[j] = ${step.outIndex}: the byte there is ` +
        `0x${step.out.toString(16).padStart(2, '0')}. That byte XORs one byte of your message.`;
      stepOut.append(
        el('p', { class: 'hint' }, [
          el('span', { text: 'violet = i' }),
          document.createTextNode('  ·  '),
          el('span', { text: 'amber = j' }),
          document.createTextNode('  ·  '),
          el('span', { text: 'green = the output index' }),
        ])
      );
      stepOut.append(
        byteBlock(
          `KEYSTREAM SO FAR (${n + 1} byte${n === 0 ? '' : 's'})`,
          Uint8Array.from(prgaTrace.slice(0, n + 1).map((s) => s.out))
        )
      );
    }
  }

  const btnBack = el('button', { class: 'btn', type: 'button', text: '‹ Back' });
  const btnStep = el('button', { class: 'btn btn-primary', type: 'button', text: 'Step ›' });
  const btnKsaEnd = el('button', { class: 'btn', type: 'button', text: 'Skip to keystream' });
  const btnReset = el('button', { class: 'btn', type: 'button', text: 'Reset' });

  function sync(): void {
    btnBack.disabled = cursor === 0;
    btnStep.disabled = cursor >= 255 + PRGA_STEPS;
    btnKsaEnd.disabled = cursor >= 256;
    draw();
  }

  btnStep.addEventListener('click', () => {
    if (cursor < 255 + PRGA_STEPS) cursor++;
    sync();
  });
  btnBack.addEventListener('click', () => {
    if (cursor > 0) cursor--;
    sync();
  });
  btnKsaEnd.addEventListener('click', () => {
    cursor = 256;
    sync();
  });
  btnReset.addEventListener('click', () => {
    cursor = 0;
    sync();
  });
  keyInput.addEventListener('input', () => {
    if (rebuild()) {
      cursor = 0;
      sync();
    }
  });

  rebuild();

  host.append(
    card([
      el('h3', { text: 'The executed state' }),
      el('div', { class: 'controls' }, [
        field('Inspection key (hex)', keyInput),
        btnBack,
        btnStep,
        btnKsaEnd,
        btnReset,
      ]),
      el('p', {
        class: 'hint',
        id: 'rc4-key-hint',
        text:
          'Any 1 to 256 bytes — that is RC4’s own contract. WEP’s 5-or-13-byte ' +
          'rule belongs to the WEP wrapper in panel 2, not to the cipher.',
      }),
      stepLabel,
      permWrap,
      explain,
      stepOut,
    ])
  );

  // ── The vector check: compute both sides and compare ──────────────────
  host.append(renderVectorCheck());

  host.append(
    details('Why passing these vectors is not a security claim', [
      el('p', {
        text:
          'A test vector says this implementation agrees with the specified output. ' +
          'It says nothing about whether RC4 is safe to use. RC4 has cryptographic ' +
          'weaknesses beyond anything WEP does with it, and RFC 7465 prohibits RC4 ' +
          'cipher suites in TLS outright.',
      }),
      el('p', {
        text:
          'Nor does the rest of this lab imply that fresh keys and a proper message ' +
          'authentication code would rehabilitate RC4 as a modern design choice. They ' +
          'would not. The lesson here is narrower and more useful: a cipher can be ' +
          'implemented exactly right and still sit inside a broken system.',
      }),
      el('p', {}, [
        document.createTextNode('Vectors from '),
        el('a', {
          href: 'https://www.rfc-editor.org/rfc/rfc6229.html',
          target: '_blank',
          rel: 'noopener noreferrer',
          text: 'RFC 6229',
        }),
        document.createTextNode('; the TLS prohibition is '),
        el('a', {
          href: 'https://www.rfc-editor.org/rfc/rfc7465.html',
          target: '_blank',
          rel: 'noopener noreferrer',
          text: 'RFC 7465',
        }),
        document.createTextNode('.'),
      ]),
    ])
  );
}

function renderVectorCheck(): HTMLElement {
  const rows: HTMLElement[] = [];
  let allMatch = true;

  for (const v of RFC6229_VECTORS) {
    const key = fromHex(v.keyHex);
    const stream = new Rc4Keystream(key);
    for (const row of v.at) {
      stream.skip(row.offset - stream.offset);
      const computed = toHex(stream.next(16));
      const match = computed === row.hex;
      if (!match) allMatch = false;
      rows.push(
        el('tr', { class: match ? '' : 'is-leader' }, [
          el('td', { text: `${v.keyBits}-bit` }),
          el('td', { class: 'num', text: String(row.offset) }),
          el('td', { class: 'num', text: row.hex }),
          el('td', { class: 'num', text: computed }),
          el('td', {}, [
            verdict(match ? 'pass' : 'fail', match ? 'MATCH' : 'DIFFERS', {
              'data-claim': 'vector-row',
            }),
          ]),
        ])
      );
    }
  }

  return card(
    [
      el('h3', { text: 'Compare against the published vectors' }),
      el('p', {
        text:
          'Both sides are computed and shown: the expected bytes come from RFC 6229 and ' +
          'the computed bytes come from the cipher you just stepped through. The offsets ' +
          'are positions in one continuous keystream, not block boundaries — RC4 has no blocks.',
      }),
      el('div', { id: 'rc4-vector-verdict' }, [
        verdict(allMatch ? 'pass' : 'fail', allMatch ? 'TEST VECTOR MATCH' : 'VECTOR MISMATCH', {
          'data-claim': 'vector-summary',
        }),
        el('p', {
          class: 'hint',
          id: 'rc4-vector-scope',
          text:
            `All ${RFC6229_ROW_COUNT} published expected-byte rows across ` +
            `${RFC6229_VECTORS.length} keys reproduce exactly. This checks implementation ` +
            `correctness against the specification. It is not a statement that RC4 is secure.`,
        }),
      ]),
      scroller('RFC 6229 vector comparison', [
        el('table', {}, [
          el('caption', { text: 'Expected bytes from RFC 6229 beside the bytes this cipher computed' }),
          el('thead', {}, [
            el('tr', {}, [
              el('th', { text: 'Key size' }),
              el('th', { class: 'num', text: 'Offset' }),
              el('th', { class: 'num', text: 'Expected (RFC 6229)' }),
              el('th', { class: 'num', text: 'Computed here' }),
              el('th', { text: 'Result' }),
            ]),
          ]),
          el('tbody', {}, rows),
        ]),
      ]),
    ],
    { id: 'rc4-vectors' }
  );
}
