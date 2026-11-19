/**
 * Panel 6 — the broadcast single-byte-bias attack.
 *
 * AlFardan, Bernstein, Paterson, Poettering and Schuldt, "On the Security of
 * RC4 in TLS and WPA" (USENIX Security 2013) [R10]. One fixed plaintext,
 * encrypted under many independent RC4 keys, leaks through the keystream's
 * per-position bias: a maximum-likelihood estimate over enough sessions
 * recovers the plaintext byte at a biased position.
 *
 * The keystream generation runs in a Web Worker; the recovery (Algorithm 4)
 * runs here, on the tallies the worker returns and the public bias table —
 * never on the secret. Two things this panel is careful to say:
 *
 *   - the strongest usable bias at teaching scale is Z₂ → 0, and that is
 *     exactly the byte a TLS attack CANNOT use, because the first 36 keystream
 *     bytes encrypt the Handshake Finished message. TLS mode starts at
 *     position 37 and, at these session counts, recovers nothing;
 *   - the bias table is MEASURED offline (2^24 keys), not assumed, and the
 *     paper's own figures are at 2^44 keys and 2^26 sessions, far beyond this.
 */
import {
  BIAS_TABLE,
  PAPER_HEADLINE,
  TLS_FIRST_USABLE_POSITION,
  positionRange,
  recoverPlaintext,
  runBroadcast,
  seededKeySource,
} from '../rc4/broadcast';
import type { Outbound } from '../rc4/broadcast-worker';
import { card, clear, details, dlRow, el, field, note, scroller, statusRegion, verdict } from './dom';

const DEFAULT_SECRET = 'PASSWORD';
const SECRET_MAX = 16;
const SESSION_OPTIONS = [256, 1024, 4096, 16384, 65536] as const;
const RUN_SEED = 20130101; // a fixed seed: reproducible runs (brief §tests)
const SWEEP_SESSIONS = [64, 256, 1024, 4096, 16384] as const;
// Each trial is an INDEPENDENT seeded run (seededKeySource hashes the seed, so
// 1000+t give uncorrelated keystreams — see broadcast-core.ts and the
// independence test). 30 trials keeps the synchronous sweep near 2s while giving
// a stable enough rate to read the rise honestly.
const SWEEP_TRIALS = 30;

const asBytes = (s: string): Uint8Array => new Uint8Array(Array.from(s, (c) => c.charCodeAt(0) & 0xff));
const printable = (b: number): string => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·');
const hex = (b: number): string => b.toString(16).padStart(2, '0');

export function renderPanel6(host: HTMLElement): void {
  clear(host);

  let worker: Worker | null = null;
  let activeRunId: string | null = null;

  const secretInput = el('input', { type: 'text', value: DEFAULT_SECRET, maxlength: String(SECRET_MAX), spellcheck: 'false' }) as HTMLInputElement;
  const modeSelect = el('select', {}, [
    el('option', { value: 'broadcast', text: 'Broadcast (keystream positions 1…L)' }),
    el('option', { value: 'tls', text: 'TLS (positions 37…, skipping the Finished message)' }),
  ]) as HTMLSelectElement;
  const sessionSelect = el(
    'select',
    {},
    SESSION_OPTIONS.map((s) => el('option', { value: String(s), text: `${s.toLocaleString()} sessions` })),
  ) as HTMLSelectElement;
  sessionSelect.value = '16384';
  const runButton = el('button', { class: 'btn btn-primary', type: 'button', text: 'Broadcast and recover' }) as HTMLButtonElement;
  const cancelButton = el('button', { class: 'btn', type: 'button', text: 'Cancel', disabled: 'true' }) as HTMLButtonElement;

  const status = statusRegion('broadcast-status');
  const output = el('div', { id: 'broadcast-output' });

  function stopWorker(): void {
    worker?.terminate();
    worker = null;
    activeRunId = null;
  }
  function retire(): void {
    stopWorker();
    clear(output);
    status.textContent = '';
    cancelButton.disabled = true;
    runButton.disabled = false;
  }
  secretInput.addEventListener('input', retire);
  modeSelect.addEventListener('change', retire);
  sessionSelect.addEventListener('change', retire);

  function positionsFor(len: number): number[] {
    return modeSelect.value === 'tls' ? positionRange(TLS_FIRST_USABLE_POSITION, len) : positionRange(1, len);
  }

  runButton.addEventListener('click', () => {
    const secret = asBytes(secretInput.value);
    if (secret.length === 0) {
      retire();
      status.textContent = 'Enter a short plaintext to broadcast.';
      return;
    }
    stopWorker();
    clear(output);
    const positions = positionsFor(secret.length);
    const sessions = Number(sessionSelect.value);
    const runId = `b-${Date.now()}`;
    activeRunId = runId;
    runButton.disabled = true;
    cancelButton.disabled = false;
    status.textContent = `Encrypting the plaintext under ${sessions.toLocaleString()} RC4 keys…`;

    worker = new Worker(new URL('../rc4/broadcast-worker.ts', import.meta.url), { type: 'module' });
    worker.addEventListener('message', (event: MessageEvent<Outbound>) => {
      const message = event.data;
      if (message.runId !== activeRunId) return;
      if (message.kind === 'progress') {
        status.textContent = `Encrypting… ${message.done.toLocaleString()} / ${message.total.toLocaleString()} sessions`;
        return;
      }
      if (message.kind === 'cancelled') {
        status.textContent = 'Cancelled.';
        runButton.disabled = false;
        cancelButton.disabled = true;
        return;
      }
      if (message.kind === 'error') {
        status.textContent = message.message;
        runButton.disabled = false;
        cancelButton.disabled = true;
        return;
      }
      // tallies: recover HERE, from the tallies and the public table only.
      const tallies = message.tallies.map((t) => Int32Array.from(t));
      const recovered = recoverPlaintext(tallies, positions);
      renderResult(secret, positions, sessions, recovered);
      status.textContent = `Recovered ${Array.from(recovered, (b, i) => (b === secret[i] ? 1 : 0)).reduce((a: number, c) => a + c, 0)} of ${secret.length} bytes.`;
      runButton.disabled = false;
      cancelButton.disabled = true;
      stopWorker();
    });
    worker.postMessage({ kind: 'run', runId, secret: Array.from(secret), positions, sessions, seed: RUN_SEED });
  });

  cancelButton.addEventListener('click', () => {
    if (worker && activeRunId) worker.postMessage({ kind: 'cancel', runId: activeRunId });
  });

  function renderResult(secret: Uint8Array, positions: number[], sessions: number, recovered: Uint8Array): void {
    clear(output);
    const correct = Array.from(recovered, (b, i) => b === secret[i]);
    const successCount = correct.filter(Boolean).length;
    const tls = modeSelect.value === 'tls';

    const rows = positions.map((pos, i) =>
      el('tr', { 'data-position': String(pos), 'data-correct': String(correct[i]) }, [
        el('th', { scope: 'row', text: `Z${pos}` }),
        el('td', { class: 'mono', text: hex(secret[i]) }),
        el('td', { class: 'mono', text: hex(recovered[i]) }),
        el('td', { class: 'mono', text: printable(recovered[i]) }),
        el('td', {}, [correct[i] ? verdict('pass', 'recovered') : verdict('fail', 'not recovered')]),
      ]),
    );
    output.append(
      scroller('Per-position recovery', [
        el('table', { id: 'broadcast-table', class: 'data-table' }, [
          el('caption', { class: 'sr-only', text: 'Recovered plaintext byte at each keystream position' }),
          el('thead', {}, [
            el('tr', {}, [
              el('th', { scope: 'col', text: 'Position' }),
              el('th', { scope: 'col', text: 'Plaintext' }),
              el('th', { scope: 'col', text: 'Recovered' }),
              el('th', { scope: 'col', text: 'As text' }),
              el('th', { scope: 'col', text: 'Result' }),
            ]),
          ]),
          el('tbody', {}, rows),
        ]),
      ]),
    );

    const recoveredText = Array.from(recovered, (b, i) => (correct[i] ? printable(b) : '·')).join('');
    output.append(
      el('p', { id: 'broadcast-verdict' }, [
        successCount > 0 && !tls
          ? verdict('alarm', `${successCount} of ${secret.length} plaintext bytes recovered from the ciphertext biases alone: "${recoveredText}"`)
          : verdict('pass', `${successCount} of ${secret.length} bytes recovered at these positions`),
      ]),
    );

    const z2Index = positions.indexOf(2);
    if (!tls && z2Index >= 0) {
      output.append(
        note('alarm', [
          el('strong', { text: `The reliably recovered byte is Z₂ (position 2). ` }),
          `Z₂ is biased toward 0 at about 1/128, twice uniform, so the most common ciphertext byte there is the plaintext byte. It is the one byte a TLS attack cannot use — switch the mode above to TLS and it drops out of range.`,
        ]),
      );
    } else if (tls) {
      output.append(
        note('neutral', [
          el('strong', { text: `TLS positions start at 37. ` }),
          `The strong Z₂ bias is out of scope because the first 36 keystream bytes encrypt the Handshake Finished message, which is not constant across sessions (AlFardan et al., §3.1: "this byte is always used to encrypt a Finished message in TLS, we are unable to exploit it"). The weaker per-position biases need far more sessions than a browser runs, so at ${sessions.toLocaleString()} sessions this recovers nothing.`,
        ]),
      );
    }
  }

  // ── Success rises with sessions (position 2, synchronous and quick) ────────
  const sweepButton = el('button', { class: 'btn', type: 'button', text: 'Measure success vs. sessions (position 2)' }) as HTMLButtonElement;
  const sweepOut = statusRegion('broadcast-sweep');
  sweepButton.addEventListener('click', () => {
    sweepButton.disabled = true;
    clear(sweepOut);
    sweepOut.append(el('p', { text: 'Running trials…' }));
    // Defer so the status paints before the (fast) sweep.
    setTimeout(() => {
      const secret = new Uint8Array([0x6d]); // one byte at position 2
      // Each trial is an independent seeded run; count successes per session size.
      const results = SWEEP_SESSIONS.map((s) => {
        let ok = 0;
        for (let t = 0; t < SWEEP_TRIALS; t++) {
          if (runBroadcast(secret, [2], s, seededKeySource(1000 + t)).successCount === 1) ok++;
        }
        return { sessions: s, ok, rate: Math.round((ok / SWEEP_TRIALS) * 100) };
      });
      const rows = results.map(({ sessions, rate }) =>
        el('tr', { 'data-sessions': String(sessions) }, [
          el('th', { scope: 'row', text: sessions.toLocaleString() }),
          el('td', { class: 'mono', 'data-rate': String(rate), text: `${rate}%` }),
          el('td', {}, [el('div', { class: 'bar', style: `--w:${rate}%` }, [el('span', { class: 'bar-fill', style: `width:${rate}%` })])]),
        ]),
      );
      // The claim is DERIVED from the table above, not asserted, so it can never
      // contradict the measured rates. "Recovers every time" is attached to the
      // session count where the data actually shows it, not to a fixed threshold.
      const at = (n: number) => results.find((r) => r.sessions === n);
      const top = results[results.length - 1];
      const r1k = at(1024);
      const r4k = at(4096);
      const reliable = results.find((r) => r.rate === 100);
      const claim =
        `Recovery climbs with the number of sessions and is not certain at a thousand: over ${SWEEP_TRIALS} independent trials, position 2 is recovered ` +
        `${r1k ? `${r1k.ok} of ${SWEEP_TRIALS} times (${r1k.rate}%) at 1,024 sessions` : ''}` +
        `${r4k ? ` and ${r4k.rate}% at 4,096` : ''}` +
        `${reliable ? `, and only at ${reliable.sessions.toLocaleString()} sessions does it recover every time (100%)` : `, and does not reach certainty within ${top.sessions.toLocaleString()} sessions here`}. ` +
        `More sessions also recover more bytes — the paper's own curves, at 2^24–2^26 sessions, recover the first several dozen bytes of the plaintext.`;
      clear(sweepOut);
      sweepOut.append(
        scroller('Recovery rate for position 2 by session count', [
          el('table', { id: 'broadcast-sweep-table', class: 'data-table' }, [
            el('caption', { class: 'sr-only', text: 'Recovery success rate at position 2 against the number of sessions' }),
            el('thead', {}, [el('tr', {}, [el('th', { scope: 'col', text: 'Sessions' }), el('th', { scope: 'col', text: `Recovered (of ${SWEEP_TRIALS})` }), el('th', { scope: 'col', text: '' })])]),
            el('tbody', {}, rows),
          ]),
        ]),
        el('div', { class: 'note note-accent', 'data-sweep-claim': '' }, [claim]),
      );
      sweepButton.disabled = false;
    }, 0);
  });

  const z2Rate = BIAS_TABLE.counts[1][0] / BIAS_TABLE.samples;
  host.append(
    card([
      el('h3', { text: 'Recover a repeated plaintext from RC4 bias' }),
      el('p', {
        text:
          'RC4 keystream bytes are not uniform. Encrypt one fixed plaintext under many keys — the broadcast setting, or one short secret sent to many sessions — and each ciphertext position inherits the bias of its keystream byte. Enough sessions, and a maximum-likelihood estimate recovers the plaintext.',
      }),
      field('Plaintext to broadcast (ASCII)', secretInput),
      field('Attack surface', modeSelect),
      field('Sessions', sessionSelect),
      el('div', { class: 'button-row' }, [runButton, cancelButton]),
      status,
      output,
    ]),
    card([
      el('h3', { text: 'Why more sessions recover more' }),
      el('p', { text: 'The bias is tiny, so it shows only in aggregate. Position 2 — RC4’s strongest single-byte bias — recovers once there are enough sessions to see Z₂’s pull toward zero.' }),
      el('div', { class: 'button-row' }, [sweepButton]),
      sweepOut,
    ]),
    details('The measured bias table, and the paper’s scale', [
      note('neutral', [
        `This attack uses a bias table measured OFFLINE over 2^${BIAS_TABLE.log2keys} random keys (${BIAS_TABLE.samples.toLocaleString()} keystreams), shipped as data in `,
        el('code', { text: 'src/rc4/bias-table.json' }),
        `. It records Pr(Z_r = k) for positions r = 1…${BIAS_TABLE.positions}. At position 2 the measured Pr(Z₂ = 0) is ${(z2Rate * 100).toFixed(2)}% — about ${(z2Rate * 256).toFixed(2)}× uniform.`,
      ]),
      el('dl', { class: 'count-list' }, [
        dlRow('Table sample size', `2^${BIAS_TABLE.log2keys} keys`),
        dlRow('Pr(Z₂ = 0), measured', `${(z2Rate * 100).toFixed(3)}%`),
        dlRow('Uniform baseline', `${((1 / 256) * 100).toFixed(3)}%`),
      ]),
      note('accent', [PAPER_HEADLINE]),
      el('p', {
        class: 'cite',
        text:
          'Nadhem J. AlFardan, Daniel J. Bernstein, Kenneth G. Paterson, Bertram Poettering and Jacob C. N. Schuldt, "On the Security of RC4 in TLS and WPA", USENIX Security 2013 [R10]. The measurement is the paper’s §4.1 step; the maximum-likelihood recovery is its Algorithm 4.',
      }),
    ]),
  );
}
