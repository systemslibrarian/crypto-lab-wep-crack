/**
 * Panel 5 — recover the shared key with PTW.
 *
 * A FRESH 104-bit session key, traffic generated under the declared profile,
 * and a real PTW run in a worker. The worker gets captured bytes and the public
 * profile assumptions; the experiment controller keeps ground truth and makes
 * the final byte-for-byte comparison.
 *
 * The two-step verdict is the point:
 *   - the attacker reports a VALIDATED CANDIDATE, having passed the public
 *     capture-based rule on reserved distinct-IV packets;
 *   - only then does the controller compare it with its hidden key, and only
 *     equality renders WEP KEY RECOVERED. A mismatch is an experiment failure.
 *
 * Recovery here does NOT depend on panel 3 finding a collision: PTW works from
 * distinct-IV samples, and the duplicates are excluded from the vote.
 */

import { ExperimentController } from '../wep/controller';
import { toHex } from '../wep/bytes';
import {
  ARP_REQUEST_KNOWN_PREFIX,
  IV_POLICY,
  PROFILE_DESCRIPTION,
  PROFILE_ID,
  PROFILE_PAYLOAD_LEN,
} from '../wep/traffic';
import { MEASURED_SUCCESS_RATES, MEASUREMENT_NOTE } from '../wep/attack/fixtures';
import {
  buildAttackRequest,
  type AttackResult,
  type WorkerInbound,
  type WorkerOutbound,
} from '../wep/attack/contract';
import {
  byteBlock,
  card,
  clear,
  details,
  dlRow,
  el,
  field,
  note,
  scroller,
  statusRegion,
  verdict,
} from './dom';

const VALIDATION_RESERVE = 20;
const DEFAULT_PACKETS = 60000;
const MAX_CANDIDATES = 200000;
const MAX_MILLIS = 30000;

export function renderPanel5(host: HTMLElement): void {
  clear(host);

  let controller = new ExperimentController({ sharedKeyBytes: 13 });
  let worker: Worker | null = null;
  /** The run this panel is currently willing to believe. */
  let activeRunId: string | null = null;
  let runCounter = 0;
  let revealed = false;
  let lastResult: AttackResult | null = null;

  const packetsSelect = el('select', { id: 'ptw-packets' }) as HTMLSelectElement;
  for (const n of [20000, 40000, 60000, 80000]) {
    packetsSelect.append(el('option', { value: String(n), text: `${n.toLocaleString()} packets`, selected: n === DEFAULT_PACKETS }));
  }
  const btnRun = el('button', { class: 'btn btn-primary', type: 'button', text: 'Run the attack' });
  const btnCancel = el('button', { class: 'btn', type: 'button', text: 'Cancel' }) as HTMLButtonElement;
  btnCancel.disabled = true;
  const btnNewSession = el('button', { class: 'btn', type: 'button', text: 'New session key' });
  const btnReveal = el('button', { class: 'btn btn-danger', type: 'button', text: 'Reveal the session key' });

  const progressBar = el('progress', { id: 'ptw-progress', max: '100', value: '0', 'aria-label': 'Attack progress' }) as HTMLProgressElement;
  const progressWrap = el('div', { hidden: true }, [progressBar, el('p', { class: 'hint', id: 'ptw-progress-text' })]);
  const status = statusRegion('ptw-status');
  const resultBox = el('div', { id: 'ptw-result' });
  const votesBox = el('div', { id: 'ptw-votes' });

  /** Clear any previous verdict. A changed session must not keep a stale one. */
  function retireVerdict(): void {
    activeRunId = null;
    lastResult = null;
    revealed = false;
    clear(resultBox);
    clear(votesBox);
    clear(status);
    status.append(
      el('div', {}, [verdict('neutral', 'NO RUN YET', { 'data-claim': 'ptw-state' })]),
      el('p', {
        class: 'hint',
        text:
          'A fresh 104-bit key is loaded. Nothing has been attacked yet, so there is no ' +
          'verdict to show — which is different from an attack that failed.',
      })
    );
  }

  function ensureWorker(): Worker {
    if (worker) return worker;
    worker = new Worker(new URL('../wep/attack/worker.ts', import.meta.url), { type: 'module' });
    worker.addEventListener('message', (event: MessageEvent<WorkerOutbound>) => {
      const msg = event.data;
      // A late reply for a retired run must not restore a stale verdict.
      const runId = msg.kind === 'result' ? msg.result.runId : msg.progress.runId;
      if (runId !== activeRunId) return;

      if (msg.kind === 'progress') {
        const pct = msg.progress.total > 0 ? Math.round((msg.progress.processed / msg.progress.total) * 100) : 0;
        progressBar.value = pct;
        const text = document.getElementById('ptw-progress-text');
        if (text) {
          text.textContent =
            msg.progress.phase === 'voting'
              ? `Counting votes from ${msg.progress.total.toLocaleString()} usable samples…`
              : `Ranking candidates — ${msg.progress.candidatesTested.toLocaleString()} tested so far…`;
        }
        return;
      }
      finish(msg.result);
    });
    return worker;
  }

  function finish(result: AttackResult): void {
    lastResult = result;
    btnRun.disabled = false;
    btnCancel.disabled = true;
    progressWrap.hidden = true;
    renderResult();
  }

  function run(): void {
    runCounter++;
    const runId = `run-${runCounter}-${Date.now()}`;
    // Retire the old verdict BEFORE starting, then adopt the new run id.
    retireVerdict();
    activeRunId = runId;

    const packets = Number(packetsSelect.value);
    const generated = controller.generate(packets + VALIDATION_RESERVE);

    // THE BOUNDARY CROSSING. Only `.body` goes; `.plaintext` is dropped here.
    const request = buildAttackRequest({
      runId,
      keyBits: 104,
      profile: {
        profileId: PROFILE_ID,
        knownPrefix: ARP_REQUEST_KNOWN_PREFIX,
        payloadLength: PROFILE_PAYLOAD_LEN,
        keyId: 0,
      },
      budget: { maxPackets: packets, maxCandidates: MAX_CANDIDATES, maxMillis: MAX_MILLIS },
      capturedBodies: generated.slice(0, packets).map((p) => p.body),
      validationBodies: generated.slice(packets).map((p) => p.body),
    });

    btnRun.disabled = true;
    btnCancel.disabled = false;
    progressWrap.hidden = false;
    progressBar.value = 0;
    clear(status);
    status.append(
      el('div', {}, [verdict('neutral', 'COLLECTING AND SEARCHING', { 'data-claim': 'ptw-state' })]),
      el('p', {
        class: 'hint',
        text: `${packets.toLocaleString()} packets generated and handed over as captured bytes.`,
      })
    );

    const message: WorkerInbound = { kind: 'run', request };
    ensureWorker().postMessage(message);
  }

  function cancel(): void {
    if (!activeRunId || !worker) return;
    const message: WorkerInbound = { kind: 'cancel', runId: activeRunId };
    worker.postMessage(message);
    btnCancel.disabled = true;
  }

  function renderResult(): void {
    const result = lastResult;
    if (!result) return;
    clear(status);
    clear(resultBox);
    clear(votesBox);

    // The attacker's half: a VALIDATED CANDIDATE, or a scoped non-result.
    const candidateHex = result.candidate ? toHex(result.candidate) : null;
    const comparison = controller.compare(result.candidate);

    let stateChip: HTMLElement;
    let explanation: string;
    switch (result.state) {
      case 'recovered-candidate':
        if (comparison.kind === 'recovered') {
          // BOTH halves passed. Only now is this a recovery.
          stateChip = verdict('alarm', 'WEP KEY RECOVERED', { 'data-claim': 'ptw-state' });
          explanation =
            `The attacker returned a candidate that passed the public validation rule on ` +
            `${result.counts.validationChecked} reserved distinct-IV packets, and the ` +
            `experiment controller then compared it byte for byte with the key it had been ` +
            `holding. They are equal.`;
        } else {
          // A validated candidate that is NOT the key is an experiment failure.
          stateChip = verdict('fail', 'EXPERIMENT FAILURE — VALIDATED CANDIDATE IS NOT THE KEY', {
            'data-claim': 'ptw-state',
          });
          explanation =
            `The attacker returned a candidate that passed capture-based validation, but ` +
            `the controller’s comparison disagrees: ` +
            `${comparison.kind === 'mismatch' ? comparison.reason : 'no candidate'}. That is an ` +
            `implementation problem in this lab, not a successful recovery.`;
        }
        break;
      case 'no-key-within-budget':
        stateChip = verdict('neutral', 'NO KEY RECOVERED WITHIN THIS BUDGET', { 'data-claim': 'ptw-state' });
        explanation =
          `The bounded run completed without a validated candidate, stopping at the ` +
          `${result.boundBy === 'time' ? `${(MAX_MILLIS / 1000).toFixed(0)}-second time cap` : `${MAX_CANDIDATES.toLocaleString()}-candidate cap`}. ` +
          `Note what this does NOT prove: that more packets were the only thing missing. ` +
          `For a strong key byte the correct value’s votes are equidistributed, so more ` +
          `samples do not help that sum at all.`;
        break;
      case 'no-usable-samples':
        stateChip = verdict('neutral', 'NO USABLE SAMPLES', { 'data-claim': 'ptw-state' });
        explanation = 'Nothing in the capture matched the declared profile, so no vote was cast.';
        break;
      case 'cancelled':
        stateChip = verdict('neutral', 'CANCELLED', { 'data-claim': 'ptw-state' });
        explanation = 'Processing stopped at your request. The counts below are what it got through.';
        break;
      default:
        stateChip = verdict('fail', 'EXPERIMENT ERROR', { 'data-claim': 'ptw-state' });
        explanation = result.error ?? 'An independent check exposed an implementation problem.';
    }

    status.append(el('div', {}, [stateChip]), el('p', { class: 'hint', id: 'ptw-explanation', text: explanation }));

    // Measured counts, kept separate because they mean different things.
    resultBox.append(
      el('h4', { text: 'What this run actually measured' }),
      el('dl', { class: 'counts' }, [
        dlRow('Packets supplied to the attacker', result.counts.supplied.toLocaleString(), { id: 'ptw-supplied' }),
        dlRow('Usable samples', result.counts.usable.toLocaleString(), { id: 'ptw-usable' }),
        dlRow('Unique voting samples', result.counts.voting.toLocaleString(), { id: 'ptw-voting' }),
        dlRow('Duplicate IVs excluded', result.counts.duplicateIvExcluded.toLocaleString(), { id: 'ptw-dup' }),
        dlRow('Validation packets reserved', result.counts.validationAvailable.toLocaleString(), { id: 'ptw-vavail' }),
        dlRow('Validation packets checked', result.counts.validationChecked.toLocaleString(), { id: 'ptw-vchecked' }),
        dlRow('Candidates tested', result.counts.candidatesTested.toLocaleString(), { id: 'ptw-tested' }),
        dlRow('Compute time', `${result.elapsedMillis.toLocaleString()} ms`, { id: 'ptw-elapsed' }),
      ])
    );

    if (candidateHex) {
      resultBox.append(
        el('h4', { text: 'The candidate the attacker returned' }),
        byteBlock('VALIDATED CANDIDATE', result.candidate!),
        el('p', {
          class: 'hint',
          id: 'ptw-scenario',
          text:
            `Found by scenario ${result.scenario ?? '?'} of the paper’s search` +
            (result.assumedStrong && result.assumedStrong.length
              ? `, assuming sum ${result.assumedStrong.join(' and ')} came from a strong key byte.`
              : ', with key ranking alone and no strong-byte assumption.'),
        })
      );
      if (comparison.kind === 'recovered') {
        resultBox.append(
          note('alarm', [
            el('p', {
              text:
                'A secret has been exposed. Everything the attacker used was public: the ' +
                'IVs travel in the clear, the known plaintext comes from the declared ' +
                'traffic profile, and the validation packets are ordinary captures.',
            }),
          ])
        );
      }
    }

    // The reveal, clearly marked, and never part of the attack path.
    if (revealed) {
      resultBox.append(
        el('h4', { text: 'Ground truth (revealed, not recovered)' }),
        byteBlock('SESSION KEY HELD BY THE CONTROLLER', controller.revealForDisplay()),
        note('neutral', [
          el('p', {
            text:
              'Shown because you asked. The attacker never received this, and it played ' +
              'no part in the search — the only thing the controller ever did with it was ' +
              'the one byte-for-byte comparison above.',
          }),
        ])
      );
    } else {
      resultBox.append(btnReveal);
    }

    // The vote tables, so the mechanism is inspectable.
    if (result.voteTables.length) {
      votesBox.append(renderVoteTables(result));
    }
  }

  btnRun.addEventListener('click', run);
  btnCancel.addEventListener('click', cancel);
  btnNewSession.addEventListener('click', () => {
    // A new session invalidates everything: new key, new generator, no verdict.
    controller = new ExperimentController({ sharedKeyBytes: 13 });
    retireVerdict();
  });
  btnReveal.addEventListener('click', () => {
    revealed = true;
    renderResult();
  });
  // Changing the packet budget also retires the old verdict.
  packetsSelect.addEventListener('change', retireVerdict);

  host.append(
    el('h2', { text: 'Recover the shared key' }),
    el('p', {
      text:
        'Keystream reuse leaks relationships and a linear checksum lets messages be ' +
        'altered. Neither recovers the key. This does: the first three bytes of every ' +
        'RC4 key in WEP are the public IV, and that is enough of a foothold to vote the ' +
        'secret out of the key schedule, one statistical nudge per packet.',
    }),
    note('accent', [
      el('p', {
        text:
          'This panel runs the real PTW attack from Tews, Weinmann and Pyshkin (2007) in ' +
          'a worker. It does not depend on panel 3 finding a collision: PTW works from ' +
          'DISTINCT IVs, and repeated ones are excluded from the vote because they carry ' +
          'no new evidence.',
      }),
    ]),
    card([
      el('div', { class: 'controls' }, [
        field('Packets to generate', packetsSelect),
        btnRun,
        btnCancel,
        btnNewSession,
      ]),
      el('p', {
        class: 'hint',
        text:
          `Traffic profile: ${PROFILE_DESCRIPTION} IV policy: ${IV_POLICY}. ` +
          `${VALIDATION_RESERVE} extra distinct-IV packets are held back for candidate ` +
          `validation and are excluded from the vote.`,
      }),
      progressWrap,
      status,
      resultBox,
    ]),
    votesBox,
    renderMeasurements(),
    renderBoundaries(),
    renderMechanism()
  );

  retireVerdict();
}

function renderVoteTables(result: AttackResult): HTMLElement {
  const rows: HTMLElement[] = [];
  for (const table of result.voteTables) {
    const top = table.top.slice(0, 3);
    rows.push(
      el('tr', {}, [
        el('td', { class: 'num', text: `σ${table.sigmaIndex}` }),
        el('td', { class: 'num', text: table.totalVotes.toLocaleString() }),
        el('td', { class: 'num', text: (table.totalVotes / 256).toFixed(1) }),
        ...top.map((row) =>
          el('td', { class: 'num', text: `0x${row.value.toString(16).padStart(2, '0')} (${row.votes})` })
        ),
      ])
    );
  }
  return card([
    el('h3', { text: 'The vote tables' }),
    el('p', {
      text:
        'One table per sum. Each usable sample casts one vote in every table, and the ' +
        'leading value is the sum’s best guess — "best" meaning it beat the noise ' +
        'floor, which is the third column.',
    }),
    note('neutral', [
      el('p', {
        text:
          'What is being voted on is a RUNNING TOTAL, not a key byte. σ4 is the sum of ' +
          'the first five secret bytes mod 256, so a leading value there is evidence about ' +
          'that total and not a certainty about any single byte. The key is read off the ' +
          'differences between consecutive sums at the end.',
      }),
    ]),
    scroller('PTW vote tables', [
      el('table', {}, [
        el('caption', { text: 'Leading values per sum, with the vote count each received' }),
        el('thead', {}, [
          el('tr', {}, [
            el('th', { class: 'num', text: 'Sum' }),
            el('th', { class: 'num', text: 'Votes cast' }),
            el('th', { class: 'num', text: 'Noise floor' }),
            el('th', { class: 'num', text: '1st' }),
            el('th', { class: 'num', text: '2nd' }),
            el('th', { class: 'num', text: '3rd' }),
          ]),
        ]),
        el('tbody', {}, rows),
      ]),
    ]),
    el('p', {
      class: 'hint',
      text:
        'A leading value is evidence, not a probability. Where a leader sits close to the ' +
        'noise floor, key ranking starts admitting runners-up and testing the keys they ' +
        'make — which is why the candidate count above can run into the thousands.',
    }),
  ]);
}

function renderMeasurements(): HTMLElement {
  return details('How often this actually works, measured rather than asserted', [
    el('p', {
      text:
        'The PTW paper reports recovery from fewer than 40,000 packets in 50% of cases ' +
        'under its own stated conditions, with all three search scenarios and a ' +
        '1,000,000-key limit. That is a probabilistic result from that paper’s ' +
        'experiments. It is not a guarantee, it is not a benchmark for a browser, and it ' +
        'is not a claim about this implementation.',
    }),
    el('p', { text: 'These are this implementation’s own measured runs:' }),
    scroller('Measured success rates', [
      el('table', {}, [
        el('caption', { text: MEASUREMENT_NOTE }),
        el('thead', {}, [
          el('tr', {}, [
            el('th', { class: 'num', text: 'Packets' }),
            el('th', { class: 'num', text: 'Recovered' }),
            el('th', { class: 'num', text: 'Attempted' }),
          ]),
        ]),
        el('tbody', {}, MEASURED_SUCCESS_RATES.map((r) =>
          el('tr', {}, [
            el('td', { class: 'num', text: r.packets.toLocaleString() }),
            el('td', { class: 'num', text: String(r.recovered) }),
            el('td', { class: 'num', text: String(r.attempted) }),
          ])
        )),
      ]),
    ]),
    el('p', {
      text:
        'Declared departures from the paper, so its figures are not borrowed: this ' +
        'implementation assumes at most the top one and two most-likely-strong sums ' +
        'rather than searching further; it caps candidates at 200,000 rather than a ' +
        'million; 40-bit recovery is outside stage 1; and validation is stricter than the ' +
        'paper’s — the known keystream prefix AND the genuine WEP ICV on reserved ' +
        'packets, where the paper used six keystream bytes on ten random sessions.',
    }),
  ]);
}

function renderBoundaries(): HTMLElement {
  return details('What the attacker was and was not given', [
    el('p', {
      text:
        'The worker receives captured protected bodies, the public profile identifier, ' +
        'the declared key size, the resource budgets and a run identifier. It does not ' +
        'receive the shared key, the generator’s seed or state, any plaintext, or a ' +
        'callable reference to the generator or the controller — and that is checked ' +
        'inside the worker on every message, not just at the sender.',
    }),
    el('p', {
      text:
        'Because this exhibit omits MAC headers, the packet class is an explicit public ' +
        'property of the generated profile. The attacker is TOLD these are ARP requests ' +
        'rather than identifying them from fields the model does not have. The address ' +
        'fields are well formed and vary per packet, and they reach the attack only ' +
        'inside ciphertext.',
    }),
    el('p', {
      text:
        'And the honest caveat: these are experimental roles inside one browser ' +
        'application. Hiding a value in an interface does not make it inaccessible to ' +
        'someone inspecting their own browser. The separation is real as data flow — it ' +
        'is what makes the recovery a result rather than a lookup — not as a security ' +
        'boundary.',
    }),
    el('p', {
      text:
        'Session material stays in memory. Nothing is written to storage, the URL, a log ' +
        'or an analytics call. Reset releases the references and invalidates the run; this ' +
        'is not a claim that JavaScript can guarantee the bytes are erased from memory.',
    }),
  ]);
}

function renderMechanism(): HTMLElement {
  return details('The equations, for the expert', [
    el('p', {
      text:
        'Klein’s attack gives an approximation for one key byte that depends on the ' +
        'key-schedule permutation at that step. PTW’s contribution is to re-express it ' +
        'as an estimator for the SUMS that depends only on the public IV, so every sum can ' +
        'be voted on independently and in any order.',
    }),
    el('div', { class: 'bytes' }, [
      el('span', { text: 'σi  =  sum of K[3..3+i]  =  sum of Rk[0..i]   (mod 256)' }),
      el('br', {}),
      el('span', { text: 'Ai  =  S3⁻¹[(3+i) − X[2+i]]  −  ( j3 + sum of S3[3..i+3] )   (mod 256)' }),
      el('br', {}),
      el('span', { text: 'Rk[0] = σ0,   Rk[i] = σi − σi−1' }),
    ]),
    el('p', {
      text:
        'S3 and j3 are the RC4 key-schedule state after the three IV bytes — computable by ' +
        'anyone, because the IV is public. X is the keystream, recovered by XORing captured ' +
        'ciphertext against the profile’s fixed 16-byte prefix. A0 reads X[2] and A12 ' +
        'reads X[14], so a 104-bit key needs 15 keystream bytes and the ARP profile ' +
        'supplies 16. That is equation 5 of the paper; equation 4 is the same thing with ' +
        'the true intermediate permutations, and substituting S3 for all of them is what ' +
        'makes it computable from the IV alone.',
    }),
    el('p', {
      text:
        'For part of the key space that substitution fails in a specific way. The paper ' +
        'calls those strong key bytes: Rk[i] is one if some run of (Rk[k] + 3 + k) ending ' +
        'at i sums to zero mod 256. For such a sum the correct value’s votes become ' +
        'equidistributed and more packets never help, so the attack instead guesses which ' +
        'index is strong from the vote distribution alone and reads that byte off the ' +
        'congruence. Rk[0] can never be strong.',
    }),
    el('p', {}, [
      document.createTextNode('Source: Erik Tews, Ralf-Philipp Weinmann and Andrei Pyshkin, '),
      el('a', {
        href: 'https://eprint.iacr.org/2007/120',
        target: '_blank',
        rel: 'noopener noreferrer',
        text: 'Breaking 104 bit WEP in less than 60 seconds',
      }),
      document.createTextNode(
        ' (2007) — section 3.1 for Klein’s map, section 4 for the extension to sums, section 5 for the ARP assumption, section 6 for ranking and strong keys, section 7 for the measured results. FMS and KoreK are different attacks and are not implemented here.'
      ),
    ]),
  ]);
}
