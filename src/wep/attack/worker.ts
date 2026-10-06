/**
 * The attack worker. Runs PTW off the main thread, bounded and cancellable.
 *
 * Its entire input is a `WorkerInbound` message, and `assertCaptureOnly` is
 * applied to every inbound request HERE, inside the worker, before any work
 * starts. Checking at the sender would be checking the wrong side: the worker
 * is the thing that must not be given secrets, so it is the thing that refuses
 * them. A refusal comes back as an `experiment-error` result rather than a
 * silent drop, because a run that never answers looks exactly like one still
 * collecting.
 *
 * Cancellation: the panel posts `{kind:'cancel', runId}` and the run's progress
 * callback notices between batches. Every outbound message carries the run id
 * it belongs to, so a late reply for a retired run can be discarded by the
 * panel rather than restoring a stale verdict.
 */

import { assertCaptureOnly, type WorkerInbound, type WorkerOutbound } from './contract';
import { runPtw } from './ptw';

/** Run ids the panel has asked us to abandon. */
const cancelled = new Set<string>();

function post(message: WorkerOutbound): void {
  self.postMessage(message);
}

self.addEventListener('message', (event: MessageEvent<WorkerInbound>) => {
  const message = event.data;

  if (message.kind === 'cancel') {
    cancelled.add(message.runId);
    return;
  }

  if (message.kind !== 'run') return;
  const { request } = message;

  try {
    // The boundary is enforced on the receiving side, before any computation.
    assertCaptureOnly(request);
  } catch (e) {
    post({
      kind: 'result',
      result: {
        runId: request?.runId ?? 'unknown',
        state: 'experiment-error',
        candidate: null,
        counts: {
          supplied: 0,
          usable: 0,
          duplicateIvExcluded: 0,
          voting: 0,
          validationAvailable: 0,
          validationChecked: 0,
          candidatesTested: 0,
        },
        elapsedMillis: 0,
        voteTables: [],
        error: e instanceof Error ? e.message : String(e),
      },
    });
    return;
  }

  const result = runPtw(request, {
    shouldContinue: () => !cancelled.has(request.runId),
    onProgress: (processed, total, candidatesTested) => {
      post({
        kind: 'progress',
        progress: {
          runId: request.runId,
          phase: candidatesTested > 0 ? 'ranking' : 'voting',
          processed,
          total,
          candidatesTested,
        },
      });
    },
  });

  post({ kind: 'result', result });
  cancelled.delete(request.runId);
});
