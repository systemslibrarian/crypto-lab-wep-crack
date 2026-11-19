/**
 * The broadcast-attack worker (AlFardan et al., USENIX 2013, §4.1).
 *
 * It plays the broadcast SENDER: given a secret, positions and a session count,
 * it encrypts the secret under that many RC4 keys and returns the per-position
 * ciphertext tallies — never the recovered plaintext. Recovery (the attacker's
 * ML step) runs on the main thread from the tallies and the public bias table,
 * so the inference never touches the secret.
 *
 * Off the main thread, chunked and cancellable, so a large run keeps the UI
 * responsive. The key source is built ONCE per run so a seeded run does not
 * repeat keys across chunks.
 */
import { generateTallies, secureKeySource, seededKeySource, type KeySource } from './broadcast-core';

interface RunMessage {
  kind: 'run';
  runId: string;
  secret: number[];
  positions: number[];
  sessions: number;
  /** null => cryptographically random keys; a number => reproducible. */
  seed: number | null;
}
interface CancelMessage {
  kind: 'cancel';
  runId: string;
}
type Inbound = RunMessage | CancelMessage;

export interface TalliesMessage {
  kind: 'tallies';
  runId: string;
  tallies: number[][];
}
export interface ProgressMessage {
  kind: 'progress';
  runId: string;
  done: number;
  total: number;
}
export interface CancelledMessage {
  kind: 'cancelled';
  runId: string;
}
export interface ErrorMessage {
  kind: 'error';
  runId: string;
  message: string;
}
export type Outbound = TalliesMessage | ProgressMessage | CancelledMessage | ErrorMessage;

const cancelled = new Set<string>();
const post = (m: Outbound): void => self.postMessage(m);

self.addEventListener('message', (event: MessageEvent<Inbound>) => {
  const message = event.data;
  if (message.kind === 'cancel') {
    cancelled.add(message.runId);
    return;
  }
  if (message.kind !== 'run') return;
  const { runId, positions, sessions } = message;
  try {
    const secret = Uint8Array.from(message.secret);
    if (secret.length !== positions.length) throw new Error('one position per secret byte');
    const source: KeySource = message.seed === null ? secureKeySource : seededKeySource(message.seed);
    const tallies = positions.map(() => new Int32Array(256));
    const chunk = 8192;
    let done = 0;
    while (done < sessions) {
      if (cancelled.has(runId)) {
        post({ kind: 'cancelled', runId });
        return;
      }
      const n = Math.min(chunk, sessions - done);
      const part = generateTallies(secret, positions, n, source);
      for (let i = 0; i < positions.length; i++) {
        for (let k = 0; k < 256; k++) tallies[i][k] += part[i][k];
      }
      done += n;
      post({ kind: 'progress', runId, done, total: sessions });
    }
    post({ kind: 'tallies', runId, tallies: tallies.map((t) => Array.from(t)) });
  } catch (error) {
    post({ kind: 'error', runId, message: error instanceof Error ? error.message : String(error) });
  }
});
