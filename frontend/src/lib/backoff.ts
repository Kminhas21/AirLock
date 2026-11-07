// backoff.ts — exponential, capped, jittered reconnect delays.
// delay = min(maxMs, baseMs * 2^attempt) * (1 - jitter * rng())

export interface BackoffOptions {
  baseMs?: number;
  maxMs?: number;
  /** Fraction (0..1) of the delay that may be randomly shaved off. */
  jitter?: number;
  /** Injected random source returning [0,1); defaults to Math.random. */
  rng?: () => number;
}

export interface Backoff {
  next: () => number;
  reset: () => void;
}

export function createBackoff(opts: BackoffOptions = {}): Backoff {
  const { baseMs = 500, maxMs = 10000, jitter = 0.3, rng = Math.random } = opts;
  let attempt = 0;
  return {
    next() {
      const raw = Math.min(maxMs, baseMs * 2 ** attempt);
      if (raw < maxMs) attempt += 1;
      return Math.round(raw * (1 - jitter * rng()));
    },
    reset() {
      attempt = 0;
    },
  };
}
