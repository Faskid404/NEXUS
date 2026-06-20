export interface RetryOpts {
  attempts?: number;
  baseMs?: number;
  maxMs?: number;
  jitter?: boolean;
  retryIf?: (err: unknown) => boolean;
}

export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOpts = {}): Promise<T> {
  const {
    attempts = 3,
    baseMs   = 500,
    maxMs    = 30_000,
    jitter   = true,
    retryIf  = () => true,
  } = opts;
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (i + 1 >= attempts || !retryIf(e)) break;
      const base  = Math.min(baseMs * 2 ** i, maxMs);
      const delay = jitter ? base * (0.5 + Math.random() * 0.5) : base;
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw last;
}

export function isTransient(err: unknown): boolean {
  const msg = (err as Error)?.message ?? String(err);
  return /ECONNREFUSED|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|socket hang up|ENOTFOUND|timeout/i.test(msg);
}
