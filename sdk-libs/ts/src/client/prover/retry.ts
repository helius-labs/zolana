/** Attempts per prover request, mirroring the Rust client's `PROVE_MAX_ATTEMPTS`. */
export const MAX_ATTEMPTS = 3;
/** Wait between attempts, mirroring `PROVE_RETRY_BACKOFF_SECS`. */
export const RETRY_DELAY_MS = 2_000n;
/** Bound on one attestation request, mirroring `STATUS_POLL_TIMEOUT_SECS`. */
export const ATTESTATION_TIMEOUT_MS = 30_000;
const RETRY_AFTER_CAP_MS = 30_000n;

const IMF_FIXDATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/u;

/** The wait before retrying an attestation answer, `undefined` for a final one. */
export function attestationRetryDelayMs(
  status: number,
  retryAfter: string | null,
  nowMs: number,
): bigint | undefined {
  if (status === 503) return RETRY_DELAY_MS;
  if (status !== 429) return undefined;
  return retryAfterMs(retryAfter?.trim() ?? "", nowMs) ?? RETRY_DELAY_MS;
}

/** `Retry-After` as delay seconds or an IMF-fixdate, capped, `undefined` for any other value. */
function retryAfterMs(value: string, nowMs: number): bigint | undefined {
  let delay: bigint;
  if (/^\d+$/u.test(value)) {
    delay = BigInt(value) * 1000n;
  } else {
    const date = imfFixdateMs(value);
    if (date === undefined) return undefined;
    delay = BigInt(Math.max(date - nowMs, 0));
  }
  return delay < RETRY_AFTER_CAP_MS ? delay : RETRY_AFTER_CAP_MS;
}

/** Refuses a wrong weekday, an overflowing field and a year before 1970, as Rust httpdate does. */
function imfFixdateMs(value: string): number | undefined {
  if (!IMF_FIXDATE.test(value)) return undefined;
  const date = Date.parse(value);
  return date >= 0 && new Date(date).toUTCString() === value ? date : undefined;
}
