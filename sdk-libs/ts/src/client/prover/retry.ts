/** Attempts per prover request, mirroring the Rust client's `PROVE_MAX_ATTEMPTS`. */
export const MAX_ATTEMPTS = 3;
/** Wait between attempts, mirroring `PROVE_RETRY_BACKOFF_SECS`. */
export const RETRY_DELAY_MS = 2_000n;
/** Bound on one attestation request, mirroring `STATUS_POLL_TIMEOUT_SECS`. */
export const ATTESTATION_TIMEOUT_MS = 30_000;
const RETRY_AFTER_CAP_MS = 30_000n;

/** The wait before retrying an attestation answer, `undefined` for a final one. */
export function attestationRetryDelayMs(
  status: number,
  retryAfter: string | null,
): bigint | undefined {
  if (status === 503) return RETRY_DELAY_MS;
  if (status !== 429) return undefined;
  const seconds = retryAfter?.trim() ?? "";
  if (!/^\d+$/u.test(seconds)) return RETRY_DELAY_MS;
  const delay = BigInt(seconds) * 1000n;
  return delay < RETRY_AFTER_CAP_MS ? delay : RETRY_AFTER_CAP_MS;
}
