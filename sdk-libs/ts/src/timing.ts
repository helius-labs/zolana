/**
 * Opt-in phase timing, printed to stderr when `ZOLANA_TIMING` is set.
 *
 * Mirrors the Rust client crate's `ZOLANA_TIMING` flag so Photon / prover
 * latency can be attributed from the same process that runs a fill or wallet.
 */

let cached: boolean | undefined;

/** True when `ZOLANA_TIMING` is present in the environment (any value). */
export function timingEnabled(): boolean {
  if (cached === undefined) {
    cached =
      typeof process !== "undefined" &&
      typeof process.env === "object" &&
      process.env !== null &&
      Object.prototype.hasOwnProperty.call(process.env, "ZOLANA_TIMING");
  }
  return cached;
}

/** Reset the cached enablement check (tests only). */
export function resetTimingEnabledForTests(): void {
  cached = undefined;
}

/** Emit a scalar observation alongside phase timings. */
export function noteTiming(key: string, value: number | string): void {
  if (!timingEnabled()) return;
  console.error(`timing ${key}=${value}`);
}

/**
 * Times an async call and prints `timing phase=<name> ms=<n> [ok|err]` when
 * timing is enabled. Always returns or rethrows the inner result.
 */
export async function timePhase<T>(name: string, run: () => Promise<T>): Promise<T> {
  if (!timingEnabled()) return run();
  const started = performance.now();
  try {
    const value = await run();
    console.error(`timing phase=${name} ms=${Math.round(performance.now() - started)} ok`);
    return value;
  } catch (error) {
    console.error(`timing phase=${name} ms=${Math.round(performance.now() - started)} err`);
    throw error;
  }
}
