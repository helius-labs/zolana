/**
 * Starting point for the arithmetic pool, using the browser's available logical
 * processors. Cap large machines at the 18-worker configuration benchmarked by
 * this demo. This is a default, not a measurement of the fastest pool size.
 */
export function automaticProvingThreads(
  reported = globalThis.navigator?.hardwareConcurrency,
): number {
  if (reported === undefined || !Number.isFinite(reported) || reported < 1) return 4;
  return Math.min(18, Math.floor(reported));
}
