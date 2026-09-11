/** Statistics for a completed foreground run; preparation and warmups are separate. */
export function proofStatistics(values: readonly number[]) {
  if (values.length === 0 || values.some((n) => !Number.isFinite(n) || n < 0)) {
    throw new Error("Expected finite, nonnegative timing samples");
  }
  const sorted = [...values].sort((a, b) => a - b);
  const n = sorted.length;
  const middle = Math.floor(n / 2);
  const p50Ms = n % 2 ? sorted[middle]! : (sorted[middle - 1]! + sorted[middle]!) / 2;
  // Nearest-rank p95. Preserve outliers; do not trim or average session percentiles.
  const p95Ms = sorted[Math.ceil(0.95 * n) - 1]!;
  return {
    count: n,
    p50Ms,
    p95Ms,
    maxMs: sorted[n - 1]!,
    underOneSecond: values.filter((n) => n < 1000).length,
    p95UnderOneSecond: p95Ms < 1000,
  };
}
