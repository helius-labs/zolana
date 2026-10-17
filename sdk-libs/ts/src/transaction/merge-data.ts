import { TransactionError } from "./error.js";

/** Merging may consolidate value, but cannot change its committed ring data. */
export function checkMergeRingDataHash(
  actual: bigint,
  expected: bigint,
  slot: number | "output",
): void {
  if (actual !== expected)
    throw new TransactionError("TRANSACTION_MERGE_RING_DATA_MISMATCH", { slot });
}
