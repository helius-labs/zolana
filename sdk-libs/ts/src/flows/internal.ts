import { assertIsAddress } from "@solana/kit";

import { ClientError } from "../client/error.js";
import type { Address } from "../interface/types.js";

/** @internal */
export function checkedAddress(value: Address, field: string): void {
  try {
    assertIsAddress(value);
  } catch {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field } });
  }
}

/** The runtime clamps a larger request instead of failing, so the ceiling is enforced here. */
const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;

/**
 * @internal The budget a legacy transaction received per instruction. A
 * deposit, a registration or a ring deposit has never needed more, and a
 * version 1 transaction budgets zero units for what it does not name.
 */
export const DEFAULT_COMPUTE_UNIT_LIMIT = 200_000;

/** @internal */
export function checkedComputeUnitLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COMPUTE_UNIT_LIMIT) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "computeUnitLimit" } });
  }
  return value;
}

/** @internal */
export function checkedPriorityFee(value: bigint | undefined): void {
  if (value !== undefined && (value < 0n || value > 0xffff_ffff_ffff_ffffn)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "priorityFeeLamports" },
    });
  }
}
