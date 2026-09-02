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

/** @internal */
export function checkedU32(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return value;
}

/** @internal */
export function checkedComputeUnitPrice(value: bigint | undefined): void {
  if (value !== undefined && (value < 0n || value > 0xffff_ffff_ffff_ffffn)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "computeUnitPriceMicroLamports" },
    });
  }
}
