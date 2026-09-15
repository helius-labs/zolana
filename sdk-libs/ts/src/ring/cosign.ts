import type { Address } from "@solana/kit";

import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingCoSigner,
} from "./codecs.js";
import { RingError } from "./error.js";

/** Mirrors Rust `CoSignerRequirement`, a withdrawal leg carries its mint and public amount. */
export interface CoSignDemand {
  readonly classes: number;
  readonly withdrawal?: Readonly<{ mint: Address; amount: bigint }>;
}

export const TRANSFER_DEMAND: CoSignDemand = Object.freeze({ classes: RING_COSIGN_TRANSFERS });
export const DEPOSIT_DEMAND: CoSignDemand = Object.freeze({ classes: RING_COSIGN_DEPOSITS });

/** Mirrors Rust `require_cosigner`, the approval bit demands the signer whatever its scope. */
export function checkRingCoSigner(
  input: Readonly<{
    ringProgramId: Address;
    configured: RingCoSigner | undefined;
    supplied: SignerAccount | undefined;
    demand: CoSignDemand;
    approvalRequired: boolean;
  }>,
): void {
  const { configured } = input;
  if (configured === undefined) {
    if (input.approvalRequired) throw coSignerRequired(input, "approvalWithoutCoSigner");
    return;
  }
  if (!input.approvalRequired && !inScope(configured, input.demand)) return;
  if (input.supplied === undefined) throw coSignerRequired(input, "missing");
  if (signerAddress(input.supplied) !== configured.signer)
    throw coSignerRequired(input, "mismatch");
}

function inScope(configured: RingCoSigner, demand: CoSignDemand): boolean {
  const classes = configured.scope & demand.classes;
  if ((classes & (RING_COSIGN_TRANSFERS | RING_COSIGN_DEPOSITS)) !== 0) return true;
  const withdrawal = demand.withdrawal;
  if ((classes & RING_COSIGN_WITHDRAWALS) === 0 || withdrawal === undefined) return false;
  const threshold = configured.thresholds.find((row) => row.mint === withdrawal.mint);
  return threshold === undefined || withdrawal.amount > threshold.above;
}

function coSignerRequired(
  input: Readonly<{ ringProgramId: Address; configured: RingCoSigner | undefined }>,
  reason: "approvalWithoutCoSigner" | "missing" | "mismatch",
): RingError {
  return new RingError("RING_COSIGNER_REQUIRED", {
    details: {
      ringProgramId: input.ringProgramId,
      reason,
      ...(input.configured === undefined ? {} : { expected: input.configured.signer }),
    },
  });
}
