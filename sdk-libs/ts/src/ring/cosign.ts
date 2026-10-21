import type { Address } from "@solana/kit";

import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { SettlementTransfer } from "../transaction/instructions/transact.js";

import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingCoSigner,
} from "./codecs.js";
import { RingError } from "./error.js";

/** The operation classes of one ring operation and every mint it withdraws with its total. */
export interface CoSignDemand {
  readonly classes: number;
  /** Each withdrawn mint once, SOL under the zero address. */
  readonly withdrawals: readonly Readonly<{ mint: Address; amount: bigint }>[];
}

export const TRANSFER_DEMAND: CoSignDemand = Object.freeze({
  classes: RING_COSIGN_TRANSFERS,
  withdrawals: Object.freeze([]),
});
export const DEPOSIT_DEMAND: CoSignDemand = Object.freeze({
  classes: RING_COSIGN_DEPOSITS,
  withdrawals: Object.freeze([]),
});

/** A transact is a transfer, each public leg adds its class, Rust `classes` and `withdrawals`. */
export function transactDemand(transfers: readonly SettlementTransfer[]): CoSignDemand {
  let classes = RING_COSIGN_TRANSFERS;
  const totals = new Map<Address, bigint>();
  for (const transfer of transfers) {
    classes |= transfer.isDeposit ? RING_COSIGN_DEPOSITS : RING_COSIGN_WITHDRAWALS;
    if (transfer.isDeposit) continue;
    const mint = transfer.kind === "sol" ? SOL_MINT : transfer.mint;
    totals.set(mint, (totals.get(mint) ?? 0n) + transfer.amount);
  }
  return Object.freeze({
    classes,
    withdrawals: Object.freeze(
      [...totals].map(([mint, amount]) => Object.freeze({ mint, amount })),
    ),
  });
}

/** Rust `RingProgramConfig::demanded_co_signer`, the approval bit demands the co-signer whatever its scope. */
export function demandedCoSigner(
  input: Readonly<{
    configured: RingCoSigner | undefined;
    approvalRequired: boolean;
    transfers: readonly SettlementTransfer[];
    /** Empty on the anonymous and delegate rails. */
    ownerSigners: readonly Address[];
  }>,
): Address | undefined {
  const { configured } = input;
  if (input.approvalRequired && configured === undefined)
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { reason: "approvalWithoutCoSigner" },
    });
  const demanded =
    configured !== undefined &&
    (input.approvalRequired || inScope(configured, transactDemand(input.transfers)))
      ? configured.signer
      : undefined;
  // Rust `CoSignerIsOwner`, dual control needs a second key.
  if (demanded !== undefined && input.ownerSigners.includes(demanded))
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { reason: "coSignerIsOwner", expected: demanded },
    });
  return demanded;
}

/** Mirrors Rust `demanded_co_signer`, the supplied signer once its scope or the approval bit demands it. */
export function checkRingCoSigner(
  input: Readonly<{
    ringProgramId: Address;
    configured: RingCoSigner | undefined;
    supplied: SignerAccount | undefined;
    demand: CoSignDemand;
    approvalRequired: boolean;
  }>,
): SignerAccount | undefined {
  const { configured } = input;
  if (configured === undefined) {
    if (input.approvalRequired) throw coSignerRequired(input, "approvalWithoutCoSigner");
    return undefined;
  }
  if (!input.approvalRequired && !inScope(configured, input.demand)) return undefined;
  if (input.supplied === undefined) throw coSignerRequired(input, "missing");
  if (signerAddress(input.supplied) !== configured.signer)
    throw coSignerRequired(input, "mismatch");
  return input.supplied;
}

/** A shared class demands the co-signer, a withdrawal only above its mint's threshold or without a row. */
function inScope(configured: RingCoSigner, demand: CoSignDemand): boolean {
  const classes = configured.scope & demand.classes;
  if ((classes & (RING_COSIGN_TRANSFERS | RING_COSIGN_DEPOSITS)) !== 0) return true;
  if ((classes & RING_COSIGN_WITHDRAWALS) === 0) return false;
  return demand.withdrawals.some((withdrawal) => {
    const threshold = configured.thresholds.find((row) => row.mint === withdrawal.mint);
    return threshold === undefined || withdrawal.amount > threshold.amount;
  });
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
