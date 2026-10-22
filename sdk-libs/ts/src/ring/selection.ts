import type { TreeContext } from "../client/ports.js";
import type { SpendSelectionErrors } from "../flows/select.js";
import { InterfaceError } from "../interface/errors.js";
import { TRANSACTION_SIZE_LIMIT } from "../interface/transaction-size.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { WalletUtxo } from "../transaction/wallet/state.js";

import { RingError } from "./error.js";
import type { ProvenRingTransfer } from "./pipeline.js";

/** Ring notes are spent from the client's tree, the stored nullifier was derived for that tree. */
export function ringProofInput(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  client: TreeContext,
): ProofInputUtxo {
  if (entry.outputContext.tree !== client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: entry.outputContext.tree, clientTree: client.tree },
    });
  }
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierPublicKey: owner.nullifierPublicKey,
    nullifier: entry.nullifier,
    treeId: client.treeId,
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
  });
}

export function ringIntentMismatch(field: string): RingError {
  return new RingError("RING_INTENT_MISMATCH", { details: { field } });
}

/** @internal */
export const ringSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { selected: eligible, maximum: max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
};

/** @internal A spend past one version 1 transaction is refused before approval as too many notes. */
export async function provenWithinTransaction(
  selected: number,
  prove: () => Promise<ProvenRingTransfer>,
): Promise<ProvenRingTransfer> {
  try {
    return await prove();
  } catch (cause) {
    if (!(cause instanceof InterfaceError) || cause.code !== "INTERFACE_TRANSACTION_TOO_LARGE")
      throw cause;
    // Largest notes first, no cover of fewer notes exists.
    throw new RingError("RING_TOO_MANY_INPUTS", {
      details: { selected, size: cause.details?.["size"], limit: TRANSACTION_SIZE_LIMIT },
      cause,
    });
  }
}
