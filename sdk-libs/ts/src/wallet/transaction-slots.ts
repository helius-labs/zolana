import { getAddressDecoder } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import type { Address, RequestContext, Signature } from "../interface/types.js";

type SignatureReader = Pick<IndexerReader, "getShieldedTransactionsBySignature">;

const addressDecoder = getAddressDecoder();

export interface TransactionSlots {
  /** Owner tag by output slot index. */
  readonly ownerTags: ReadonlyMap<number, Address>;
  /** Tree leaf by output slot index, which ties a slot to a wallet's UTXO. */
  readonly leaves: ReadonlyMap<number, bigint>;
}

/**
 * Readable without a viewing key. The tag matching the fee payer is the
 * sender's, the rest are recipients'.
 */
export async function fetchTransactionSlots(
  input: Readonly<{ rpc: SignatureReader; signature: Signature; leafIndex?: bigint }>,
  context?: RequestContext,
): Promise<TransactionSlots> {
  const { transactions } = await input.rpc.getShieldedTransactionsBySignature(
    input.signature,
    undefined,
    context,
  );
  // One signature can carry several events. The leaf index picks the right one.
  const event =
    input.leafIndex === undefined
      ? transactions[0]
      : (transactions.find(({ transaction }) =>
          transaction.outputSlots.some((slot) => slot.outputContext.leafIndex === input.leafIndex),
        ) ?? transactions[0]);
  const ownerTags = new Map<number, Address>();
  const leaves = new Map<number, bigint>();
  event?.transaction.outputSlots.forEach((slot, slotIndex) => {
    ownerTags.set(slotIndex, addressDecoder.decode(slot.viewTag));
    leaves.set(slotIndex, slot.outputContext.leafIndex);
  });
  return { ownerTags, leaves };
}
