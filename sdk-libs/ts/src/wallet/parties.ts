import { getAddressDecoder } from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import type { Address, RequestContext, Signature } from "../interface/types.js";

type SignatureReader = Pick<ZolanaClient, "getShieldedTransactionsBySignature">;

const addressDecoder = getAddressDecoder();

/** Owner tag per output slot index, as base58. */
export type OwnerTags = ReadonlyMap<number, Address>;

/**
 * Readable without a viewing key. The tag matching the fee payer is the sender's,
 * the rest are recipients'.
 */
export async function fetchOwnerTags(
  input: Readonly<{ rpc: SignatureReader; signature: Signature; leafIndex?: bigint }>,
  context?: RequestContext,
): Promise<OwnerTags> {
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
  const tags = new Map<number, Address>();
  event?.transaction.outputSlots.forEach((slot, slotIndex) => {
    tags.set(slotIndex, addressDecoder.decode(slot.viewTag));
  });
  return tags;
}
