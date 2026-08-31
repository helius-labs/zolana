import { describe, expect, it } from "vitest";

import type { IndexerReader } from "../src/client/index.js";
import { getAddressDecoder } from "@solana/kit";

import type { Bytes32, Signature } from "../src/interface/types.js";
import { fetchTransactionSlots } from "../src/wallet/transaction-slots.js";

const SIGNATURE = "1".repeat(87) as Signature;
const filled = (byte: number) => new Uint8Array(32).fill(byte) as Bytes32;

function reader(events: readonly { leaf: bigint; tags: readonly Bytes32[] }[]) {
  return {
    getShieldedTransactionsBySignature: async (signature: Signature) => {
      expect(signature).toBe(SIGNATURE);
      return {
        context: { slot: 1n },
        transactions: events.map((event, eventIndex) => ({
          eventIndex,
          transaction: {
            outputSlots: event.tags.map((viewTag, slotIndex) => ({
              viewTag,
              outputContext: { leafIndex: event.leaf + BigInt(slotIndex) },
            })),
          },
        })),
      };
    },
  } as object as Pick<IndexerReader, "getShieldedTransactionsBySignature">;
}

describe("owner tags", () => {
  it("reads a tag per output slot", async () => {
    const { ownerTags: tags } = await fetchTransactionSlots({
      rpc: reader([{ leaf: 0n, tags: [filled(7), filled(8)] }]),
      signature: SIGNATURE,
    });

    const base58 = getAddressDecoder();
    expect(tags.size).toBe(2);
    expect(tags.get(0)).toBe(base58.decode(filled(7)));
    expect(tags.get(1)).toBe(base58.decode(filled(8)));
  });

  it("picks the event holding the leaf, not the first one", async () => {
    const { ownerTags: tags } = await fetchTransactionSlots({
      rpc: reader([
        { leaf: 0n, tags: [filled(1)] },
        { leaf: 50n, tags: [filled(2)] },
      ]),
      signature: SIGNATURE,
      leafIndex: 50n,
    });

    expect(tags.size).toBe(1);
    expect(tags.get(0)).toBe(getAddressDecoder().decode(filled(2)));
  });
});
