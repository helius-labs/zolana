import {
  fetchMaybeAddressLookupTable,
  findAddressLookupTablePda,
  getCreateLookupTableInstruction,
  getExtendLookupTableInstruction,
} from "@solana-program/address-lookup-table";
import { createNoopSigner, type Address, type Transaction } from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { buildUnsignedTransaction } from "../client/kit.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type { RequestContext } from "../interface/types.js";

import { RingError, wrapRingError } from "./error.js";
import { ringLookupTableAddresses } from "./instructions.js";

export interface RingLookupTable {
  readonly transaction: Transaction;
  readonly address: Address;
  /** The table is usable from the slot after this one. */
  readonly slot: bigint;
}

/** One table serves every transact of the ring and tree pair. */
export async function buildRingLookupTableTransaction(
  input: Readonly<{
    client: ZolanaClient;
    ringProgramId: Address;
    feePayer: Address;
    tree?: Address;
    /** The config tier. False builds a table without the policy_config and entries_tree entries. */
    hasPolicy?: boolean;
  }>,
  context?: RequestContext,
): Promise<RingLookupTable> {
  try {
    const tree = input.tree ?? input.client.tree;
    const [addresses, slot, lifetime] = await Promise.all([
      ringLookupTableAddresses({
        ringProgramId: input.ringProgramId,
        tree,
        ...(input.hasPolicy === undefined ? {} : { hasPolicy: input.hasPolicy }),
      }),
      // The create instruction checks the slot against SlotHashes, so it must be finalized.
      input.client.solanaRpc.getSlot({ commitment: "finalized" }).send(),
      input.client.getLatestBlockhash(context),
    ]);
    const recentSlot = BigInt(slot);
    const authority = createNoopSigner(input.feePayer);
    const address = await findAddressLookupTablePda({ authority: input.feePayer, recentSlot });
    const create = getCreateLookupTableInstruction({
      address,
      authority: input.feePayer,
      payer: authority,
      recentSlot,
    });
    const extend = getExtendLookupTableInstruction({
      address: address[0],
      authority,
      payer: authority,
      addresses: [...addresses],
    });
    return Object.freeze({
      transaction: checkedTransactionSize(
        buildUnsignedTransaction({
          feePayer: input.feePayer,
          lifetime,
          instructions: [create, extend],
        }),
      ),
      address: address[0],
      slot: recentSlot,
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_LOOKUP_TABLE", cause);
  }
}

export async function fetchRingLookupTable(
  input: Readonly<{
    client: ZolanaClient;
    ringProgramId: Address;
    address: Address;
    tree?: Address;
    outputTree?: Address;
    entriesTree?: Address;
    /** The config tier. False drops the policy_config and entries_tree entries. */
    hasPolicy?: boolean;
  }>,
): Promise<readonly Address[]> {
  const tree = input.tree ?? input.client.tree;
  const [table, required] = await Promise.all([
    fetchMaybeAddressLookupTable(input.client.solanaRpc, input.address, {
      commitment: input.client.commitment,
    }),
    ringLookupTableAddresses({
      ringProgramId: input.ringProgramId,
      tree,
      ...(input.outputTree === undefined ? {} : { outputTree: input.outputTree }),
      ...(input.entriesTree === undefined ? {} : { entriesTree: input.entriesTree }),
      ...(input.hasPolicy === undefined ? {} : { hasPolicy: input.hasPolicy }),
    }),
  ]);
  if (!table.exists) {
    throw new RingError("RING_LOOKUP_TABLE_NOT_FOUND", { details: { address: input.address } });
  }
  const held = new Set<string>(table.data.addresses);
  const missing = required.filter((address) => !held.has(address));
  if (missing.length > 0) {
    throw new RingError("RING_LOOKUP_TABLE_INCOMPLETE", {
      details: { address: input.address, missing },
    });
  }
  return Object.freeze([...table.data.addresses]);
}
