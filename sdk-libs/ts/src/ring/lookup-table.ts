import {
  fetchMaybeAddressLookupTable,
  findAddressLookupTablePda,
  getCreateLookupTableInstruction,
  getExtendLookupTableInstruction,
} from "@solana-program/address-lookup-table";
import { createNoopSigner, type Address, type Transaction } from "@solana/kit";

import type { BlockhashProvider, ChainReader, KitRpcAccess, TreeContext } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import type { RequestContext } from "../interface/types.js";

import { fetchRingConfigs } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import {
  ringLookupTableAddresses,
  ringSettlementStatics,
  type RingTransactTrees,
} from "./instructions.js";

export interface RingLookupTable {
  readonly transaction: Transaction;
  readonly address: Address;
  /** The table is usable from the slot after this one. */
  readonly slot: bigint;
}

export type RingLookupTableReader = KitRpcAccess;
export type RingLookupTableClient = RingLookupTableReader &
  TreeContext &
  BlockhashProvider &
  Pick<ChainReader, "getAccount">;

/** One table serves every transact over the same ring and trees. */
export async function buildRingLookupTableTransaction(
  input: Readonly<{
    client: RingLookupTableClient;
    ringProgramId: Address;
    feePayer: Address;
    tree?: Address;
    outputTree?: Address;
  }>,
  context?: RequestContext,
): Promise<RingLookupTable> {
  try {
    const trees = await ringTransactTrees(input, context);
    const [addresses, slot, lifetime] = await Promise.all([
      ringLookupTableAddresses({ ringProgramId: input.ringProgramId, trees }),
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
      addresses: [...new Set([...addresses, ...ringSettlementStatics()])],
    });
    return Object.freeze({
      transaction: compileUnsignedTransaction({
        feePayer: input.feePayer,
        lifetime,
        instructions: [create, extend],
      }),
      address: address[0],
      slot: recentSlot,
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_LOOKUP_TABLE", cause);
  }
}

export async function fetchRingLookupTable(
  input: Readonly<{
    client: RingLookupTableReader;
    ringProgramId: Address;
    address: Address;
    trees: RingTransactTrees;
  }>,
): Promise<readonly Address[]> {
  const [table, required] = await Promise.all([
    fetchMaybeAddressLookupTable(input.client.solanaRpc, input.address, {
      commitment: input.client.commitment,
    }),
    ringLookupTableAddresses({ ringProgramId: input.ringProgramId, trees: input.trees }),
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

async function ringTransactTrees(
  input: Readonly<{
    client: RingLookupTableClient;
    ringProgramId: Address;
    tree?: Address;
    outputTree?: Address;
  }>,
  context: RequestContext | undefined,
): Promise<RingTransactTrees> {
  const tree = input.tree ?? input.client.tree;
  const outputTree = input.outputTree ?? tree;
  const configs = await fetchRingConfigs(input.client, input.ringProgramId, context);
  return configs.hasPolicy
    ? { tree, outputTree, hasPolicy: true, entriesTree: configs.policy.entriesTree }
    : { tree, outputTree, hasPolicy: false };
}
