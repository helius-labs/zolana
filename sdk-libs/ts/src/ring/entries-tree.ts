import type { ChainReader } from "../client/ports.js";
import type { MerkleProof, NonInclusionProof } from "../client/rpc.js";
import { decodeTreeHeadRoots } from "../interface/codecs/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { Address, Bytes32, RequestContext, TreeHeadRoots } from "../interface/types.js";
import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";

/** Mirrors Rust `head_roots`, the roots a proof binds when no indexer answer fixed them. */
export async function readEntriesTreeHeads(
  client: Pick<ChainReader, "getAccount">,
  entriesTree: Address,
  context: RequestContext | undefined,
): Promise<TreeHeadRoots> {
  const account = await client.getAccount(entriesTree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID) {
    throw new RingError("RING_ENTRIES_TREE_INVALID", { details: { entriesTree } });
  }
  try {
    return decodeTreeHeadRoots(account.data);
  } catch (cause) {
    throw new RingError("RING_ENTRIES_TREE_INVALID", { details: { entriesTree }, cause });
  }
}

/** An indexer proof is trusted for one leaf of the entries tree at full height only. */
export function checkedEntryProof<P extends MerkleProof | NonInclusionProof>(
  proof: P | undefined,
  expected: Readonly<{ entriesTree: Address; leaf: Bytes32; pathLength: number }>,
): P {
  if (
    proof === undefined ||
    proof.merkleContext.tree !== expected.entriesTree ||
    !equalBytes(proof.leaf, expected.leaf) ||
    proof.path.length !== expected.pathLength
  ) {
    throw new RingError("RING_ENTRY_PROOF_INCOMPLETE", {
      details: { entriesTree: expected.entriesTree },
    });
  }
  return proof;
}
