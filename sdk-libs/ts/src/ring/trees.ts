import type { ChainReader, TreeContext } from "../client/ports.js";
import { decodeTreeId } from "../interface/codecs/index.js";
import { treeAddress } from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { Address, RequestContext } from "../interface/types.js";
import { RingError } from "./error.js";

export async function resolveRingOutputTree(
  client: TreeContext & Pick<ChainReader, "getAccount">,
  outputTree: Address | undefined,
  context?: RequestContext,
): Promise<TreeContext> {
  const tree = outputTree ?? client.tree;
  let treeId = client.treeId;
  if (tree !== client.tree) {
    const account = await client.getAccount(tree, context);
    if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
      throw new RingError("RING_TREE_MISMATCH", { details: { tree } });
    treeId = decodeTreeId(account.data);
  }
  if (treeAddress(treeId) !== tree)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree, treeId } });
  return { tree, treeId };
}
