import type { ChainReader, TreeContext } from "../client/ports.js";
import { decodeTreeId } from "../interface/codecs/index.js";
import { treeAddress } from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { Address, RequestContext } from "../interface/types.js";
import type { TreeId } from "../transaction/utxo.js";
import { RingError } from "./error.js";

export async function resolveRingOutputTree(
  client: TreeContext & Pick<ChainReader, "getAccount">,
  outputTree: Address | undefined,
  context?: RequestContext,
): Promise<TreeContext> {
  const tree = outputTree ?? client.tree;
  const treeId = tree === client.tree ? client.treeId : await readTreeId(client, tree, context);
  if (treeAddress(treeId) !== tree)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree, treeId } });
  return { tree, treeId };
}

/** Successful ids are cached. A cancellable read is never shared across callers. */
export function ringTreeIdResolver(
  client: Pick<ChainReader, "getAccount">,
  known: readonly TreeContext[],
  context?: RequestContext,
): (tree: Address) => Promise<TreeId> {
  const ids = new Map<Address, TreeId>(known.map(({ tree, treeId }) => [tree, treeId]));
  const pending = new Map<Address, Promise<TreeId>>();
  return (tree) => {
    const cached = ids.get(tree);
    if (cached !== undefined) return Promise.resolve(cached);
    // The first caller's abort signal must not cancel another caller's lookup.
    const shared = context?.signal === undefined && context?.timeoutMs === undefined;
    const inFlight = shared ? pending.get(tree) : undefined;
    if (inFlight !== undefined) return inFlight;
    const id = readTreeId(client, tree, context).then((treeId) => {
      if (treeAddress(treeId) !== tree)
        throw new RingError("RING_TREE_MISMATCH", { details: { tree, treeId } });
      ids.set(tree, treeId);
      return treeId;
    });
    if (shared) {
      pending.set(tree, id);
      const clear = () => {
        if (pending.get(tree) === id) pending.delete(tree);
      };
      void id.then(clear, clear);
    }
    return id;
  };
}

async function readTreeId(
  client: Pick<ChainReader, "getAccount">,
  tree: Address,
  context: RequestContext | undefined,
): Promise<TreeId> {
  const account = await client.getAccount(tree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree } });
  return decodeTreeId(account.data);
}
