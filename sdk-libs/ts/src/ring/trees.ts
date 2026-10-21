import type { ChainReader, TreeContext } from "../client/ports.js";
import { decodeTreeId, decodeTreePaused, decodeUtxoRoot } from "../interface/codecs/index.js";
import { treeAddress } from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { equal } from "../transaction/internal.js";
import type { TreeId } from "../transaction/utxo.js";
import { RingError } from "./error.js";

/** The first-contact root an anonymous audit proof binds, Rust `BoundAnchor`. */
export interface BoundAnchor {
  readonly tree: Address;
  readonly rootIndex: number;
  readonly root: Bytes32;
}

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

/** Rust `BoundAnchor::holds`, the program reads the root at the index of an unpaused tree. */
export async function anchorHolds(
  client: Pick<ChainReader, "getAccount">,
  anchor: BoundAnchor,
  context: RequestContext | undefined,
): Promise<boolean> {
  const data = await treeData(client, anchor.tree, context);
  if (decodeTreePaused(data))
    throw new RingError("RING_ANCHOR_INVALID", {
      details: { reason: "paused", tree: anchor.tree },
    });
  const held = decodeUtxoRoot(data, anchor.rootIndex);
  return held !== undefined && equal(held, anchor.root);
}

async function readTreeId(
  client: Pick<ChainReader, "getAccount">,
  tree: Address,
  context: RequestContext | undefined,
): Promise<TreeId> {
  return decodeTreeId(await treeData(client, tree, context));
}

async function treeData(
  client: Pick<ChainReader, "getAccount">,
  tree: Address,
  context: RequestContext | undefined,
): Promise<Uint8Array> {
  const account = await client.getAccount(tree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree } });
  return account.data;
}
