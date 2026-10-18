import { describe, expect, it, vi } from "vitest";

import { treeAddress } from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { readTreeHeads } from "../src/ring/policy-trees.js";
import { ringTreeIdResolver } from "../src/ring/trees.js";
import { ownedAccount } from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";

function treeWithId(treeId: number): RpcAccount {
  return ownedAccount(
    SHIELDED_POOL_PROGRAM_ID,
    treeAccount({ stateCursor: 1, written: 2, nullifierCursor: 3n, treeId }),
  );
}

describe("ringTreeIdResolver", () => {
  it("reads a tree again after a failed read", async () => {
    const tree = treeAddress(2);
    const getAccount = vi
      .fn<(address: string) => Promise<RpcAccount | undefined>>()
      .mockRejectedValueOnce(new Error("rpc down"))
      .mockResolvedValue(treeWithId(2));
    const resolve = ringTreeIdResolver({ getAccount }, []);
    await expect(resolve(tree)).rejects.toThrow("rpc down");
    await expect(resolve(tree)).resolves.toBe(2);
    await expect(resolve(tree)).resolves.toBe(2);
    expect(getAccount).toHaveBeenCalledTimes(2);
  });

  it("does not share a cancellable lookup between callers", async () => {
    const tree = treeAddress(2);
    const pending: Array<(account: RpcAccount) => void> = [];
    const getAccount = vi.fn(() => new Promise<RpcAccount>((resolve) => pending.push(resolve)));
    const controller = new AbortController();
    const resolve = ringTreeIdResolver({ getAccount }, [], { signal: controller.signal });
    const first = resolve(tree);
    const second = resolve(tree);
    expect(getAccount).toHaveBeenCalledTimes(2);
    pending[0]?.(treeWithId(2));
    pending[1]?.(treeWithId(2));
    await expect(first).resolves.toBe(2);
    await expect(second).resolves.toBe(2);
    await expect(resolve(tree)).resolves.toBe(2);
    expect(getAccount).toHaveBeenCalledTimes(2);
  });
});

describe("readTreeHeads", () => {
  it("reads the heads of the tree the caller names", async () => {
    const tree = treeAddress(1);
    const heads = await readTreeHeads(
      { getAccount: async () => treeWithId(1) },
      { tree, treeId: 1 },
      undefined,
    );
    expect(heads.stateRootIndex).toBe(1);
  });

  it("refuses an account whose tree id differs, like Rust `current_roots`", async () => {
    await expect(
      readTreeHeads(
        { getAccount: async () => treeWithId(0) },
        { tree: treeAddress(1), treeId: 1 },
        undefined,
      ),
    ).rejects.toThrow("RING_TREE_MISMATCH");
  });
});
