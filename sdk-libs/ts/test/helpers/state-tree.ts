import { STATE_TREE_HEIGHT } from "../../src/client/prover/assembly.js";
import { poseidon } from "../../src/hasher/index.js";
import type { Bytes32 } from "../../src/interface/types.js";

/** A state tree holding the given leaves, every other leaf empty, as the program hashes it. */
export interface StateTree {
  readonly root: Bytes32;
  /** The siblings of leaf `index`, the leaf's own level first. */
  path(index: number): Bytes32[];
}

export function stateTree(leaves: readonly Uint8Array[]): StateTree {
  return stateTreeAt(new Map(leaves.map((leaf, index) => [index, leaf])));
}

/** `leaves` by leaf index. */
export function stateTreeAt(leaves: ReadonlyMap<number, Uint8Array>): StateTree {
  const empty: Uint8Array[] = [new Uint8Array(32)];
  for (let height = 0; height < STATE_TREE_HEIGHT; height++) {
    const below = empty[height] ?? new Uint8Array(32);
    empty.push(poseidon([below, below]));
  }
  const levels: Map<number, Uint8Array>[] = [new Map(leaves)];
  for (let height = 0; height < STATE_TREE_HEIGHT; height++) {
    const below = levels[height] ?? new Map<number, Uint8Array>();
    const blank = empty[height] ?? new Uint8Array(32);
    const above = new Map<number, Uint8Array>();
    for (const index of below.keys()) {
      const parent = index >> 1;
      if (!above.has(parent))
        above.set(
          parent,
          poseidon([below.get(parent * 2) ?? blank, below.get(parent * 2 + 1) ?? blank]),
        );
    }
    levels.push(above);
  }
  const root = levels[STATE_TREE_HEIGHT]?.get(0) ?? empty[STATE_TREE_HEIGHT] ?? new Uint8Array(32);
  return Object.freeze({
    root: root as Bytes32,
    path: (index: number) =>
      levels
        .slice(0, STATE_TREE_HEIGHT)
        .map(
          (level, height) =>
            (level.get((index >> height) ^ 1) ?? empty[height] ?? new Uint8Array(32)) as Bytes32,
        ),
  });
}
