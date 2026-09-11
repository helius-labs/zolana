import { unsigned } from "./internal.js";
import { poseidon, rightAlign } from "./merge-utils.js";
import type { Bytes32 } from "./types.js";

/**
 * Tree slots a transact or merge proof carries in its public inputs. Every
 * proof publishes exactly this many `(id, utxo_root, nullifier_root)` slots;
 * an unused slot is all zero and sits after the used ones. Mirrors Rust
 * `zolana_interface::INPUT_TREES`.
 */
export const INPUT_TREES = 5;

/**
 * The tree id the SDK hashes under until the tree id is read from the tree
 * account. The protocol has one live tree today and it carries id 0, so
 * every wallet, sync, and builder path passes this constant.
 *
 * TODO(tree-id): resolve the tree id from the tree account.
 */
export const DEFAULT_TREE_ID = 0;

/** One public tree slot: the raw `u16` tree id with the roots the proof opens against. */
export interface TreeSlot {
  readonly id: number;
  readonly utxoRoot: Bytes32;
  readonly nullifierRoot: Bytes32;
}

const ZERO_32 = new Uint8Array(32) as Bytes32;

/** An unused slot: id and both roots are zero. */
export const ZERO_TREE_SLOT: TreeSlot = Object.freeze({
  id: 0,
  utxoRoot: ZERO_32,
  nullifierRoot: ZERO_32,
});

/** The field element a `u16` tree id enters a hash as: right-aligned big-endian. */
export function treeIdField(treeId: number): Bytes32 {
  const id = unsigned(treeId, 0xffff, "treeId");
  return rightAlign(Uint8Array.of(id >> 8, id & 0xff));
}

/** `Poseidon(tree_id, utxo_root, nullifier_root)`. Mirrors Rust `TreeSlot::hash`. */
export function treeSlotHash(slot: TreeSlot): Bytes32 {
  return poseidon([treeIdField(slot.id), slot.utxoRoot, slot.nullifierRoot]);
}

/**
 * The single public-input element the slots enter as: a right fold over the
 * slot hashes, so the on-chain verifier can start from a precomputed all-zero
 * suffix. Mirrors Rust `tree_slots_hash_chain`; takes exactly `INPUT_TREES`
 * slots.
 */
export function treeSlotsHashChain(slots: readonly TreeSlot[]): Bytes32 {
  if (slots.length !== INPUT_TREES) {
    throw new RangeError(
      `a tree slot chain takes ${String(INPUT_TREES)} slots, received ${String(slots.length)}`,
    );
  }
  const hashes = slots.map(treeSlotHash);
  let chain = hashes[INPUT_TREES - 1] as Bytes32;
  for (let index = INPUT_TREES - 2; index >= 0; index -= 1) {
    chain = poseidon([hashes[index] as Bytes32, chain]);
  }
  return chain;
}

/**
 * The slot layout of a proof: the input trees in the order the inputs
 * reference them, then zero slots. The shielded pool fills the same layout
 * from its run of input tree accounts.
 */
export function inputTreeSlots(inputTrees: readonly TreeSlot[]): readonly TreeSlot[] {
  if (inputTrees.length < 1 || inputTrees.length > INPUT_TREES) {
    throw new RangeError(
      `a proof opens against 1 to ${String(INPUT_TREES)} trees, received ${String(inputTrees.length)}`,
    );
  }
  return Object.freeze([
    ...inputTrees,
    ...Array.from({ length: INPUT_TREES - inputTrees.length }, () => ZERO_TREE_SLOT),
  ]);
}
