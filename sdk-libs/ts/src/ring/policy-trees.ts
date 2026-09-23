import type { ChainReader, ProofReader } from "../client/ports.js";
import {
  RING_ANSWER_SLOTS,
  RING_NULLIFIER_PATH_LENGTH,
  RING_STATE_PATH_LENGTH,
} from "../client/prover/types.js";
import type { MerkleProof, NonInclusionProof } from "../client/rpc.js";
import { decodeTreeHeadRoots, decodeTreeId } from "../interface/codecs/index.js";
import { nullifierPdaAddress } from "../interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import { INPUT_TREES, type TreeSlot } from "../interface/tree-slot.js";
import type {
  Address,
  Bytes32,
  RequestContext,
  TreeContext,
  TreeHeadRoots,
} from "../interface/types.js";
import { ZERO_32 } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";
import type { LeafTree } from "./policy.js";

/** Mirrors Rust `head_roots`, the roots a proof binds when no indexer answer fixed them. */
export async function readTreeHeads(
  client: Pick<ChainReader, "getAccount">,
  tree: LeafTree,
  context: RequestContext | undefined,
): Promise<TreeHeadRoots> {
  const account = await client.getAccount(tree.tree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID) {
    throw new RingError("RING_POLICY_TREE_INVALID", { details: { tree: tree.tree } });
  }
  let found: number;
  let heads: TreeHeadRoots;
  try {
    found = decodeTreeId(account.data);
    heads = decodeTreeHeadRoots(account.data);
  } catch (cause) {
    throw new RingError("RING_POLICY_TREE_INVALID", { details: { tree: tree.tree }, cause });
  }
  if (found !== tree.treeId) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: tree.tree, expected: tree.treeId, found },
    });
  }
  return heads;
}

/** An indexer proof is trusted for one leaf of `tree` at full height only. */
export function checkedEntryProof<P extends MerkleProof | NonInclusionProof>(
  proof: P | undefined,
  expected: Readonly<{ tree: Address; leaf: Bytes32; pathLength: number }>,
): P {
  if (
    proof === undefined ||
    proof.merkleContext.tree !== expected.tree ||
    !equalBytes(proof.leaf, expected.leaf) ||
    proof.path.length !== expected.pathLength
  ) {
    throw new RingError("RING_ENTRY_PROOF_INCOMPLETE", { details: { tree: expected.tree } });
  }
  return proof;
}

export interface PolicyTreeFact {
  /** Absent for an unclaimed address, its absence is read in the address tree. */
  readonly holder?: LeafTree;
  /** The live leaf, absent for an unclaimed address. */
  readonly state?: Bytes32;
  /** The live leaf's nullifier or the unclaimed address. */
  readonly absence: Bytes32;
}

export interface ProvenPolicyTrees {
  readonly trees: readonly LeafTree[];
  readonly slots: readonly TreeSlot[];
  readonly contexts: readonly TreeContext[];
  readonly factSlots: readonly number[];
  readonly states: readonly (MerkleProof | undefined)[];
  readonly absences: readonly NonInclusionProof[];
}

export type PolicyTreeClient = Pick<ChainReader, "getAccount"> &
  Pick<ProofReader, "getMerkleProofs" | "getNonInclusionProofs">;

/** Mirrors Rust `PolicyTrees`, the address tree leads when an absence or no fact reads it. */
export function planPolicyTrees(
  addressTree: LeafTree,
  holders: readonly (LeafTree | undefined)[],
): Readonly<{ trees: readonly LeafTree[]; factSlots: readonly number[] }> {
  const trees: LeafTree[] = [];
  const slotOf = (tree: LeafTree): number => {
    const known = trees.findIndex((candidate) => candidate.tree === tree.tree);
    if (known >= 0) return known;
    trees.push(tree);
    return trees.length - 1;
  };
  if (holders.length === 0 || holders.includes(undefined)) slotOf(addressTree);
  const factSlots = holders.map((holder) => slotOf(holder ?? addressTree));
  if (trees.length > INPUT_TREES) {
    throw new RingError("RING_TOO_MANY_POLICY_TREES", {
      details: { trees: trees.length, maximum: INPUT_TREES },
    });
  }
  return Object.freeze({ trees: Object.freeze(trees), factSlots: Object.freeze(factSlots) });
}

/** Every tree's leaves in one call per proof kind, each kind opening against one root. */
export async function provePolicyTrees(
  input: Readonly<{
    client: PolicyTreeClient;
    addressTree: LeafTree;
    facts: readonly PolicyTreeFact[];
  }>,
  context?: RequestContext,
): Promise<ProvenPolicyTrees> {
  const { trees, factSlots } = planPolicyTrees(
    input.addressTree,
    input.facts.map((fact) => fact.holder),
  );
  const states: (MerkleProof | undefined)[] = input.facts.map(() => undefined);
  const absences: (NonInclusionProof | undefined)[] = input.facts.map(() => undefined);
  const reads = await Promise.all(
    trees.map(async ({ tree, treeId }, slot) => {
      const members = input.facts.flatMap((fact, index) =>
        factSlots[index] === slot ? [{ fact, index }] : [],
      );
      const live = members.flatMap(({ fact, index }) =>
        fact.state === undefined ? [] : [{ leaf: fact.state, index }],
      );
      const [stateProofs, absenceProofs] = await Promise.all([
        live.length === 0
          ? []
          : input.client
              .getMerkleProofs(
                tree,
                live.map(({ leaf }) => leaf),
                undefined,
                context,
              )
              .then((response) => response.proofs),
        members.length === 0
          ? []
          : input.client
              .getNonInclusionProofs(
                tree,
                members.map(({ fact }) => fact.absence),
                undefined,
                context,
              )
              .then((response) => response.proofs),
      ]);
      if (stateProofs.length !== live.length || absenceProofs.length !== members.length) {
        throw new RingError("RING_ENTRY_PROOF_INCOMPLETE", { details: { tree } });
      }
      live.forEach(({ leaf, index }, position) => {
        states[index] = checkedEntryProof(stateProofs[position], {
          tree,
          leaf,
          pathLength: RING_STATE_PATH_LENGTH,
        });
      });
      members.forEach(({ fact, index }, position) => {
        absences[index] = checkedEntryProof(absenceProofs[position], {
          tree,
          leaf: fact.absence,
          pathLength: RING_NULLIFIER_PATH_LENGTH,
        });
      });
      const roots = await treeRoots(
        {
          state: singleRoot(live.map(({ index }) => states[index])),
          nullifier: singleRoot(members.map(({ index }) => absences[index])),
        },
        () => readTreeHeads(input.client, { tree, treeId }, context),
      );
      return {
        slot: Object.freeze({
          id: treeId,
          utxoRoot: roots.state.value,
          nullifierRoot: roots.nullifier.value,
        }),
        context: Object.freeze({
          utxoTreeRootIndex: roots.state.index,
          nullifierTreeRootIndex: roots.nullifier.index,
        }),
      };
    }),
  );
  return Object.freeze({
    trees,
    slots: Object.freeze(reads.map((read) => read.slot)),
    contexts: Object.freeze(reads.map((read) => read.context)),
    factSlots,
    states: Object.freeze(states),
    absences: Object.freeze(
      absences.map((proof) => {
        if (proof === undefined) throw new RingError("RING_ENTRY_PROOF_INCOMPLETE");
        return proof;
      }),
    ),
  });
}

interface HistoryRoot {
  readonly value: Bytes32;
  readonly index: number;
}

/** A kind no fact touched binds the tree's head root. */
async function treeRoots(
  fixed: Readonly<{ state: HistoryRoot | undefined; nullifier: HistoryRoot | undefined }>,
  readHeads: () => Promise<TreeHeadRoots>,
): Promise<Readonly<{ state: HistoryRoot; nullifier: HistoryRoot }>> {
  const { state, nullifier } = fixed;
  if (state !== undefined && nullifier !== undefined) return { state, nullifier };
  const heads = await readHeads();
  return {
    state: state ?? { value: heads.stateRoot, index: heads.stateRootIndex },
    nullifier: nullifier ?? { value: heads.nullifierRoot, index: heads.nullifierRootIndex },
  };
}

/** One call proves every leaf against one root. */
function singleRoot(
  proofs: readonly (MerkleProof | NonInclusionProof | undefined)[],
): HistoryRoot | undefined {
  const [first] = proofs;
  if (first === undefined) return undefined;
  if (
    proofs.some(
      (proof) =>
        proof === undefined ||
        proof.rootIndex !== first.rootIndex ||
        !equalBytes(proof.root, first.root),
    )
  ) {
    throw new RingError("RING_POLICY_ROOT_MISMATCH");
  }
  return { value: first.root, index: first.rootIndex };
}

/** Mirrors Rust `RevocationTargets::verify`, one empty nullifier PDA per nonzero target under its policy tree. */
export async function revocationPdaAddresses(
  input: Readonly<{
    policyTrees: readonly Address[];
    targets: readonly Bytes32[];
    treeIndexes: readonly number[];
  }>,
): Promise<readonly Address[]> {
  if (
    input.targets.length !== RING_ANSWER_SLOTS ||
    input.treeIndexes.length !== RING_ANSWER_SLOTS
  ) {
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED", {
      details: { revocationTargets: input.targets.length },
    });
  }
  return Promise.all(
    input.targets.flatMap((target, slot) => {
      const index = input.treeIndexes[slot] ?? 0;
      if (equalBytes(target, ZERO_32)) {
        if (index !== 0) throw revocationTreeIndexInvalid(slot);
        return [];
      }
      const tree = input.policyTrees[index];
      if (tree === undefined) throw revocationTreeIndexInvalid(slot);
      return [nullifierPdaAddress(tree, target)];
    }),
  );
}

function revocationTreeIndexInvalid(slot: number): RingError {
  return new RingError("RING_POLICY_SHAPE_UNSUPPORTED", {
    details: { reason: "revocationTreeIndex", slot },
  });
}
