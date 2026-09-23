import type {
  Address,
  Bytes32,
  MergeTransactInstructionData,
  RequestContext,
} from "../../interface/types.js";
import { mergeExternalDataHash } from "../../interface/codecs/index.js";
import { InstructionTag } from "../../interface/program.js";
import { treeAddress } from "../../interface/pda/index.js";
import { inputTreeSlots, treeIdField, type TreeSlot } from "../../interface/tree-slot.js";
import { MERGE_INPUTS, PreparedMerge } from "../../transaction/instructions/builders.js";

import type { ProofReader, IndexedProofInputs, PreparedMergeInputs } from "../ports.js";
import { ClientError, fromClientCause } from "../error.js";
import {
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  field,
  hashChain4,
  poseidon,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import {
  createDummyTransferInput,
  createOutput,
  createRealInput,
  prepareInput,
  resolvedPublicInputHash,
  treeSlotFields,
  validateSpendProof,
} from "./assembly.js";
import type { Field, MergeInputs, TransferInput } from "./types.js";

export interface MergeAssembly {
  readonly proverInputs: MergeInputs;
  readonly expiryUnixTs: bigint;
  readonly outputHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndex: number;
  readonly nullifierTreeRootIndex: number;
  readonly privateTxHash: Bytes32;
  readonly publicInputHash: Bytes32;
  /// Recomputed on-chain from the instruction; surfaced so the caller need not
  /// re-derive it.
  readonly externalDataHash: Bytes32;
  readonly eddsaOwner: boolean;
  instructionData(proof: MergeTransactInstructionData["proof"]): MergeTransactInstructionData;
}

export async function assembleMerge(
  prepared: PreparedMerge,
  indexer: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">,
  tree: Address,
  context?: RequestContext,
): Promise<MergeAssembly> {
  try {
    validatePreparedMerge(prepared);
    const dummyNullifiers = prepared.dummyNullifiers();
    const [proofs, dummyResponse] = await Promise.all([
      indexer.getInputMerkleProofs(prepared.inputUtxoHashes(), undefined, context),
      dummyNullifiers.length === 0
        ? Promise.resolve(undefined)
        : indexer.getNonInclusionProofs(tree, dummyNullifiers, undefined, context),
    ]);
    return assembleMergeUnchecked(prepared, proofs, dummyResponse?.proofs ?? [], tree);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

export function assembleMergeWithProofs(
  prepared: PreparedMerge,
  proofs: readonly SpendProof[],
  tree: Address,
  dummyNullifierProofs: readonly NonInclusionProof[] = [],
): MergeAssembly {
  try {
    return assembleMergeUnchecked(prepared, proofs, dummyNullifierProofs, tree);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

/** The one tree slot a merge opens against, and the root positions its instruction references. */
interface MergeInputTree {
  readonly slot: TreeSlot;
  readonly utxoRootIndex: number;
  readonly nullifierRootIndex: number;
}

function assembleMergeUnchecked(
  prepared: PreparedMerge,
  proofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  tree: Address,
): MergeAssembly {
  validateMergeTree(prepared, tree);
  const realInputs = prepared.inputs.filter((input) => !input.isDummy());
  if (proofs.length !== realInputs.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: { expected: realInputs.length, state: proofs.length, nullifier: proofs.length },
    });
  }
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const dummyNullifiers = prepared.dummyNullifiers();
  if (dummyNullifierProofs.length !== dummyNullifiers.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: {
        expected: dummyNullifiers.length,
        state: 0,
        nullifier: dummyNullifierProofs.length,
      },
    });
  }
  const inputs: TransferInput[] = [];
  let inputTree: MergeInputTree | undefined;
  let proofIndex = 0;
  let dummyIndex = 0;
  for (const [index, input] of prepared.inputs.entries()) {
    if (input.isDummy()) {
      if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");
      const nullifier = dummyNullifiers[dummyIndex];
      const proof = dummyNullifierProofs[dummyIndex++];
      if (!nullifier || !proof) {
        throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
          details: { index: dummyIndex - 1 },
        });
      }
      if (!equal(proof.leaf, nullifier)) {
        throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
          details: { index: dummyIndex - 1 },
        });
      }
      if (proof.merkleContext.tree !== tree) {
        throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
          details: { proofTree: proof.merkleContext.tree, submitTree: tree },
        });
      }
      checkNullifierRoot(inputTree, proof, index);
      const converted = createDummyTransferInput(input, proof, nullifier);
      inputs.push(converted);
      continue;
    }
    const proof = proofs[proofIndex];
    if (!proof) {
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
        details: { index: proofIndex },
      });
    }
    validateSpendProof(input, proof, proofIndex);
    if (proof.state.merkleContext.tree !== tree) {
      throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
        details: {
          proofTree: proof.state.merkleContext.tree,
          submitTree: tree,
        },
      });
    }
    if (proof.nullifier.merkleContext.tree !== tree) {
      throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
        details: {
          proofTree: proof.nullifier.merkleContext.tree,
          submitTree: tree,
        },
      });
    }
    if (inputTree === undefined) {
      inputTree = Object.freeze({
        slot: Object.freeze({
          id: prepared.inputTreeId,
          utxoRoot: new Uint8Array(proof.state.root) as Bytes32,
          nullifierRoot: new Uint8Array(proof.nullifier.root) as Bytes32,
        }),
        utxoRootIndex: proof.state.rootIndex,
        nullifierRootIndex: proof.nullifier.rootIndex,
      });
    } else {
      if (
        !equal(proof.state.root, inputTree.slot.utxoRoot) ||
        proof.state.rootIndex !== inputTree.utxoRootIndex
      ) {
        throw new ClientError("CLIENT_INPUT_TREE_ROOT_MISMATCH", { details: { index } });
      }
      checkNullifierRoot(inputTree, proof.nullifier, index);
    }
    // A P256 owner contributes the 0 sentinel: the merge circuit recomputes its
    // pk_field from the witnessed point and ignores the per-input value.
    const ownerPublicKeyHash =
      input.utxo.owner.signatureType() === "p256"
        ? 0n
        : bytesField(input.utxo.owner.ownerProofInputHash(), "merge owner public key");
    const converted = createRealInput(input, proof, ownerPublicKeyHash);
    inputs.push(converted);
    proofIndex++;
  }
  if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");

  const local = prepareMerge(prepared, tree);
  const complete = local.finish(inputTree);
  return Object.freeze({
    ...complete,
    proverInputs: Object.freeze({
      ...local.inputs.payload,
      inputs: Object.freeze(inputs),
      treeSlots: Object.freeze(inputTreeSlots([inputTree.slot]).map(treeSlotFields)),
      publicInputHash: asField(bytesToBigInt(complete.publicInputHash)),
    }),
  });
}

interface PreparedMergeAssembly {
  readonly inputs: IndexedProofInputs & {
    readonly circuit: "merge";
    readonly payload: PreparedMergeInputs;
  };
  finish(tree: MergeInputTree): Omit<MergeAssembly, "proverInputs">;
}

export function prepareMerge(prepared: PreparedMerge, tree: Address): PreparedMergeAssembly {
  validateMergeTree(prepared, tree);
  const expiryUnixTs = prepared.expiryUnixTs;
  // 1. Reuse commitments within one call to keep mutable input bytes bound to the statement.
  const realCommitments = new Map(
    prepared.inputUtxoHashes().map(({ index, utxoHash }) => [index, utxoHash]),
  );
  const commitments = prepared.inputs.map((input, index) => {
    if (input.isDummy()) return null;
    const commitment = realCommitments.get(index);
    if (commitment === undefined) throw new ClientError("CLIENT_INVALID_MERGE");
    return commitment;
  });
  const dummyNullifiers = prepared.dummyNullifiers();
  let dummyIndex = 0;
  const inputs = prepared.inputs.map((input) => {
    const nullifier = input.isDummy() ? dummyNullifiers[dummyIndex++] : input.nullifier();
    if (nullifier === undefined) throw new ClientError("CLIENT_INVALID_MERGE");
    const owner =
      input.isDummy() || input.utxo.owner.signatureType() === "p256"
        ? 0n
        : bytesField(input.utxo.owner.ownerProofInputHash(), "merge owner public key");
    return prepareInput(input, { owner, treeSlot: 0, nullifier });
  });
  const inputHashes = commitments.map((commitment) =>
    commitment === null ? 0n : bytesToBigInt(commitment),
  );
  const nullifiers = inputs.map((input) =>
    checkedBytes(bigintToBytes(input.nullifier), 32, "nullifier"),
  );
  const output = createOutput(prepared.output, prepared.outputTreeId);
  if (prepared.output.isDummy()) throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  const outputHash = checkedBytes(prepared.outputHash(), 32, "merge output hash");
  const externalDataHash = mergeExternalDataHash({
    instructionTag:
      prepared.output.ringProgramId === undefined
        ? InstructionTag.mergeTransact
        : InstructionTag.ringMergeTransact,
    expiryUnixTs,
    outputUtxoHash: outputHash,
  });
  // Merge has no blinding seed: the owner's nullifier secret takes its place
  // in the private transaction blinding, so a reader holding the secret
  // recovers the output without any disclosed value.
  const firstNullifier = nullifiers[0];
  if (firstNullifier === undefined) throw new ClientError("CLIENT_NO_INPUTS");
  const privateTxBlinding = prepared.privateTxBlinding();
  const privateTxHash = bigintToBytes(
    poseidon([
      hashChain4(inputHashes),
      bytesToBigInt(outputHash),
      hashChain4(Array.from({ length: MERGE_INPUTS }, () => 0n)),
      bytesToBigInt(externalDataHash),
      bytesField(privateTxBlinding, "merge private tx blinding"),
    ]),
  ) as Bytes32;
  const eddsaOwner = prepared.signingPublicKey.signatureType() === "ed25519";
  const ownerPublicKeyHash = bytesField(
    prepared.signingPublicKey.ownerProofInputHash(),
    "merge owner public key",
  );
  const outputTreeIdField = bytesToBigInt(treeIdField(prepared.outputTreeId));
  const publicInputs = [
    hashChain4(nullifiers.map(bytesToBigInt)),
    bytesToBigInt(outputHash),
    outputTreeIdField,
    bytesToBigInt(privateTxHash),
    bytesToBigInt(externalDataHash),
    1n,
    ...(prepared.output.ringProgramId === undefined
      ? [ownerPublicKeyHash]
      : [BigInt(output.circuit.ringDataHash), BigInt(output.circuit.ringProgramId)]),
  ].map(asField);
  const payload: PreparedMergeInputs = Object.freeze({
    inputs: Object.freeze(inputs),
    output,
    outputTreeId: asField(outputTreeIdField),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    userNullifierPublicKey: asField(
      bytesField(prepared.nullifierPublicKey, "merge nullifier public key"),
    ),
    externalDataHash: asField(bytesToBigInt(externalDataHash)),
    privateTxHash: asField(bytesToBigInt(privateTxHash)),
    allowDummyInputs: asField(1n),
    outputRingDataHash: output.circuit.ringDataHash,
    ringProgramId: output.circuit.ringProgramId,
  });
  return Object.freeze({
    inputs: Object.freeze({
      circuit: "merge",
      payload,
      trees: Object.freeze([{ tree, id: prepared.inputTreeId }]),
      lookups: Object.freeze(
        commitments.map((commitment) => Object.freeze({ treeSlot: 0, commitment })),
      ),
      publicInputs: Object.freeze(publicInputs),
    }),
    finish(inputTree: MergeInputTree): Omit<MergeAssembly, "proverInputs"> {
      const publicInputHash = checkedBytes(
        bigintToBytes(resolvedPublicInputHash(publicInputs, inputTreeSlots([inputTree.slot]))),
        32,
        "public input hash",
      );
      const utxoTreeRootIndex = inputTree.utxoRootIndex;
      const nullifierTreeRootIndex = inputTree.nullifierRootIndex;
      const instructionData = (
        proof: MergeTransactInstructionData["proof"],
      ): MergeTransactInstructionData =>
        Object.freeze({
          expiryUnixTs,
          proof: copyMergeProof(proof),
          outputUtxoHash: new Uint8Array(outputHash) as Bytes32,
          eddsaOwner,
          privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
          nullifiers: Object.freeze(
            nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
          ),
          utxoTreeRootIndex,
          nullifierTreeRootIndex,
        });
      return Object.freeze({
        expiryUnixTs,
        // `Object.freeze` seals the assembly and the nullifier array but not the
        // buffers inside them, and those are the buffers `instructionData` copies
        // from on every call. Hand out copies of everything the closure reads so a
        // frozen assembly cannot be steered into emitting different instruction
        // data than the one it was proved with.
        outputHash: new Uint8Array(outputHash) as Bytes32,
        nullifiers: Object.freeze(
          nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
        ),
        utxoTreeRootIndex,
        nullifierTreeRootIndex,
        privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
        publicInputHash,
        externalDataHash,
        eddsaOwner,
        instructionData,
      });
    },
  });
}

function validateMergeTree(prepared: PreparedMerge, tree: Address): void {
  validatePreparedMerge(prepared);
  // The submit tree must be the tree the inputs are hashed under, or the proof
  // and the instruction would name different trees.
  if (treeAddress(prepared.inputTreeId) !== tree) {
    throw new ClientError("CLIENT_MERGE_TREE_MISMATCH", {
      details: { proofTree: treeAddress(prepared.inputTreeId), submitTree: tree },
    });
  }
  // The merge instruction appends its output to the same tree it spends from,
  // so an output hashed under another tree would prove a commitment the
  // instruction's output tree rejects.
  if (
    prepared.output.ringProgramId === undefined &&
    prepared.outputTreeId !== prepared.inputTreeId
  ) {
    throw new ClientError("CLIENT_TREE_ID_MISMATCH", {
      details: { expected: prepared.inputTreeId, actual: prepared.outputTreeId },
    });
  }
}

function checkNullifierRoot(
  inputTree: MergeInputTree,
  proof: NonInclusionProof,
  index: number,
): void {
  if (
    !equal(proof.root, inputTree.slot.nullifierRoot) ||
    proof.rootIndex !== inputTree.nullifierRootIndex
  ) {
    throw new ClientError("CLIENT_NULLIFIER_ROOT_MISMATCH", { details: { index } });
  }
}

function validatePreparedMerge(prepared: PreparedMerge): void {
  if (!(prepared instanceof PreparedMerge)) throw new ClientError("CLIENT_INVALID_MERGE");
  if (prepared.inputs.length !== MERGE_INPUTS) {
    throw new ClientError("CLIENT_INVALID_MERGE_SHAPE", {
      details: { expected: MERGE_INPUTS, actual: prepared.inputs.length },
    });
  }
  let total = 0n;
  prepared.inputs.forEach((input) => {
    if (!input.isDummy()) {
      if (
        input.utxo.ringProgramId !== prepared.output.ringProgramId ||
        input.utxo.asset !== prepared.output.asset
      )
        throw new ClientError("CLIENT_INVALID_MERGE");
      total += input.utxo.amount;
    }
    if (!input.isDummy() && !equal(input.nullifierPublicKey, prepared.nullifierPublicKey)) {
      throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
    }
    if (
      !input.isDummy() &&
      !equal(input.utxo.owner.toBytes(), prepared.signingPublicKey.toBytes())
    ) {
      throw new ClientError("CLIENT_MERGE_SIGNING_KEY_MISMATCH");
    }
  });
  if (
    !equal(
      prepared.output.ownerAddress?.signingPublicKey.toBytes() ?? new Uint8Array(),
      prepared.signingPublicKey.toBytes(),
    )
  )
    throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  if (total !== prepared.output.amount || total > 0xffff_ffff_ffff_ffffn)
    throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
}

function copyMergeProof(
  proof: MergeTransactInstructionData["proof"],
): MergeTransactInstructionData["proof"] {
  return Object.freeze({
    a: checkedBytes(proof.a, 32, "merge proof a"),
    b: checkedBytes(proof.b, 128, "merge proof b"),
    c: checkedBytes(proof.c, 32, "merge proof c"),
  });
}

function asField(value: bigint): Field {
  return field(value, "merge field") as Field;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
