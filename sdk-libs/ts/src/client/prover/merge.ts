import type {
  Address,
  Bytes32,
  MergeTransactInstructionData,
  RequestContext,
} from "../../interface/types.js";
import { mergeExternalDataHash } from "../../interface/codecs/index.js";
import { treeAddress } from "../../interface/pda/index.js";
import {
  inputTreeSlots,
  treeIdField,
  treeSlotsHashChain,
  type TreeSlot,
} from "../../interface/tree-slot.js";
import { mergePrivateTxBlinding } from "../../keypair/merge/index.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../../keypair/public-key.js";
import { PreparedMerge } from "../../transaction/instructions/builders.js";
import {
  MERGE_SUPPORTED_INPUT_COUNTS,
  isSupportedMergeInputCount,
} from "../../interface/constants.js";

import type { ProofReader } from "../ports.js";
import { ClientError, fromClientCause } from "../error.js";
import {
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  field,
  hashChain,
  poseidon,
} from "../internal.js";
import type { NonInclusionProof, SpendProof } from "../rpc.js";
import {
  createDummyTransferInput,
  createOutput,
  createRealInput,
  treeSlotFields,
  validateSpendProof,
} from "./assembly.js";
import type { Field, MergeInputs, TransferInput } from "./types.js";

const MERGE_INSTRUCTION_TAG = 13;

export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierKey: NullifierKey;
}

export interface MergeAssembly {
  readonly proverInputs: MergeInputs;
  readonly expiryUnixTs: bigint;
  readonly outputHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndexes: readonly number[];
  readonly nullifierTreeRootIndexes: readonly number[];
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
  material: MergeMaterialInput,
  indexer: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">,
  tree: Address,
  context?: RequestContext,
): Promise<MergeAssembly> {
  try {
    validateMergeMaterial(prepared, material);
    const dummyNullifiers = prepared.dummyNullifiers(material.nullifierKey);
    const [proofs, dummyResponse] = await Promise.all([
      indexer.getInputMerkleProofs(prepared.inputUtxoHashes(), undefined, context),
      dummyNullifiers.length === 0
        ? Promise.resolve(undefined)
        : indexer.getNonInclusionProofs(tree, dummyNullifiers, undefined, context),
    ]);
    return assembleMergeUnchecked(prepared, material, proofs, dummyResponse?.proofs ?? [], tree);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

export function assembleMergeWithProofs(
  prepared: PreparedMerge,
  material: MergeMaterialInput,
  proofs: readonly SpendProof[],
  tree: Address,
  dummyNullifierProofs: readonly NonInclusionProof[] = [],
): MergeAssembly {
  try {
    return assembleMergeUnchecked(prepared, material, proofs, dummyNullifierProofs, tree);
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
  material: MergeMaterialInput,
  proofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  tree: Address,
): MergeAssembly {
  validateMergeMaterial(prepared, material);
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
  if (prepared.outputTreeId !== prepared.inputTreeId) {
    throw new ClientError("CLIENT_TREE_ID_MISMATCH", {
      details: { expected: prepared.inputTreeId, actual: prepared.outputTreeId },
    });
  }
  const realInputs = prepared.inputs.filter((input) => !input.isDummy());
  if (proofs.length !== realInputs.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: { expected: realInputs.length, state: proofs.length, nullifier: proofs.length },
    });
  }
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");
  const dummyNullifiers = prepared.dummyNullifiers(material.nullifierKey);
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
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
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
      inputHashes.push(0n);
      nullifiers.push(new Uint8Array(nullifier) as Bytes32);
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
    inputHashes.push(bytesToBigInt(input.hash()));
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    proofIndex++;
  }
  if (inputTree === undefined) throw new ClientError("CLIENT_NO_INPUTS");

  const output = createOutput(prepared.output, prepared.outputTreeId);
  if (prepared.output.isDummy()) throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  const outputHash = checkedBytes(prepared.outputHash(), 32, "merge output hash");
  const externalDataHash = mergeExternalDataHash({
    instructionTag: MERGE_INSTRUCTION_TAG,
    expiryUnixTs: prepared.expiryUnixTs,
    outputUtxoHash: outputHash,
  });
  // Merge has no blinding seed: the owner's nullifier secret takes its place
  // in the private transaction blinding, so a reader holding the secret
  // recovers the output without any disclosed value.
  const firstNullifier = nullifiers[0];
  if (firstNullifier === undefined) throw new ClientError("CLIENT_NO_INPUTS");
  const privateTxBlinding = mergePrivateTxBlinding(material.nullifierKey, firstNullifier);
  const privateTxHash = bigintToBytes(
    poseidon([
      hashChain(inputHashes),
      bytesToBigInt(outputHash),
      // The address-hash chain is one zero per input slot, so its length is the
      // padded shape, not a constant.
      hashChain(Array.from({ length: prepared.inputs.length }, () => 0n)),
      bytesToBigInt(externalDataHash),
      bytesField(privateTxBlinding, "merge private tx blinding"),
    ]),
  ) as Bytes32;
  const eddsaOwner = prepared.signingPublicKey.signatureType() === "ed25519";
  const ownerPublicKeyHash = bytesField(
    prepared.signingPublicKey.ownerProofInputHash(),
    "merge owner public key",
  );
  const treeSlots = inputTreeSlots(inputTree.slot);
  const outputTreeIdField = bytesToBigInt(treeIdField(prepared.outputTreeId));
  const publicInputHash = bigintToBytes(
    hashChain([
      hashChain(nullifiers.map(bytesToBigInt)),
      bytesToBigInt(outputHash),
      bytesToBigInt(treeSlotsHashChain(treeSlots)),
      outputTreeIdField,
      bytesToBigInt(privateTxHash),
      bytesToBigInt(externalDataHash),
      1n,
      ownerPublicKeyHash,
    ]),
  ) as Bytes32;
  const proverInputs: MergeInputs = Object.freeze({
    inputs: Object.freeze(inputs),
    output,
    treeSlots: Object.freeze(treeSlots.map(treeSlotFields)),
    outputTreeId: asField(outputTreeIdField),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    userNullifierPublicKey: asField(
      bytesField(material.nullifierKey.publicKey(), "merge nullifier public key"),
    ),
    userNullifierSecret: asField(
      bytesField(material.nullifierKey.secretBytes(), "merge nullifier secret"),
    ),
    externalDataHash: asField(bytesToBigInt(externalDataHash)),
    privateTxHash: asField(bytesToBigInt(privateTxHash)),
    allowDummyInputs: asField(1n),
    publicInputHash: asField(bytesToBigInt(publicInputHash)),
    outputRingDataHash: asField(0n),
    ringProgramId: asField(0n),
  });
  // Every input references the same root history positions; the shielded pool
  // rejects a merge whose entries disagree.
  const utxoTreeRootIndexes = Object.freeze(
    Array.from({ length: prepared.inputs.length }, () => inputTree.utxoRootIndex),
  );
  const nullifierTreeRootIndexes = Object.freeze(
    Array.from({ length: prepared.inputs.length }, () => inputTree.nullifierRootIndex),
  );
  const instructionData = (
    proof: MergeTransactInstructionData["proof"],
  ): MergeTransactInstructionData =>
    Object.freeze({
      expiryUnixTs: prepared.expiryUnixTs,
      proof: copyMergeProof(proof),
      outputUtxoHash: new Uint8Array(outputHash) as Bytes32,
      eddsaOwner,
      privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
      nullifiers: Object.freeze(
        nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
      ),
      utxoTreeRootIndexes,
      nullifierTreeRootIndexes,
    });
  return Object.freeze({
    proverInputs,
    expiryUnixTs: prepared.expiryUnixTs,
    // `Object.freeze` seals the assembly and the nullifier array but not the
    // buffers inside them, and those are the buffers `instructionData` copies
    // from on every call. Hand out copies of everything the closure reads so a
    // frozen assembly cannot be steered into emitting different instruction
    // data than the one it was proved with.
    outputHash: new Uint8Array(outputHash) as Bytes32,
    nullifiers: Object.freeze(nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32)),
    utxoTreeRootIndexes,
    nullifierTreeRootIndexes,
    privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
    publicInputHash,
    externalDataHash,
    eddsaOwner,
    instructionData,
  });
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

function validateMergeMaterial(prepared: PreparedMerge, material: MergeMaterialInput): void {
  if (!(prepared instanceof PreparedMerge)) throw new ClientError("CLIENT_INVALID_MERGE");
  if (
    !(material.signingPublicKey instanceof ShieldedPublicKey) ||
    !(material.nullifierKey instanceof NullifierKey)
  ) {
    throw new ClientError("CLIENT_INVALID_MERGE_MATERIAL");
  }
  if (!isSupportedMergeInputCount(prepared.inputs.length)) {
    throw new ClientError("CLIENT_INVALID_MERGE_SHAPE", {
      details: { supported: MERGE_SUPPORTED_INPUT_COUNTS, actual: prepared.inputs.length },
    });
  }
  if (!equal(prepared.signingPublicKey.toBytes(), material.signingPublicKey.toBytes())) {
    throw new ClientError("CLIENT_MERGE_SIGNING_KEY_MISMATCH");
  }
  const expectedNullifierPublicKey = material.nullifierKey.publicKey();
  prepared.inputs.forEach((input) => {
    if (!input.isDummy() && !equal(input.nullifierKey.publicKey(), expectedNullifierPublicKey)) {
      throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
    }
  });
}

function copyMergeProof(
  proof: MergeTransactInstructionData["proof"],
): MergeTransactInstructionData["proof"] {
  return Object.freeze({
    a: checkedBytes(proof.a, 32, "merge proof a"),
    b: checkedBytes(proof.b, 64, "merge proof b"),
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
