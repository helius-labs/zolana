import type {
  Address,
  Bytes32,
  MergeTransactInstructionData,
  RequestContext,
} from "../../interface/types.js";
import { mergeExternalDataHash } from "../../interface/codecs/index.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../../keypair/public-key.js";
import { MERGE_INPUTS, PreparedMerge } from "../../transaction/instructions/builders.js";

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

function assembleMergeUnchecked(
  prepared: PreparedMerge,
  material: MergeMaterialInput,
  proofs: readonly SpendProof[],
  dummyNullifierProofs: readonly NonInclusionProof[],
  tree: Address,
): MergeAssembly {
  validateMergeMaterial(prepared, material);
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
  const utxoRoots: bigint[] = [];
  const nullifierRoots: bigint[] = [];
  const rootIndexes: Array<readonly [number, number]> = [];
  let proofIndex = 0;
  let dummyIndex = 0;
  for (const input of prepared.inputs) {
    if (input.isDummy()) {
      const first = inputs[0];
      const firstIndexes = rootIndexes[0];
      if (!first || !firstIndexes) throw new ClientError("CLIENT_NO_INPUTS");
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
      const converted = createDummyTransferInput(input, first.utxoTreeRoot, proof, nullifier);
      inputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(new Uint8Array(nullifier) as Bytes32);
      utxoRoots.push(converted.utxoTreeRoot);
      nullifierRoots.push(converted.nullifierTreeRoot);
      rootIndexes.push([firstIndexes[0], proof.rootIndex]);
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
    utxoRoots.push(converted.utxoTreeRoot);
    nullifierRoots.push(converted.nullifierTreeRoot);
    rootIndexes.push([proof.state.rootIndex, proof.nullifier.rootIndex]);
    proofIndex++;
  }

  const output = createOutput(prepared.output);
  if (prepared.output.isDummy()) throw new ClientError("CLIENT_INVALID_MERGE_OUTPUT");
  const outputHash = checkedBytes(prepared.output.hash(), 32, "merge output hash");
  const externalDataHash = mergeExternalDataHash({
    instructionTag: MERGE_INSTRUCTION_TAG,
    expiryUnixTs: prepared.expiryUnixTs,
    outputUtxoHash: outputHash,
  });
  const privateTxHash = bigintToBytes(
    poseidon([
      hashChain(inputHashes),
      bytesToBigInt(outputHash),
      hashChain(Array.from({ length: MERGE_INPUTS }, () => 0n)),
      bytesToBigInt(externalDataHash),
    ]),
  ) as Bytes32;
  const eddsaOwner = prepared.signingPublicKey.signatureType() === "ed25519";
  const ownerPublicKeyHash = bytesField(
    prepared.signingPublicKey.ownerProofInputHash(),
    "merge owner public key",
  );
  const commonPublicInputs = [
    hashChain(nullifiers.map(bytesToBigInt)),
    bytesToBigInt(outputHash),
    hashChain(utxoRoots),
    hashChain(nullifierRoots),
    bytesToBigInt(privateTxHash),
    bytesToBigInt(externalDataHash),
    1n,
  ];
  const publicInputHash = bigintToBytes(
    hashChain([...commonPublicInputs, ownerPublicKeyHash]),
  ) as Bytes32;
  const proverInputs: MergeInputs = Object.freeze({
    inputs: Object.freeze(inputs),
    output,
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
  const utxoTreeRootIndexes = Object.freeze(rootIndexes.map(([state]) => state));
  const nullifierTreeRootIndexes = Object.freeze(rootIndexes.map(([, nullifier]) => nullifier));
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

function validateMergeMaterial(prepared: PreparedMerge, material: MergeMaterialInput): void {
  if (!(prepared instanceof PreparedMerge)) throw new ClientError("CLIENT_INVALID_MERGE");
  if (
    !(material.signingPublicKey instanceof ShieldedPublicKey) ||
    !(material.nullifierKey instanceof NullifierKey)
  ) {
    throw new ClientError("CLIENT_INVALID_MERGE_MATERIAL");
  }
  if (prepared.inputs.length !== MERGE_INPUTS) {
    throw new ClientError("CLIENT_INVALID_MERGE_SHAPE", {
      details: { expected: MERGE_INPUTS, actual: prepared.inputs.length },
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
