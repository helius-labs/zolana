import type { Address, Bytes32, RequestContext } from "@zolana/interface";
import type { MergeTransactInstructionData } from "@zolana/interface/instructions";
import { NullifierKey, P256PublicKey, ShieldedPublicKey } from "@zolana/keypair";
import { encryptVerifiable, mergePublicContribution } from "@zolana/keypair/merge";
import { PreparedMerge } from "@zolana/transaction";
import { EncryptedScheme, encodeMerge, encodeOutputData } from "@zolana/transaction/serialization";

import { ClientError, fromClientCause } from "../error.js";
import {
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  checkedBytes,
  field,
  hashChain,
  hashField,
  p256Coordinates,
  poseidon,
  sha256Bytes,
} from "../internal.js";
import type { Rpc, SpendProof } from "../rpc.js";
import {
  createDummyTransferInput,
  createOutput,
  createRealInput,
  validateSpendProof,
} from "./assembly.js";
import type { Field, MergeInputs, TransferInput } from "./types.js";

const MERGE_INPUTS = 8;
const MERGE_INSTRUCTION_TAG = 12;
const P256_GENERATOR_X = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const P256_GENERATOR_Y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
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
  readonly encryptedUtxo: Uint8Array;
  readonly eddsaOwner: boolean;
  instructionData(proof: MergeTransactInstructionData["proof"]): MergeTransactInstructionData;
}

export async function assembleMerge(
  prepared: PreparedMerge,
  material: MergeMaterialInput,
  indexer: Pick<Rpc, "getInputMerkleProofs">,
  tree: Address,
  context?: RequestContext,
): Promise<MergeAssembly> {
  try {
    validateMergeMaterial(prepared, material);
    const proofs = await indexer.getInputMerkleProofs(
      prepared.inputUtxoHashes(),
      undefined,
      context,
    );
    return assembleMergeWithProofs(prepared, material, proofs, tree);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

export function assembleMergeWithProofs(
  prepared: PreparedMerge,
  material: MergeMaterialInput,
  proofs: readonly SpendProof[],
  tree: Address,
): MergeAssembly {
  try {
    return assembleMergeWithProofsUnchecked(prepared, material, proofs, tree);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

function assembleMergeWithProofsUnchecked(
  prepared: PreparedMerge,
  material: MergeMaterialInput,
  proofs: readonly SpendProof[],
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

  const inputs: TransferInput[] = [];
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
  const utxoRoots: bigint[] = [];
  const nullifierRoots: bigint[] = [];
  const rootIndexes: Array<readonly [number, number]> = [];
  let proofIndex = 0;
  for (const input of prepared.inputs) {
    if (input.isDummy()) {
      const first = inputs[0];
      const firstIndexes = rootIndexes[0];
      if (!first || !firstIndexes) throw new ClientError("CLIENT_NO_INPUTS");
      const converted = createDummyTransferInput(
        input,
        first.utxoTreeRoot,
        first.nullifierTreeRoot,
        first.ownerPublicKeyHash,
      );
      inputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(bigintToBytes(converted.nullifier) as Bytes32);
      utxoRoots.push(converted.utxoTreeRoot);
      nullifierRoots.push(converted.nullifierTreeRoot);
      rootIndexes.push(firstIndexes);
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
    const ownerPublicKeyHash =
      prepared.signingPublicKey.signatureType() === "p256"
        ? 0n
        : bytesField(prepared.signingPublicKey.ownerPublicKeyField(), "merge owner public key");
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
  const plaintext = encodeMerge({
    amount: prepared.output.amount,
    assetField: bigintToBytes(hashField(addressBytes(prepared.output.asset))) as Bytes32,
    blinding: prepared.output.blinding,
  });
  const encrypted = encryptVerifiable(
    prepared.txViewingSecret,
    prepared.userViewingPublicKey,
    plaintext,
  );
  const contribution = mergePublicContribution(encrypted.txViewingPublicKey, encrypted.ciphertext);
  const encryptedUtxo = encodeOutputData(
    EncryptedScheme.merge,
    concat(encrypted.txViewingPublicKey.toBytes(), encrypted.ciphertext),
    "verifiable",
  );
  if (encryptedUtxo.length !== 110) {
    throw new ClientError("CLIENT_INVALID_MERGE_CIPHERTEXT", {
      details: { expected: 110, actual: encryptedUtxo.length },
    });
  }
  const externalDataHash = mergeExternalDataHash(prepared.expiryUnixTs, outputHash, encryptedUtxo);
  const privateTxHash = bigintToBytes(
    poseidon([
      hashChain(inputHashes),
      bytesToBigInt(outputHash),
      hashChain(Array.from({ length: MERGE_INPUTS }, () => 0n)),
      bytesToBigInt(externalDataHash),
    ]),
  ) as Bytes32;
  const eddsaOwner = prepared.signingPublicKey.signatureType() === "ed25519";
  const [p256PublicKeyX, p256PublicKeyY] = eddsaOwner
    ? [P256_GENERATOR_X, P256_GENERATOR_Y]
    : p256Coordinates(prepared.signingPublicKey.p256().toBytes());
  const [viewingX, viewingY] = p256Coordinates(prepared.userViewingPublicKey.toBytes());
  const userViewingPublicKey = Uint8Array.from([
    4,
    ...bigintToBytes(viewingX),
    ...bigintToBytes(viewingY),
  ]);
  const ownerPublicKeyHash = eddsaOwner
    ? bytesField(prepared.signingPublicKey.ownerPublicKeyField(), "merge owner public key")
    : 0n;
  const publicInputHash = bigintToBytes(
    hashChain([
      hashChain(nullifiers.map(bytesToBigInt)),
      bytesToBigInt(outputHash),
      hashChain(utxoRoots),
      hashChain(nullifierRoots),
      bytesToBigInt(privateTxHash),
      bytesToBigInt(externalDataHash),
      bytesToBigInt(prepared.signingPublicKey.ownerPublicKeyField()),
      bytesToBigInt(ShieldedPublicKey.fromP256(prepared.userViewingPublicKey).hash()),
      bytesToBigInt(contribution.txViewingPublicKeyLow),
      bytesToBigInt(contribution.txViewingPublicKeyHigh),
      bytesToBigInt(contribution.ciphertextHash),
    ]),
  ) as Bytes32;
  const proverInputs: MergeInputs = Object.freeze({
    inputs: Object.freeze(inputs),
    output,
    p256PublicKeyX: asInteger(p256PublicKeyX),
    p256PublicKeyY: asInteger(p256PublicKeyY),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    userNullifierPublicKey: asField(
      bytesField(material.nullifierKey.publicKey(), "merge nullifier public key"),
    ),
    userNullifierSecret: asField(
      bytesField(material.nullifierKey.secretBytes(), "merge nullifier secret"),
    ),
    txViewingSecret: asField(bytesField(prepared.txViewingSecret, "transaction viewing secret")),
    userViewingPublicKey: Object.freeze(
      Array.from(userViewingPublicKey, (byte) => asField(BigInt(byte))),
    ),
    externalDataHash: asField(bytesToBigInt(externalDataHash)),
    privateTxHash: asField(bytesToBigInt(privateTxHash)),
    publicInputHash: asField(bytesToBigInt(publicInputHash)),
    zoneProgramId: asField(0n),
  });
  const utxoTreeRootIndexes = Object.freeze(rootIndexes.map(([state]) => state));
  const nullifierTreeRootIndexes = Object.freeze(rootIndexes.map(([, nullifier]) => nullifier));
  return Object.freeze({
    proverInputs,
    expiryUnixTs: prepared.expiryUnixTs,
    outputHash,
    nullifiers: Object.freeze(nullifiers),
    utxoTreeRootIndexes,
    nullifierTreeRootIndexes,
    privateTxHash,
    encryptedUtxo,
    eddsaOwner,
    instructionData(proof: MergeTransactInstructionData["proof"]): MergeTransactInstructionData {
      return Object.freeze({
        expiryUnixTs: prepared.expiryUnixTs,
        proof: copyMergeProof(proof),
        outputUtxoHash: new Uint8Array(outputHash) as Bytes32,
        nullifiers: Object.freeze(
          nullifiers.map((nullifier) => new Uint8Array(nullifier) as Bytes32),
        ),
        utxoTreeRootIndexes,
        nullifierTreeRootIndexes,
        privateTxHash: new Uint8Array(privateTxHash) as Bytes32,
        encryptedUtxo: new Uint8Array(encryptedUtxo),
        eddsaOwner,
      });
    },
  });
}

function validateMergeMaterial(prepared: PreparedMerge, material: MergeMaterialInput): void {
  if (!(prepared instanceof PreparedMerge)) throw new ClientError("CLIENT_INVALID_MERGE");
  if (
    !(material.signingPublicKey instanceof ShieldedPublicKey) ||
    !(material.viewingPublicKey instanceof P256PublicKey) ||
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
  if (!equal(prepared.userViewingPublicKey.toBytes(), material.viewingPublicKey.toBytes())) {
    throw new ClientError("CLIENT_MERGE_MATERIAL_VIEWING_KEY_MISMATCH");
  }
  const expectedNullifierPublicKey = material.nullifierKey.publicKey();
  prepared.inputs.forEach((input) => {
    if (!input.isDummy() && !equal(input.nullifierKey.publicKey(), expectedNullifierPublicKey)) {
      throw new ClientError("CLIENT_MERGE_NULLIFIER_KEY_MISMATCH");
    }
  });
}

function mergeExternalDataHash(
  expiryUnixTs: bigint,
  outputHash: Bytes32,
  encryptedUtxo: Uint8Array,
): Bytes32 {
  if (expiryUnixTs < 0n || expiryUnixTs > 0xffff_ffff_ffff_ffffn) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "expiryUnixTs" } });
  }
  const expiry = bigintToBytes(expiryUnixTs, 8);
  const length = bigintToBytes(BigInt(encryptedUtxo.length), 2);
  const digest = sha256Bytes(
    concat(Uint8Array.of(MERGE_INSTRUCTION_TAG), expiry, outputHash, length, encryptedUtxo),
  );
  digest[0] = 0;
  return digest;
}

function copyMergeProof(
  proof: MergeTransactInstructionData["proof"],
): MergeTransactInstructionData["proof"] {
  return Object.freeze({
    a: checkedBytes(proof.a, 32, "merge proof a"),
    b: checkedBytes(proof.b, 64, "merge proof b"),
    c: checkedBytes(proof.c, 32, "merge proof c"),
    commitment: checkedBytes(proof.commitment, 32, "merge proof commitment"),
    commitmentPok: checkedBytes(proof.commitmentPok, 32, "merge proof commitment proof"),
  });
}

function asField(value: bigint): Field {
  return field(value, "merge field") as Field;
}

function asInteger(value: bigint): Field {
  return value as Field;
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
