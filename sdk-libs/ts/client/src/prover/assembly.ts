import type { Address, Bytes32, TransactInstructionData, TransactProof } from "@zolana/interface";
import { ShieldedPublicKey } from "@zolana/keypair";
import {
  ProofInputUtxo,
  SppProofInputs,
  TransactionError,
  type ProofOutputUtxo,
} from "@zolana/transaction";

import { ClientError, fromClientCause } from "../error.js";
import {
  BN254_MODULUS,
  addressBytes,
  bigintToBytes,
  bytesField,
  bytesToBigInt,
  field,
  hashChain,
  hashField,
  poseidon,
  sha256Bytes,
} from "../internal.js";
import type { SpendProof } from "../rpc.js";
import type {
  AssembledTransfer,
  Field,
  ProverInputs,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TransferP256Inputs,
} from "./types.js";

const STATE_TREE_HEIGHT = 32;
const NULLIFIER_TREE_HEIGHT = 40;
const SYSTEM_ADDRESS = "11111111111111111111111111111111" as Address;
const ZERO_PROOF = Object.freeze({
  rail: "eddsa" as const,
  a: new Uint8Array(32),
  b: new Uint8Array(64),
  c: new Uint8Array(32),
}) as TransactProof;

interface CircuitUtxo {
  readonly domain: Field;
  readonly owner: Field;
  readonly asset: Field;
  readonly amount: Field;
  readonly blinding: Field;
  readonly dataHash: Field;
  readonly zoneDataHash: Field;
  readonly zoneProgramId: Field;
}

const CIRCUIT_UTXOS = new WeakMap<object, CircuitUtxo>();

export function circuitUtxo(value: object): CircuitUtxo {
  const result = CIRCUIT_UTXOS.get(value);
  if (!result) throw new ClientError("CLIENT_PROVER_INPUT");
  return result;
}

export function intoProver(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
): ProverInputs {
  return assemble(proofInputs, spendProofs).proverInputs;
}

export function assemble(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
): AssembledTransfer {
  try {
    return assembleUnchecked(proofInputs, spendProofs);
  } catch (cause) {
    throw fromClientCause(cause);
  }
}

function assembleUnchecked(
  proofInputs: SppProofInputs,
  spendProofs: readonly SpendProof[],
): AssembledTransfer {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  proofInputs.checkShape();
  const realInputs = proofInputs.inputUtxos.filter((input) => !input.isDummy());
  if (spendProofs.length !== realInputs.length) {
    throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
      details: {
        expected: realInputs.length,
        state: spendProofs.length,
        nullifier: spendProofs.length,
      },
    });
  }
  if (realInputs.length === 0) throw new ClientError("CLIENT_NO_INPUTS");

  const requiresP256 = realInputs.some((input) => input.utxo.owner.signatureType() === "p256");
  const signature = proofInputs.p256Signature();
  if (requiresP256 && signature === undefined) {
    throw new ClientError("CLIENT_MISSING_P256_SIGNATURE");
  }
  if (!requiresP256 && signature !== undefined) {
    throw new ClientError("CLIENT_PROOF_RAIL_MISMATCH");
  }
  const p256SigningField =
    signature === undefined
      ? 0n
      : bytesField(
          ShieldedPublicKey.fromP256(signature.publicKey).ownerPublicKeyField(),
          "p256 signing public key",
        );

  const transferInputs: TransferInput[] = [];
  const inputHashes: bigint[] = [];
  const nullifiers: Bytes32[] = [];
  const utxoRoots: bigint[] = [];
  const nullifierRoots: bigint[] = [];
  const inputOwnerFields: bigint[] = [];
  const rootIndexes: Array<readonly [number, number]> = [];
  let proofIndex = 0;
  for (let index = 0; index < proofInputs.inputUtxos.length; index++) {
    const input = proofInputs.inputUtxos[index];
    if (!input) {
      throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
        details: { got: index, expected: proofInputs.inputUtxos.length },
      });
    }
    if (input.isDummy()) {
      const first = transferInputs[0];
      const roots = rootIndexes[0];
      if (!first || !roots) throw new ClientError("CLIENT_NO_INPUTS");
      const converted = createDummyTransferInput(
        input,
        first.utxoTreeRoot,
        first.nullifierTreeRoot,
        first.ownerPublicKeyHash,
      );
      transferInputs.push(converted);
      inputHashes.push(0n);
      nullifiers.push(bigintToBytes(converted.nullifier) as Bytes32);
      utxoRoots.push(converted.utxoTreeRoot);
      nullifierRoots.push(converted.nullifierTreeRoot);
      inputOwnerFields.push(converted.ownerPublicKeyHash);
      rootIndexes.push(roots);
      continue;
    }
    const proof = spendProofs[proofIndex++];
    if (!proof) {
      throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
        details: { index: proofIndex - 1 },
      });
    }
    validateSpendProof(input, proof, proofIndex - 1);
    const ownerField =
      input.utxo.owner.signatureType() === "p256"
        ? p256SigningField
        : bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key");
    const converted = createRealInput(input, proof, ownerField);
    transferInputs.push(converted);
    inputHashes.push(bytesToBigInt(input.hash()));
    nullifiers.push(new Uint8Array(input.nullifier()) as Bytes32);
    utxoRoots.push(converted.utxoTreeRoot);
    nullifierRoots.push(converted.nullifierTreeRoot);
    inputOwnerFields.push(ownerField);
    rootIndexes.push([proof.state.rootIndex, proof.nullifier.rootIndex]);
  }

  const transferOutputs = proofInputs.outputs.map(createOutput);
  const outputHashes = proofInputs.outputs.map((output) => bytesToBigInt(output.hash()));
  const privateOutputHashes = proofInputs.outputs.map((output) =>
    output.isDummy() ? 0n : bytesToBigInt(output.hash()),
  );
  const outputOwnerFields = transferOutputs.map((output) => output.ownerPublicKeyHash);
  const externalDataHash = bytesField(proofInputs.externalData.hash(), "external data hash");
  const privateTxHash = poseidon([
    hashChain(inputHashes),
    hashChain(privateOutputHashes),
    hashChain(Array.from({ length: inputHashes.length }, () => 0n)),
    externalDataHash,
  ]);
  const p256MessageHash =
    signature === undefined ? 0n : bytesToBigInt(sha256Bytes(bigintToBytes(privateTxHash)));
  const amounts = proofInputs.publicAmounts();
  const publicSolAmount = signedField(amounts.sol ?? 0n, "public SOL amount");
  const publicSplAmount = signedField(amounts.spl ?? 0n, "public SPL amount");
  const publicSplAssetPublicKey =
    amounts.spl === undefined || amounts.spl === 0n
      ? 0n
      : hashField(addressBytes(findPublicSplAsset(proofInputs)));
  const payerPublicKeyHash = bytesField(proofInputs.payerPublicKeyHash, "payer public key hash");
  const publicInputHash = hashChain([
    hashChain(nullifiers.map(bytesToBigInt)),
    hashChain(outputHashes),
    hashChain(utxoRoots),
    hashChain(nullifierRoots),
    privateTxHash,
    hashField(bigintToBytes(p256MessageHash)),
    externalDataHash,
    publicSolAmount,
    publicSplAmount,
    publicSplAssetPublicKey,
    0n,
    payerPublicKeyHash,
    hashChain(inputOwnerFields),
    hashChain(outputOwnerFields),
    p256SigningField,
  ]);
  const common: TransferInputs = Object.freeze({
    inputs: Object.freeze(transferInputs),
    outputs: Object.freeze(transferOutputs),
    externalDataHash: asField(externalDataHash),
    privateTxHash: asField(privateTxHash),
    publicSolAmount: asField(publicSolAmount),
    publicSplAmount: asField(publicSplAmount),
    publicSplAssetPublicKey: asField(publicSplAssetPublicKey),
    zoneProgramId: asField(0n),
    payerPublicKeyHash: asField(payerPublicKeyHash),
    publicInputHash: asField(publicInputHash),
  });
  const proverInputs: ProverInputs =
    signature === undefined
      ? Object.freeze({ circuit: "transfer", payload: common })
      : Object.freeze({
          circuit: "transferP256",
          payload: Object.freeze({
            ...common,
            p256PublicKeyX: asInteger(bytesToBigInt(signature.publicKey.x())),
            p256PublicKeyY: asInteger(p256Y(signature.publicKey.toBytes())),
            p256SignatureR: asInteger(bytesToBigInt(signature.r)),
            p256SignatureS: asInteger(bytesToBigInt(signature.s)),
            p256MessageHashLow: asField(p256MessageHash & ((1n << 128n) - 1n)),
            p256MessageHashHigh: asField(p256MessageHash >> 128n),
            p256SigningPublicKeyField: asField(p256SigningField),
          } satisfies TransferP256Inputs),
        });

  const firstSigner = realInputs[0]?.utxo.owner.signatureType() === "p256" ? 255 : 0;
  let realSignerIndex = 0;
  const instructionData: TransactInstructionData = Object.freeze({
    proof: ZERO_PROOF,
    expiryUnixTs: proofInputs.externalData.expiryUnixTs,
    relayerFee: proofInputs.externalData.relayerFee,
    privateTxHash: bigintToBytes(privateTxHash) as Bytes32,
    ...(signature === undefined ? {} : { p256SigningPkX: signature.publicKey.x() }),
    txViewingPk: proofInputs.externalData.txViewingPublicKey.toBytes(),
    salt: new Uint8Array(proofInputs.externalData.salt) as never,
    inputs: Object.freeze(
      proofInputs.inputUtxos.map((input, index) => {
        const roots = rootIndexes[index];
        const nullifier = nullifiers[index];
        if (!roots || !nullifier) {
          throw new ClientError("CLIENT_PROOF_INPUT_COUNT_MISMATCH", {
            details: {
              got: Math.min(rootIndexes.length, nullifiers.length),
              expected: proofInputs.inputUtxos.length,
            },
          });
        }
        const signer = input.isDummy()
          ? firstSigner
          : realInputs[realSignerIndex++]?.utxo.owner.signatureType() === "p256"
            ? 255
            : 0;
        return Object.freeze({
          nullifierHash: nullifier,
          nullifierTreeRootIndex: roots[1],
          utxoTreeRootIndex: roots[0],
          treeIndex: 0,
          eddsaSignerIndex: signer,
        });
      }),
    ),
    ...(proofInputs.externalData.publicSolAmount === undefined
      ? {}
      : { publicSolAmount: proofInputs.externalData.publicSolAmount }),
    ...(proofInputs.externalData.publicSplAmount === undefined
      ? {}
      : { publicSplAmount: proofInputs.externalData.publicSplAmount }),
    ...(proofInputs.externalData.dataHash === undefined
      ? {}
      : { dataHash: new Uint8Array(proofInputs.externalData.dataHash) as Bytes32 }),
    ...(proofInputs.externalData.zoneDataHash === undefined
      ? {}
      : { zoneDataHash: new Uint8Array(proofInputs.externalData.zoneDataHash) as Bytes32 }),
    outputs: Object.freeze(
      proofInputs.externalData.outputs.map((output) =>
        Object.freeze({
          ...output,
          utxoHash: new Uint8Array(output.utxoHash) as Bytes32,
          ...(output.data === undefined ? {} : { data: new Uint8Array(output.data) }),
        }),
      ),
    ),
    messages: Object.freeze(
      proofInputs.externalData.messages.map((message) =>
        Object.freeze({
          viewTag: new Uint8Array(message.viewTag) as Bytes32,
          data: new Uint8Array(message.data),
        }),
      ),
    ),
  });
  return Object.freeze({
    instructionData,
    proverInputs,
    withProof(proof: TransactProof): TransactInstructionData {
      return Object.freeze({ ...instructionData, proof: copyProof(proof) });
    },
  });
}

export function createRealInput(
  input: ProofInputUtxo,
  proof: SpendProof,
  ownerPublicKeyHash: bigint,
): TransferInput {
  const value = Object.freeze({
    utxo: input,
    isDummy: asField(0n),
    statePathElements: Object.freeze(
      proof.state.path.map((item) => asField(bytesField(item, "state path element"))),
    ),
    statePathIndex: asField(proof.state.leafIndex),
    nullifierLowValue: asField(bytesField(proof.nullifier.lowElement, "low element")),
    nullifierNextValue: asField(bytesField(proof.nullifier.highElement, "high element")),
    nullifierLowPathElements: Object.freeze(
      proof.nullifier.path.map((item) => asField(bytesField(item, "nullifier path element"))),
    ),
    nullifierLowPathIndex: asField(proof.nullifier.lowElementIndex),
    utxoTreeRoot: asField(bytesField(proof.state.root, "state root")),
    nullifierTreeRoot: asField(bytesField(proof.nullifier.root, "nullifier root")),
    nullifier: asField(bytesField(input.nullifier(), "nullifier")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierSecret: asField(bytesField(input.nullifierKey.secretBytes(), "nullifier secret")),
  });
  CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input));
  return value;
}

export function createDummyTransferInput(
  input: ProofInputUtxo,
  utxoRoot: bigint,
  nullifierRoot: bigint,
  owner: bigint,
): TransferInput {
  const value = Object.freeze({
    utxo: input,
    isDummy: asField(1n),
    statePathElements: Object.freeze(Array.from({ length: STATE_TREE_HEIGHT }, () => asField(0n))),
    statePathIndex: asField(0n),
    nullifierLowValue: asField(0n),
    nullifierNextValue: asField(0n),
    nullifierLowPathElements: Object.freeze(
      Array.from({ length: NULLIFIER_TREE_HEIGHT }, () => asField(0n)),
    ),
    nullifierLowPathIndex: asField(0n),
    utxoTreeRoot: asField(utxoRoot),
    nullifierTreeRoot: asField(nullifierRoot),
    nullifier: asField(bytesField(input.nullifier(), "dummy nullifier")),
    ownerPublicKeyHash: asField(owner),
    nullifierSecret: asField(0n),
  });
  CIRCUIT_UTXOS.set(value, inputCircuitUtxo(input, true));
  return value;
}

export function createOutput(output: ProofOutputUtxo): TransferOutput {
  const ownerPublicKeyHash = output.ownerAddress
    ? bytesField(
        output.ownerAddress.signingPublicKey.ownerPublicKeyField(),
        "output owner public key",
      )
    : hashField(output.ownerTag ?? new Uint8Array(32));
  const value = Object.freeze({
    utxo: output as unknown as ProofInputUtxo,
    isDummy: asField(output.isDummy() ? 1n : 0n),
    hash: asField(bytesField(output.hash(), "output hash")),
    ownerPublicKeyHash: asField(ownerPublicKeyHash),
    nullifierPublicKey: asField(
      output.ownerAddress
        ? bytesField(output.ownerAddress.nullifierPublicKey, "output nullifier public key")
        : 0n,
    ),
  });
  CIRCUIT_UTXOS.set(value, outputCircuitUtxo(output));
  return value;
}

function inputCircuitUtxo(input: ProofInputUtxo, dummy = false): CircuitUtxo {
  const owner = dummy
    ? 0n
    : poseidon([
        bytesField(input.utxo.owner.ownerPublicKeyField(), "owner public key"),
        bytesField(input.nullifierKey.publicKey(), "nullifier public key"),
      ]);
  return Object.freeze({
    domain: asField(1n),
    owner: asField(owner),
    asset: asField(hashField(addressBytes(input.utxo.asset))),
    amount: asField(input.utxo.amount),
    blinding: asField(bytesToBigInt(input.utxo.blinding)),
    dataHash: asField(input.dataHash ? bytesField(input.dataHash, "data hash") : 0n),
    zoneDataHash: asField(
      input.zoneDataHash ? bytesField(input.zoneDataHash, "zone data hash") : 0n,
    ),
    zoneProgramId: asField(
      input.utxo.zoneProgramId ? hashField(addressBytes(input.utxo.zoneProgramId)) : 0n,
    ),
  });
}

function outputCircuitUtxo(output: ProofOutputUtxo): CircuitUtxo {
  return Object.freeze({
    domain: asField(1n),
    owner: asField(bytesField(output.ownerHash(), "output owner")),
    asset: asField(hashField(addressBytes(output.asset))),
    amount: asField(output.amount),
    blinding: asField(bytesToBigInt(output.blinding)),
    dataHash: asField(output.dataHash ? bytesField(output.dataHash, "output data hash") : 0n),
    zoneDataHash: asField(
      output.zoneDataHash ? bytesField(output.zoneDataHash, "output zone data hash") : 0n,
    ),
    zoneProgramId: asField(
      output.zoneProgramId ? hashField(addressBytes(output.zoneProgramId)) : 0n,
    ),
  });
}

export function validateSpendProof(input: ProofInputUtxo, proof: SpendProof, index: number): void {
  if (!equal(input.hash(), proof.state.leaf)) {
    throw new ClientError("CLIENT_STATE_PROOF_LEAF_MISMATCH", { details: { index } });
  }
  if (!equal(input.nullifier(), proof.nullifier.leaf)) {
    throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
      details: { index },
    });
  }
  if (proof.state.merkleContext.tree !== proof.nullifier.merkleContext.tree) {
    throw new ClientError("CLIENT_PROOF_TREE_MISMATCH", { details: { index } });
  }
  if (proof.state.path.length !== STATE_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: { index, kind: "state", expected: STATE_TREE_HEIGHT, got: proof.state.path.length },
    });
  }
  if (proof.nullifier.path.length !== NULLIFIER_TREE_HEIGHT) {
    throw new ClientError("CLIENT_PROOF_PATH_LENGTH", {
      details: {
        index,
        kind: "nullifier",
        expected: NULLIFIER_TREE_HEIGHT,
        got: proof.nullifier.path.length,
      },
    });
  }
}

function findPublicSplAsset(proofInputs: SppProofInputs): Address {
  for (const input of proofInputs.inputUtxos) {
    if (!input.isDummy() && input.utxo.asset !== SYSTEM_ADDRESS) return input.utxo.asset;
  }
  for (const output of proofInputs.outputs) {
    if (!output.isDummy() && output.asset !== SYSTEM_ADDRESS) return output.asset;
  }
  throw fromClientCause(new TransactionError("TRANSACTION_MISSING_PUBLIC_SPL_ASSET"));
}

function signedField(value: bigint, name: string): bigint {
  const result = ((value % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;
  return field(result, name);
}

function asField(value: bigint): Field {
  return field(value, "field") as Field;
}

function asInteger(value: bigint): Field {
  return value as Field;
}

function p256Y(compressed: Uint8Array): bigint {
  const x = bytesToBigInt(compressed.subarray(1));
  const p = 0xffff_ffff_0000_0001_0000_0000_0000_0000_0000_0000_ffff_ffff_ffff_ffff_ffff_ffffn;
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  let y = modPow((x ** 3n - 3n * x + b + p) % p, (p + 1n) / 4n, p);
  if ((y & 1n) !== BigInt((compressed[0] ?? 0) & 1)) y = p - y;
  return y;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let value = base;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * value) % modulus;
    value = (value * value) % modulus;
    power >>= 1n;
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

function copyProof(proof: TransactProof): TransactProof {
  return proof.rail === "eddsa"
    ? Object.freeze({
        rail: "eddsa",
        a: new Uint8Array(proof.a) as never,
        b: new Uint8Array(proof.b) as never,
        c: new Uint8Array(proof.c) as never,
      })
    : Object.freeze({
        rail: "p256",
        a: new Uint8Array(proof.a) as never,
        b: new Uint8Array(proof.b) as never,
        c: new Uint8Array(proof.c) as never,
        commitment: new Uint8Array(proof.commitment) as never,
        commitmentPok: new Uint8Array(proof.commitmentPok) as never,
      });
}
