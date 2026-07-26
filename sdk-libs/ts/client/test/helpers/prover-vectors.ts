import { sha256 } from "@noble/hashes/sha2.js";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
  type ProofOutputUtxo,
} from "@zolana/transaction";
import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";

import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import { circuitUtxo } from "../../src/prover/assembly.js";
import type { Field, ProverInputs, TransferInput, TransferOutput } from "../../src/prover/index.js";
import type { SpendProof } from "../../src/rpc.js";

export interface ProverShapeFixture {
  readonly shape: Readonly<{ inputs: string; outputs: string }>;
  readonly publicInputHashBytes: string;
  readonly proverInputs: Readonly<Record<string, unknown>>;
  readonly proverJson: Readonly<Record<string, unknown>>;
  readonly transactIxData: Readonly<{
    beforeProofBytes: string;
    afterProofBytes: string;
  }>;
}

export interface ProverRailFixture {
  readonly rail: "eddsa" | "p256";
  readonly shapes: readonly ProverShapeFixture[];
}

export interface ProverShapesFixture {
  readonly inputs: Readonly<{
    blindingSeedBytes: string;
    ed25519SecretBytes: string;
    p256SecretBytes: string;
    viewingSeedBytes: string;
  }>;
  readonly expected: Readonly<{ rails: readonly ProverRailFixture[] }>;
}

export function bytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(value)) throw new Error("invalid fixture hex");
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

export function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fieldByte(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function payerHash(): Bytes32 {
  const digest = new Uint8Array(sha256(new Uint8Array(32).fill(44)));
  digest[0] = 0;
  return digest as Bytes32;
}

function privateMessage(
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  externalDataHash: Bytes32,
): Bytes32 {
  const inputHashes = inputs.map((input) => (input.isDummy() ? 0n : bytesToBigInt(input.hash())));
  const outputHashes = outputs.map((output) =>
    output.isDummy() ? 0n : bytesToBigInt(output.hash()),
  );
  const privateHash = poseidon([
    hashChain(inputHashes),
    hashChain(outputHashes),
    hashChain(Array.from({ length: inputHashes.length }, () => 0n)),
    bytesToBigInt(externalDataHash),
  ]);
  return new Uint8Array(sha256(bigintToBytes(privateHash))) as Bytes32;
}

export function buildProofInputs(
  fixture: ProverShapesFixture,
  rail: "eddsa" | "p256",
  shape: Readonly<{ inputs: number; outputs: number }>,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
  const isP256 = rail === "p256";
  const signing = isP256
    ? SigningKey.fromBytes(bytes(fixture.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(fixture.inputs.ed25519SecretBytes) as Bytes32);
  const keypair = ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(bytes(fixture.inputs.viewingSeedBytes) as Bytes32, isP256 ? 1 : 0),
  );
  const blindingSeed = bytes(fixture.inputs.blindingSeedBytes) as Bytes31;
  const inputs: ProofInputUtxo[] = [
    new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding: deriveBlinding(blindingSeed, 0),
      }),
      nullifierKey: NullifierKey.fromSigningKey(signing),
    }),
  ];
  for (let position = 1; position < shape.inputs; position++) {
    inputs.push(ProofInputUtxo.dummy(deriveBlinding(blindingSeed, position)));
  }
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    index === 0
      ? createProofOutput({
          ownerAddress: keypair.shieldedAddress(),
          ownerTag: keypair.signingPublicKey().confidentialViewTag(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: deriveBlinding(blindingSeed, 64),
        })
      : createProofOutput({
          ownerTag: new Uint8Array(32).fill(index + 64) as Bytes32,
          asset: SOL_MINT,
          amount: 0n,
          blinding: deriveBlinding(blindingSeed, index + 64),
        }),
  );
  const resolvedOwnerTags = outputs.map((output) => {
    if (output.ownerTag === undefined) throw new Error("fixture output lacks owner tag");
    return output.ownerTag;
  });
  const externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    publicSolAmount: -5n,
    userSolAccount: encodeBase58(new Uint8Array(32).fill(43)) as Address,
    userSplToken: SOL_MINT,
    splTokenInterface: SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33).fill(41) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16).fill(42) as Bytes16,
    outputs: outputs.map((output, index) => ({
      utxoHash: output.hash(),
      ownerTag: { kind: "inline" as const, value: resolvedOwnerTags[index] as Bytes32 },
      data: Uint8Array.of(1, 2, 3),
    })),
    resolvedOwnerTags,
    messages: [],
  });
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: payerHash(),
    inputUtxos: inputs,
    outputs,
    externalData,
  });
  if (isP256) {
    const signature = signing.sign(privateMessage(inputs, outputs, externalData.hash()));
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  const tree = encodeBase58(new Uint8Array(32).fill(45)) as Address;
  const spendProofs = proofInputs.inputUtxoHashes().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 32 }, () => fieldByte(46 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(47),
      rootSeq: 48n,
      rootIndex: 49 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree },
      path: Array.from({ length: 40 }, () => fieldByte(50 + index)),
      lowElement: fieldByte(51),
      lowElementIndex: 0n,
      highElement: fieldByte(52),
      highElementIndex: 1n,
      root: fieldByte(53),
      rootSeq: 54n,
      rootIndex: 55 + index,
    },
  }));
  return { proofInputs, spendProofs };
}

export interface ProverEdgeCase {
  readonly name: string;
  readonly publicInputHashBytes: string;
  readonly proverInputs: Readonly<Record<string, unknown>>;
  readonly eddsaSignerIndexes: readonly number[];
  readonly nullifierBytes: readonly string[];
  readonly rootIndexes: readonly (readonly [number, number])[];
  readonly transactIxBytes: string;
}

export interface ProverEdgeCaseOracle {
  readonly inputs: Readonly<{
    blindingSeedBytes: string;
    ed25519SecretBytes: string;
    p256SecretBytes: string;
    splMintBytes: string;
    viewingSeedBytes: string;
  }>;
  readonly expected: Readonly<{ cases: readonly ProverEdgeCase[] }>;
}

type Rail = "eddsa" | "p256";

/// One padded input slot: a real UTXO owned by the named rail's key, or a
/// padding slot. Mirrors the `Case` layout in
/// `sdk-libs/client/tests/ts_prover_oracle.rs`.
export type EdgeCaseSlot = Readonly<{ rail: Rail; position: number } | { dummy: number }>;

export interface EdgeCaseShape {
  readonly inputs: readonly EdgeCaseSlot[];
  /// Output 0 is real and owned by this rail; the rest are padding.
  readonly outputRail: Rail;
  readonly outputs: number;
  /// `true` for the SPL public leg, `false` for the SOL one.
  readonly splWithdrawal: boolean;
  readonly p256: boolean;
}

/// The four edge cases the Rust oracle emits, in the same order. Kept beside
/// the builder so a case added on one side fails the length assertion on the
/// other rather than being silently skipped.
export const PROVER_EDGE_CASES: readonly EdgeCaseShape[] = [
  {
    inputs: [{ rail: "eddsa", position: 0 }, { dummy: 1 }],
    outputRail: "eddsa",
    outputs: 3,
    splWithdrawal: true,
    p256: false,
  },
  {
    inputs: [{ rail: "eddsa", position: 0 }, { dummy: 1 }, { rail: "p256", position: 2 }],
    outputRail: "p256",
    outputs: 3,
    splWithdrawal: false,
    p256: true,
  },
  {
    inputs: [{ rail: "p256", position: 0 }, { dummy: 1 }, { rail: "eddsa", position: 2 }],
    outputRail: "p256",
    outputs: 3,
    splWithdrawal: false,
    p256: true,
  },
  {
    inputs: [
      { rail: "p256", position: 0 },
      { rail: "p256", position: 3 },
    ],
    outputRail: "p256",
    outputs: 2,
    splWithdrawal: true,
    p256: true,
  },
];

function edgeCaseKeypair(oracle: ProverEdgeCaseOracle, rail: Rail): ShieldedKeypair {
  const isP256 = rail === "p256";
  const signing = isP256
    ? SigningKey.fromBytes(bytes(oracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(oracle.inputs.ed25519SecretBytes) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(bytes(oracle.inputs.viewingSeedBytes) as Bytes32, isP256 ? 1 : 0),
  );
}

function edgeCaseSigningKey(oracle: ProverEdgeCaseOracle, rail: Rail): SigningKey {
  return rail === "p256"
    ? SigningKey.fromBytes(bytes(oracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(oracle.inputs.ed25519SecretBytes) as Bytes32);
}

export function buildEdgeCase(
  oracle: ProverEdgeCaseOracle,
  shape: EdgeCaseShape,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
  const blindingSeed = bytes(oracle.inputs.blindingSeedBytes) as Bytes31;
  const splMint = encodeBase58(bytes(oracle.inputs.splMintBytes)) as Address;
  const asset = shape.splWithdrawal ? splMint : SOL_MINT;
  const inputs = shape.inputs.map((slot) => {
    if ("dummy" in slot) return ProofInputUtxo.dummy(deriveBlinding(blindingSeed, slot.dummy));
    const signing = edgeCaseSigningKey(oracle, slot.rail);
    return new ProofInputUtxo({
      utxo: new Utxo({
        owner: signing.publicKey(),
        asset,
        amount: 100n,
        blinding: deriveBlinding(blindingSeed, slot.position),
      }),
      nullifierKey: NullifierKey.fromSigningKey(signing),
    });
  });
  const outputOwner = edgeCaseKeypair(oracle, shape.outputRail);
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    index === 0
      ? createProofOutput({
          ownerAddress: outputOwner.shieldedAddress(),
          ownerTag: outputOwner.signingPublicKey().confidentialViewTag(),
          asset,
          amount: 100n,
          blinding: deriveBlinding(blindingSeed, 64),
        })
      : createProofOutput({
          ownerTag: new Uint8Array(32).fill(index + 64) as Bytes32,
          asset: SOL_MINT,
          amount: 0n,
          blinding: deriveBlinding(blindingSeed, index + 64),
        }),
  );
  const resolvedOwnerTags = outputs.map((output) => {
    if (output.ownerTag === undefined) throw new Error("oracle output lacks owner tag");
    return output.ownerTag;
  });
  const externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    ...(shape.splWithdrawal ? { publicSplAmount: -5n } : { publicSolAmount: -5n }),
    userSolAccount: shape.splWithdrawal
      ? SOL_MINT
      : (encodeBase58(new Uint8Array(32).fill(43)) as Address),
    userSplToken: shape.splWithdrawal ? splMint : SOL_MINT,
    splTokenInterface: shape.splWithdrawal
      ? (encodeBase58(new Uint8Array(32).fill(8)) as Address)
      : SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33).fill(41) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16).fill(42) as Bytes16,
    outputs: outputs.map((output, index) => ({
      utxoHash: output.hash(),
      ownerTag: { kind: "inline" as const, value: resolvedOwnerTags[index] as Bytes32 },
      data: Uint8Array.of(1, 2, 3),
    })),
    resolvedOwnerTags,
    messages: [],
  });
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: payerHash(),
    inputUtxos: inputs,
    outputs,
    externalData,
  });
  if (shape.p256) {
    const signing = edgeCaseSigningKey(oracle, "p256");
    const signature = signing.sign(proofInputs.messageHash());
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  return { proofInputs, spendProofs: edgeCaseSpendProofs(proofInputs) };
}

function edgeCaseSpendProofs(proofInputs: SppProofInputs): readonly SpendProof[] {
  const tree = encodeBase58(new Uint8Array(32).fill(45)) as Address;
  return proofInputs.inputUtxoHashes().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 32 }, () => fieldByte(46 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(47),
      rootSeq: 48n,
      rootIndex: 49 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree },
      path: Array.from({ length: 40 }, () => fieldByte(50 + index)),
      lowElement: fieldByte(51),
      lowElementIndex: 0n,
      highElement: fieldByte(52),
      highElementIndex: 1n,
      root: fieldByte(53),
      rootSeq: 54n,
      rootIndex: 55 + index,
    },
  }));
}

function decimal(value: Field): string {
  return value.toString();
}

function utxoJson(value: object): Readonly<Record<string, string>> {
  const utxo = circuitUtxo(value);
  return {
    domainBytes: hex(bigintToBytes(utxo.domain)),
    ownerHashBytes: hex(bigintToBytes(utxo.owner)),
    assetBytes: hex(bigintToBytes(utxo.asset)),
    amountBytes: hex(bigintToBytes(utxo.amount)),
    blindingBytes: hex(bigintToBytes(utxo.blinding)),
    dataHashBytes: hex(bigintToBytes(utxo.dataHash)),
    zoneDataHashBytes: hex(bigintToBytes(utxo.zoneDataHash)),
    zoneProgramIdBytes: hex(bigintToBytes(utxo.zoneProgramId)),
  };
}

function inputJson(input: TransferInput): Readonly<Record<string, unknown>> {
  return {
    isDummy: decimal(input.isDummy),
    statePathElements: input.statePathElements.map(decimal),
    statePathIndex: decimal(input.statePathIndex),
    nullifierLowValue: decimal(input.nullifierLowValue),
    nullifierNextValue: decimal(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(decimal),
    nullifierLowPathIndex: decimal(input.nullifierLowPathIndex),
    utxoTreeRoot: decimal(input.utxoTreeRoot),
    nullifierTreeRoot: decimal(input.nullifierTreeRoot),
    nullifier: decimal(input.nullifier),
    ownerPkHash: decimal(input.ownerPublicKeyHash),
    nullifierSecret: decimal(input.nullifierSecret),
    utxo: utxoJson(input),
  };
}

function outputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return {
    isDummy: decimal(output.isDummy),
    hash: decimal(output.hash),
    ownerPkHash: decimal(output.ownerPublicKeyHash),
    nullifierPk: decimal(output.nullifierPublicKey),
    utxo: utxoJson(output),
  };
}

export function proverInputsJson(inputs: ProverInputs): Readonly<Record<string, unknown>> {
  const common = {
    rail: inputs.circuit === "transfer" ? "eddsa" : "p256",
    inputs: inputs.payload.inputs.map(inputJson),
    outputs: inputs.payload.outputs.map(outputJson),
    externalDataHash: decimal(inputs.payload.externalDataHash),
    privateTxHash: decimal(inputs.payload.privateTxHash),
    publicInputHash: decimal(inputs.payload.publicInputHash),
    publicSolAmount: decimal(inputs.payload.publicSolAmount),
    publicSplAmount: decimal(inputs.payload.publicSplAmount),
    publicSplAssetPubkey: decimal(inputs.payload.publicSplAssetPublicKey),
    zoneProgramId: decimal(inputs.payload.zoneProgramId),
    payerPubkeyHash: decimal(inputs.payload.payerPublicKeyHash),
  };
  if (inputs.circuit === "transfer") return common;
  return {
    ...common,
    p256PubX: decimal(inputs.payload.p256PublicKeyX),
    p256PubY: decimal(inputs.payload.p256PublicKeyY),
    p256SigR: decimal(inputs.payload.p256SignatureR),
    p256SigS: decimal(inputs.payload.p256SignatureS),
    p256MessageHashLow: decimal(inputs.payload.p256MessageHashLow),
    p256MessageHashHigh: decimal(inputs.payload.p256MessageHashHigh),
    p256SigningPkField: decimal(inputs.payload.p256SigningPublicKeyField),
  };
}
