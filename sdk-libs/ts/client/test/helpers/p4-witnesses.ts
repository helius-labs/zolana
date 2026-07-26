import { sha256 } from "@noble/hashes/sha2.js";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import {
  PreparedMerge,
  PreparedMergeZone,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
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
import { assemble } from "../../src/prover/index.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import {
  assembleZone,
  assembleZoneAuthority,
  assembleZoneP256,
} from "../../src/prover/zone.js";
import type { SpendProof } from "../../src/rpc.js";
import { bytes } from "./prover-vectors.js";
import { ProveIndexer } from "./p4-prove-indexer.js";
import mergeOracle from "../oracles/merge-v1.json" with { type: "json" };
import zoneOracle from "../oracles/zone-v1.json" with { type: "json" };
import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import type { ProverShapesFixture } from "./prover-vectors.js";

const fixture = proverFixtureJson as ProverShapesFixture;
const TREE = encodeBase58(new Uint8Array(32).fill(45)) as Address;
const AMOUNT = 100n;

function payerHash(): Bytes32 {
  const digest = new Uint8Array(sha256(new Uint8Array(32).fill(44)));
  digest[0] = 0;
  return digest as Bytes32;
}

function privateMessage(
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ReturnType<typeof createProofOutput>[],
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

function keypair(rail: "eddsa" | "p256"): Readonly<{
  keypair: ShieldedKeypair;
  signing: SigningKey;
}> {
  const signing =
    rail === "p256"
      ? SigningKey.fromBytes(bytes(fixture.inputs.p256SecretBytes) as Bytes32)
      : SigningKey.fromEd25519Bytes(bytes(fixture.inputs.ed25519SecretBytes) as Bytes32);
  return {
    signing,
    keypair: ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromSeed(bytes(fixture.inputs.viewingSeedBytes) as Bytes32, rail === "p256" ? 1 : 0),
    ),
  };
}

function indexRealInputs(
  indexer: ProveIndexer,
  inputs: readonly ProofInputUtxo[],
): readonly SpendProof[] {
  const proofs: SpendProof[] = [];
  for (const input of inputs) {
    if (input.isDummy()) continue;
    const hash = input.hash();
    indexer.addUtxo(hash);
    proofs.push(indexer.spendProof(hash, input.nullifier()));
  }
  return proofs;
}

/// Balanced confidential witness: one real 100-lamport input, one 100-lamport
/// output, zero public amount, remaining slots dummy. Spend proofs come from a
/// real Poseidon tree so the circuit constraints can pass.
export function buildConfidentialWitness(
  rail: "eddsa" | "p256",
  shape: Readonly<{ inputs: number; outputs: number }>,
): ReturnType<typeof assemble> {
  const { keypair: owner, signing } = keypair(rail);
  const blindingSeed = bytes(fixture.inputs.blindingSeedBytes) as Bytes31;
  const inputs: ProofInputUtxo[] = [
    new ProofInputUtxo({
      utxo: new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: AMOUNT,
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
          ownerAddress: owner.shieldedAddress(),
          ownerTag: owner.signingPublicKey().confidentialViewTag(),
          asset: SOL_MINT,
          amount: AMOUNT,
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
    publicSolAmount: 0n,
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
  if (rail === "p256") {
    const signature = signing.sign(privateMessage(inputs, outputs, externalData.hash()));
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  const indexer = new ProveIndexer(TREE);
  const spendProofs = indexRealInputs(indexer, inputs);
  return assemble(proofInputs, spendProofs);
}

function zoneKeypair(p256: boolean): Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }> {
  const signing = p256
    ? SigningKey.fromBytes(bytes(zoneOracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(zoneOracle.inputs.ed25519SecretBytes) as Bytes32);
  return {
    signing,
    keypair: ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromSeed(bytes(zoneOracle.inputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
    ),
  };
}

function buildZoneInputs(
  p256: boolean,
  shape: Readonly<{ inputs: number; outputs: number }>,
  authority: boolean,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[]; zone: Address }> {
  const zone = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
  const tree = encodeBase58(bytes(zoneOracle.inputs.treeBytes)) as Address;
  const { keypair: owner, signing } = zoneKeypair(p256);
  const seed = bytes(zoneOracle.inputs.blindingSeedBytes) as Bytes31;
  const real = shape.inputs >= 2 ? 2 : 1;
  // Match `sdk-libs/client/tests/zone_transfer/steps.rs`: real inputs carry the
  // zone; dummy inputs do not. Real outputs use an owner address; padding
  // outputs are zero-amount with no zone binding.
  const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) =>
    index < real
      ? new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding: deriveBlinding(seed, index),
            zoneProgramId: zone,
          }),
          nullifierKey: NullifierKey.fromSigningKey(signing),
        })
      : ProofInputUtxo.dummy(deriveBlinding(seed, index)),
  );
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    index === 0
      ? createProofOutput({
          ownerAddress: owner.shieldedAddress(),
          asset: SOL_MINT,
          amount: AMOUNT * BigInt(real),
          blinding: deriveBlinding(seed, 32),
          zoneProgramId: zone,
        })
      : createProofOutput({
          ownerTag: new Uint8Array(32) as Bytes32,
          asset: SOL_MINT,
          amount: 0n,
          blinding: deriveBlinding(seed, 32 + index),
        }),
  );
  const externalData = createExternalData({
    instructionDiscriminator: authority ? 3 : 2,
    expiryUnixTs: 0n,
    relayerFee: 0,
    publicSolAmount: 0n,
    userSolAccount: encodeBase58(new Uint8Array(32)) as Address,
    userSplToken: SOL_MINT,
    splTokenInterface: SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16) as Bytes16,
    outputs: outputs.map(() => ({
      utxoHash: new Uint8Array(32) as Bytes32,
      ownerTag: { kind: "inline" as const, value: new Uint8Array(32) as Bytes32 },
      data: new Uint8Array(),
    })),
    resolvedOwnerTags: outputs.map(() => new Uint8Array(32) as Bytes32),
    messages: [],
  });
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: bytes(zoneOracle.expected.payerPubkeyHashBytes) as Bytes32,
    inputUtxos: inputs,
    outputs,
    externalData,
  });
  if (p256) {
    const signature = signing.sign(privateMessage(inputs, outputs, externalData.hash()));
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  const indexer = new ProveIndexer(tree);
  const spendProofs = indexRealInputs(indexer, inputs);
  return { proofInputs, spendProofs, zone };
}

export function buildZoneWitness(
  rail: "eddsa" | "p256",
  shape: Readonly<{ inputs: number; outputs: number }>,
) {
  const built = buildZoneInputs(rail === "p256", shape, false);
  return rail === "p256"
    ? assembleZoneP256(built.proofInputs, built.spendProofs, built.zone)
    : assembleZone(built.proofInputs, built.spendProofs, built.zone);
}

export function buildZoneAuthorityWitness(shape: Readonly<{ inputs: number; outputs: number }>) {
  const built = buildZoneInputs(false, shape, true);
  return assembleZoneAuthority(built.proofInputs, built.spendProofs, built.zone);
}

function mergeSlots(zoneProgramId?: Address): {
  owner: ShieldedKeypair;
  nullifierKey: NullifierKey;
  slots: ProofInputUtxo[];
  tree: Address;
} {
  const tree = mergeOracle.inputs.tree as Address;
  const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const owner = ShieldedKeypair.fromKeys(
    signing,
    nullifierKey,
    ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
  );
  const seed = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
  const slots = mergeOracle.inputs.realInputAmounts.map(
    (amount, index) =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: owner.signingPublicKey(),
          asset: SOL_MINT,
          amount: BigInt(amount),
          blinding: deriveBlinding(seed, index),
          ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
        }),
        nullifierKey,
      }),
  );
  while (slots.length < 8) {
    slots.push(ProofInputUtxo.dummy(deriveBlinding(seed, slots.length)));
  }
  return { owner, nullifierKey, slots, tree };
}

export function buildMergeWitness() {
  const { owner, nullifierKey, slots, tree } = mergeSlots();
  const seed = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
  const prepared = new PreparedMerge({
    inputs: slots,
    output: createProofOutput({
      ownerAddress: owner.shieldedAddress(),
      asset: SOL_MINT,
      amount: BigInt(mergeOracle.inputs.outputAmount),
      blinding: deriveBlinding(seed, 2),
    }),
    expiryUnixTs: BigInt(mergeOracle.expected.merge.expiryUnixTs),
    signingPublicKey: owner.signingPublicKey(),
    userViewingPublicKey: owner.viewingPublicKey(),
    txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
  });
  const indexer = new ProveIndexer(tree);
  const proofs = indexRealInputs(indexer, slots);
  return assembleMergeWithProofs(
    prepared,
    {
      signingPublicKey: owner.signingPublicKey(),
      viewingPublicKey: owner.viewingPublicKey(),
      nullifierKey,
    },
    proofs,
    tree,
  );
}

export function buildMergeZoneWitness() {
  const zoneProgram = encodeBase58(bytes(mergeOracle.inputs.zoneProgramIdBytes)) as Address;
  const { owner, nullifierKey, slots, tree } = mergeSlots(zoneProgram);
  const seed = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
  const prepared = new PreparedMergeZone({
    inputs: slots,
    output: createProofOutput({
      ownerAddress: owner.shieldedAddress(),
      asset: SOL_MINT,
      amount: BigInt(mergeOracle.inputs.outputAmount),
      blinding: deriveBlinding(seed, 2),
      zoneProgramId: zoneProgram,
    }),
    expiryUnixTs: BigInt(mergeOracle.expected.mergeZone.expiryUnixTs),
    signingPublicKey: owner.signingPublicKey(),
    userViewingPublicKey: owner.viewingPublicKey(),
    txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
    zoneProgramId: zoneProgram,
  });
  const indexer = new ProveIndexer(tree);
  const proofs = indexRealInputs(indexer, slots);
  return assembleMergeZoneWithProofs(
    prepared,
    {
      signingPublicKey: owner.signingPublicKey(),
      viewingPublicKey: owner.viewingPublicKey(),
      nullifierKey,
    },
    proofs,
    tree,
  );
}
