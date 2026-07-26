import { SPP_SUPPORTED_SHAPES, type Address, type Bytes32 } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import { proverRequest, mergeProverRequest } from "../../src/prover/client.js";
import { assemble } from "../../src/prover/index.js";
import {
  assembleZone,
  assembleZoneAuthority,
  assembleZoneP256,
} from "../../src/prover/zone.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import proverShapesJson from "../../../fixtures/client/prover-shapes-v1.json" with {
  type: "json",
};
import zoneOracle from "../oracles/zone-v1.json" with { type: "json" };
import mergeOracle from "../oracles/merge-v1.json" with { type: "json" };
import {
  buildProofInputs,
  bytes,
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import {
  PreparedMerge,
  PreparedMergeZone,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  deriveBlinding,
  type ProofOutputUtxo,
  SppProofInputs,
} from "@zolana/transaction";
import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Bytes16, Bytes31, Bytes33 } from "@zolana/interface";
import type { P256PublicKey } from "@zolana/keypair";
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import type { SpendProof } from "../../src/rpc.js";

/// Gate line: EdDSA and P256 rails cover the complete supported shape set.
/// Pins the ten-shape authority list and asserts every TypeScript rail that
/// claims a shape can serialize a prover request for it. Live prove coverage
/// is the separate "same-revision prover" gate and is not claimed here.

const AUTHORITATIVE_SHAPES: readonly (readonly [number, number])[] = [
  [1, 1],
  [1, 2],
  [2, 2],
  [2, 3],
  [3, 3],
  [4, 3],
  [4, 4],
  [5, 3],
  [5, 4],
  [1, 8],
];

const ZONE_AUTHORITY_SHAPES: readonly (readonly [number, number])[] = [
  [1, 1],
  [2, 2],
  [3, 3],
  [4, 4],
];

const proverShapes = proverShapesJson as ProverShapesFixture;
const ZONE = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
const TREE = encodeBase58(bytes(zoneOracle.inputs.treeBytes)) as Address;
const USER_SOL_ACCOUNT = encodeBase58(bytes(zoneOracle.inputs.userSolAccountBytes)) as Address;
const AMOUNT = BigInt(zoneOracle.inputs.inputAmount);

function fieldByte(value: number): Bytes32 {
  const result = new Uint8Array(32);
  result[31] = value;
  return result as Bytes32;
}

function shapeLabel(inputs: number, outputs: number): string {
  return `${String(inputs)}x${String(outputs)}`;
}

function zoneKeypair(p256: boolean): Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }> {
  const signing = p256
    ? SigningKey.fromBytes(bytes(zoneOracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(zoneOracle.inputs.ed25519SecretBytes) as Bytes32);
  return {
    keypair: ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromSeed(bytes(zoneOracle.inputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
    ),
    signing,
  };
}

function seed(): Bytes31 {
  return bytes(zoneOracle.inputs.blindingSeedBytes) as Bytes31;
}

function payerHash(): Bytes32 {
  return bytes(zoneOracle.expected.payerPubkeyHashBytes) as Bytes32;
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

function buildZoneInputs(
  p256: boolean,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
  const { keypair: owner, signing } = zoneKeypair(p256);
  const real = shape.inputs >= 2 ? 2 : 1;
  const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) =>
    index < real
      ? new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding: deriveBlinding(seed(), index),
            zoneProgramId: ZONE,
          }),
          nullifierKey: NullifierKey.fromSigningKey(signing),
        })
      : ProofInputUtxo.dummy(deriveBlinding(seed(), index)),
  );
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    createProofOutput({
      ownerTag: fieldByte(32 + index),
      asset: SOL_MINT,
      amount: index === 0 ? AMOUNT * BigInt(real) : 0n,
      blinding: deriveBlinding(seed(), 32 + index),
      zoneProgramId: ZONE,
    }),
  );
  const resolvedOwnerTags = outputs.map((output) => {
    if (output.ownerTag === undefined) throw new Error("zone output lacks owner tag");
    return output.ownerTag;
  });
  const externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    publicSolAmount: -5n,
    userSolAccount: USER_SOL_ACCOUNT,
    userSplToken: SOL_MINT,
    splTokenInterface: SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33).fill(71) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16).fill(72) as Bytes16,
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
  if (p256) {
    const signature = signing.sign(privateMessage(inputs, outputs, externalData.hash()));
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  const spendProofs = proofInputs.inputUtxoHashes().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 32 }, () => fieldByte(73 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(74 + index),
      rootSeq: 75n,
      rootIndex: 76 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree: TREE },
      path: Array.from({ length: 40 }, () => fieldByte(77 + index)),
      lowElement: fieldByte(78),
      lowElementIndex: BigInt(index),
      highElement: fieldByte(79),
      highElementIndex: BigInt(index + 1),
      root: fieldByte(80 + index),
      rootSeq: 81n,
      rootIndex: 82 + index,
    },
  }));
  return { proofInputs, spendProofs };
}

describe("authoritative SPP shape set", () => {
  it("matches the ten shapes pinned in Rust, Go, and the on-chain verifier", () => {
    expect(SPP_SUPPORTED_SHAPES.map((shape) => [shape.inputs, shape.outputs])).toEqual(
      AUTHORITATIVE_SHAPES.map(([inputs, outputs]) => [inputs, outputs]),
    );
    expect(proverShapes.expected.rails.map((rail) => rail.rail)).toEqual(["eddsa", "p256"]);
    for (const rail of proverShapes.expected.rails) {
      expect(rail.shapes.map((entry) => [Number(entry.shape.inputs), Number(entry.shape.outputs)])).toEqual(
        AUTHORITATIVE_SHAPES.map(([inputs, outputs]) => [inputs, outputs]),
      );
    }
  });
});

describe("confidential rails build a prover request for every supported shape", () => {
  for (const rail of ["eddsa", "p256"] as const) {
    for (const [inputs, outputs] of AUTHORITATIVE_SHAPES) {
      const label = shapeLabel(inputs, outputs);
      it(`${rail} ${label} serializes circuitType and arity`, () => {
        const source = buildProofInputs(proverShapes, rail, { inputs, outputs });
        const body = proverRequest(assemble(source.proofInputs, source.spendProofs).proverInputs);
        expect(body["circuitType"]).toBe(
          rail === "eddsa" ? "transfer-confidential" : "transfer-p256-confidential",
        );
        expect(body["nInputs"]).toBe(inputs);
        expect(body["nOutputs"]).toBe(outputs);
      });
    }
  }
});

describe("zone rails build a prover request for every supported shape", () => {
  for (const [inputs, outputs] of AUTHORITATIVE_SHAPES) {
    const label = shapeLabel(inputs, outputs);
    it(`transfer-zone ${label} serializes a nonzero zone field`, () => {
      const { proofInputs, spendProofs } = buildZoneInputs(false, { inputs, outputs });
      const body = proverRequest(assembleZone(proofInputs, spendProofs, ZONE).proverInputs);
      expect(body["circuitType"]).toBe("transfer-zone");
      expect(body["nInputs"]).toBe(inputs);
      expect(body["nOutputs"]).toBe(outputs);
      expect(body["zoneProgramId"]).not.toBe("0x0");
    });
    it(`transfer-p256-zone ${label} serializes a nonzero zone field`, () => {
      const { proofInputs, spendProofs } = buildZoneInputs(true, { inputs, outputs });
      const body = proverRequest(assembleZoneP256(proofInputs, spendProofs, ZONE).proverInputs);
      expect(body["circuitType"]).toBe("transfer-p256-zone");
      expect(body["nInputs"]).toBe(inputs);
      expect(body["nOutputs"]).toBe(outputs);
      expect(body["zoneProgramId"]).not.toBe("0x0");
    });
  }

  for (const [inputs, outputs] of ZONE_AUTHORITY_SHAPES) {
    const label = shapeLabel(inputs, outputs);
    it(`transfer-zone-authority ${label} serializes the authority circuit`, () => {
      const { proofInputs, spendProofs } = buildZoneInputs(false, { inputs, outputs });
      const body = proverRequest(
        assembleZoneAuthority(proofInputs, spendProofs, ZONE).proverInputs,
      );
      expect(body["circuitType"]).toBe("transfer-zone-authority");
      expect(body["nInputs"]).toBe(inputs);
      expect(body["nOutputs"]).toBe(outputs);
      expect(body["zoneProgramId"]).not.toBe("0x0");
    });
  }
});

describe("merge rails build the fixed 8x1 prover request", () => {
  const mergeTree = mergeOracle.inputs.tree as Address;
  const zoneProgram = encodeBase58(bytes(mergeOracle.inputs.zoneProgramIdBytes)) as Address;

  function mergeMaterial(): Readonly<{
    keypair: ShieldedKeypair;
    nullifierKey: NullifierKey;
    prepared: PreparedMerge;
    preparedZone: PreparedMergeZone;
    proofs: readonly SpendProof[];
    zoneProofs: readonly SpendProof[];
  }> {
    const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
    const nullifierKey = NullifierKey.fromSigningKey(signing);
    const keypair = ShieldedKeypair.fromKeys(
      signing,
      nullifierKey,
      ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
    );
    const blinding = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
    const real = mergeOracle.inputs.realInputAmounts.map(
      (amount: string, index: number) =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: BigInt(amount),
            blinding: deriveBlinding(blinding, index),
          }),
          nullifierKey,
        }),
    );
    const zoneReal = real.map(
      (input) =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: input.utxo.owner,
            asset: input.utxo.asset,
            amount: input.utxo.amount,
            blinding: input.utxo.blinding,
            zoneProgramId: zoneProgram,
          }),
          nullifierKey: input.nullifierKey,
        }),
    );
    const dummies = Array.from({ length: 8 - real.length }, (_, index) =>
      ProofInputUtxo.dummy(deriveBlinding(blinding, index + real.length)),
    );
    const prepared = new PreparedMerge({
      inputs: [...real, ...dummies],
      output: createProofOutput({
        ownerAddress: keypair.shieldedAddress(),
        asset: SOL_MINT,
        amount: BigInt(mergeOracle.inputs.outputAmount),
        blinding: deriveBlinding(blinding, 2),
      }),
      expiryUnixTs: BigInt(mergeOracle.expected.merge.expiryUnixTs),
      signingPublicKey: keypair.signingPublicKey(),
      userViewingPublicKey: keypair.viewingPublicKey(),
      txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
    });
    const preparedZone = new PreparedMergeZone({
      inputs: [...zoneReal, ...dummies],
      output: createProofOutput({
        ownerAddress: keypair.shieldedAddress(),
        asset: SOL_MINT,
        amount: BigInt(mergeOracle.inputs.outputAmount),
        blinding: deriveBlinding(blinding, 2),
        zoneProgramId: zoneProgram,
      }),
      expiryUnixTs: BigInt(mergeOracle.expected.mergeZone.expiryUnixTs),
      signingPublicKey: keypair.signingPublicKey(),
      userViewingPublicKey: keypair.viewingPublicKey(),
      txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
      zoneProgramId: zoneProgram,
    });
    function proofsFor(inputs: readonly ProofInputUtxo[]): readonly SpendProof[] {
      return inputs.map((input, index) => ({
        state: {
          leaf: input.hash(),
          merkleContext: { treeType: 1, tree: mergeTree },
          path: Array.from({ length: 32 }, () => fieldByte(10 + index)),
          leafIndex: BigInt(index),
          root: fieldByte(11 + index),
          rootSeq: 12n,
          rootIndex: 13 + index,
        },
        nullifier: {
          leaf: input.nullifier(),
          merkleContext: { treeType: 2, tree: mergeTree },
          path: Array.from({ length: 40 }, () => fieldByte(14 + index)),
          lowElement: fieldByte(15),
          lowElementIndex: BigInt(index),
          highElement: fieldByte(16),
          highElementIndex: BigInt(index + 1),
          root: fieldByte(17 + index),
          rootSeq: 18n,
          rootIndex: 19 + index,
        },
      }));
    }
    return {
      keypair,
      nullifierKey,
      prepared,
      preparedZone,
      proofs: proofsFor(real),
      zoneProofs: proofsFor(zoneReal),
    };
  }

  it("merge 8x1 serializes the default-zone circuit", () => {
    const { keypair, nullifierKey, prepared, proofs } = mergeMaterial();
    const assembly = assembleMergeWithProofs(
      prepared,
      {
        signingPublicKey: keypair.signingPublicKey(),
        viewingPublicKey: keypair.viewingPublicKey(),
        nullifierKey,
      },
      proofs,
      mergeTree,
    );
    const body = mergeProverRequest(assembly.proverInputs, "merge");
    expect(body["circuitType"]).toBe("merge");
    expect(body["zoneProgramId"]).toBe("0x0");
  });

  it("merge-zone 8x1 serializes the zone-bound circuit", () => {
    const { keypair, nullifierKey, preparedZone, zoneProofs } = mergeMaterial();
    const assembly = assembleMergeZoneWithProofs(
      preparedZone,
      {
        signingPublicKey: keypair.signingPublicKey(),
        viewingPublicKey: keypair.viewingPublicKey(),
        nullifierKey,
      },
      zoneProofs,
      mergeTree,
    );
    const body = mergeProverRequest(assembly.proverInputs, "merge-zone");
    expect(body["circuitType"]).toBe("merge-zone");
    expect(body["zoneProgramId"]).not.toBe("0x0");
  });
});
