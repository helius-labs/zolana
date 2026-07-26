import { sha256 } from "@noble/hashes/sha2.js";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import { hashField as keypairHashField, sha256Be } from "@zolana/keypair/hash";
import { mergePublicContribution } from "@zolana/keypair/merge";
import {
  PreparedMerge,
  PreparedMergeZone,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
  type ProofOutputUtxo,
} from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import fixtureJson from "../../../fixtures/client/public-input-assembly-v1.json" with {
  type: "json",
};
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  hashField,
  poseidon,
  sha256Bytes,
} from "../../src/internal.js";
import { assemble } from "../../src/prover/index.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import {
  assembleZone,
  assembleZoneAuthority,
  assembleZoneP256,
} from "../../src/prover/zone.js";
import type { SpendProof } from "../../src/rpc.js";
import {
  buildProofInputs,
  bytes,
  hex,
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";

/// P1. Public-input assembly: every named intermediate on the confidential and
/// merge chains, rebuilt through the public TypeScript assemblers and compared
/// to values production Rust wrote. The final hash is asserted last so a miss
/// names the first divergent layer.

const fixture = fixtureJson as PublicInputFixture;
const MERGE_INPUTS = 8;

interface Chain {
  readonly nullifierChain: string;
  readonly outputHashChain: string;
  readonly utxoRootChain: string;
  readonly nullifierRootChain: string;
  readonly privateTxHash: string;
  readonly privateTxHashBytes: string;
  readonly p256MessageDigestField: string;
  readonly externalDataHash: string;
  readonly publicSolAmount: string;
  readonly publicSplAmount: string;
  readonly publicSplAssetPubkey: string;
  readonly zoneProgramId: string;
  readonly payerPubkeyHash: string;
  readonly inputOwnerChain: string;
  readonly outputOwnerChain: string;
  readonly p256SigningField: string;
  readonly p256SigningFieldBytes: string;
  readonly publicInputHash: string;
  readonly publicInputHashBytes: string;
  readonly inputOwnerPkHashes: readonly string[];
  readonly outputOwnerPkHashes: readonly string[];
  readonly p256MessageHashLow?: string;
  readonly p256MessageHashHigh?: string;
}

interface ZoneChain {
  readonly nullifierChain: string;
  readonly outputHashChain: string;
  readonly utxoRootChain: string;
  readonly nullifierRootChain: string;
  readonly externalDataHash: string;
  readonly privateTxHash: string;
  readonly p256MessageDigestField: string;
  readonly publicSolAmount: string;
  readonly publicSplAmount: string;
  readonly publicSplAssetPubkey: string;
  readonly zoneProgramId: string;
  readonly payerPubkeyHash: string;
  readonly publicInputHash: string;
  readonly inputOwnerChain: string;
  readonly inputOwnerPkHashes: readonly string[];
  readonly p256MessageHashLow?: string;
  readonly p256MessageHashHigh?: string;
  readonly p256SigningPkField?: string;
}

interface ZoneCase {
  readonly shape: Readonly<{ inputs: string; outputs: string }>;
  readonly chain: ZoneChain;
  readonly publicInputHashBytes: string;
}

interface PublicInputFixture {
  readonly inputs: ProverShapesFixture["inputs"] & {
    readonly merge: Readonly<{
      blindingSeedBytes: string;
      signingSecretBytes: string;
      viewingSeedBytes: string;
      txViewingSecretBytes: string;
      realInputAmounts: readonly string[];
      outputAmount: string;
      tree: string;
      zoneProgramIdBytes: string;
    }>;
    readonly zone: Readonly<{
      blindingSeedBytes: string;
      ed25519SecretBytes: string;
      p256SecretBytes: string;
      viewingSeedBytes: string;
      zoneProgramIdBytes: string;
      payerBytes: string;
      treeBytes: string;
      userSolAccountBytes: string;
      inputAmount: string;
    }>;
  };
  readonly expected: Readonly<{
    confidential: Readonly<{
      rails: readonly Readonly<{
        rail: "eddsa" | "p256";
        shapes: readonly Readonly<{
          shape: Readonly<{ inputs: string; outputs: string }>;
          chain: Chain;
        }>[];
      }>[];
    }>;
    mixedOwner: Readonly<{
      shape: Readonly<{ inputs: string; outputs: string }>;
      rail: "p256";
      inputOwnerKinds: readonly string[];
      chain: Chain;
    }>;
    zone: Readonly<{
      transferZone: readonly ZoneCase[];
      transferP256Zone: readonly ZoneCase[];
      transferZoneAuthority: readonly ZoneCase[];
    }>;
    zoneMixedOwner: Readonly<{
      shape: Readonly<{ inputs: string; outputs: string }>;
      rail: "p256";
      inputOwnerKinds: readonly string[];
      chain: ZoneChain;
      publicInputHashBytes: string;
    }>;
    merge: Readonly<{
      default: MergeChain;
      zone: MergeChain;
    }>;
  }>;
}

interface MergeChain {
  readonly nullifierChain: string;
  readonly outputHashBytes: string;
  readonly utxoRootChain: string;
  readonly nullifierRootChain: string;
  readonly privateTxHashBytes: string;
  readonly externalDataHashBytes: string;
  readonly publicInputHashBytes: string;
  readonly zoneProgramId: string;
  readonly ownerBindingTail: Readonly<Record<string, string>>;
}

function chainHex(values: readonly bigint[]): string {
  return hex(bigintToBytes(hashChain(values)));
}

function assertConfidentialChain(
  assembled: ReturnType<typeof assemble>,
  expected: Chain,
  rail: "eddsa" | "p256",
): void {
  const payload = assembled.proverInputs.payload;
  const nullifiers = payload.inputs.map((input) => input.nullifier);
  const outputHashes = payload.outputs.map((output) => output.hash);
  const utxoRoots = payload.inputs.map((input) => input.utxoTreeRoot);
  const nullifierRoots = payload.inputs.map((input) => input.nullifierTreeRoot);
  const inputOwners = payload.inputs.map((input) => input.ownerPublicKeyHash);
  const outputOwners = payload.outputs.map((output) => output.ownerPublicKeyHash);
  const privateTx = bigintToBytes(payload.privateTxHash);
  const p256MessageElement =
    rail === "eddsa" ? hashField(new Uint8Array(32)) : hashField(sha256Bytes(privateTx));
  const signingField =
    assembled.proverInputs.circuit === "transferP256"
      ? assembled.proverInputs.payload.p256SigningPublicKeyField
      : 0n;

  expect(chainHex(nullifiers)).toBe(expected.nullifierChain);
  expect(chainHex(outputHashes)).toBe(expected.outputHashChain);
  expect(chainHex(utxoRoots)).toBe(expected.utxoRootChain);
  expect(chainHex(nullifierRoots)).toBe(expected.nullifierRootChain);
  expect(payload.privateTxHash.toString()).toBe(expected.privateTxHash);
  expect(hex(privateTx)).toBe(expected.privateTxHashBytes);
  expect(hex(bigintToBytes(p256MessageElement))).toBe(expected.p256MessageDigestField);
  expect(payload.externalDataHash.toString()).toBe(expected.externalDataHash);
  expect(payload.publicSolAmount.toString()).toBe(expected.publicSolAmount);
  expect(payload.publicSplAmount.toString()).toBe(expected.publicSplAmount);
  expect(payload.publicSplAssetPublicKey.toString()).toBe(expected.publicSplAssetPubkey);
  expect(payload.zoneProgramId.toString()).toBe(expected.zoneProgramId);
  expect(payload.zoneProgramId).toBe(0n);
  expect(payload.payerPublicKeyHash.toString()).toBe(expected.payerPubkeyHash);
  expect(chainHex(inputOwners)).toBe(expected.inputOwnerChain);
  expect(chainHex(outputOwners)).toBe(expected.outputOwnerChain);
  expect(inputOwners.map((value) => value.toString())).toEqual(expected.inputOwnerPkHashes);
  expect(outputOwners.map((value) => value.toString())).toEqual(expected.outputOwnerPkHashes);
  expect(signingField.toString()).toBe(expected.p256SigningField);
  expect(hex(bigintToBytes(signingField))).toBe(expected.p256SigningFieldBytes);
  if (rail === "eddsa") {
    expect(signingField).toBe(0n);
    expect(p256MessageElement).toBe(hashField(new Uint8Array(32)));
  } else {
    const p256 = assembled.proverInputs;
    if (p256.circuit !== "transferP256") throw new Error("expected transferP256");
    expect(p256.payload.p256MessageHashLow.toString()).toBe(expected.p256MessageHashLow);
    expect(p256.payload.p256MessageHashHigh.toString()).toBe(expected.p256MessageHashHigh);
    expect(signingField).not.toBe(0n);
  }
  expect(payload.publicInputHash.toString()).toBe(expected.publicInputHash);
  expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
  // Re-fold the fifteen confidential elements so a stubbed final hash that
  // ignored an intermediate still fails even when the leaf fields match.
  expect(
    chainHex([
      hashChain(nullifiers),
      hashChain(outputHashes),
      hashChain(utxoRoots),
      hashChain(nullifierRoots),
      payload.privateTxHash,
      p256MessageElement,
      payload.externalDataHash,
      payload.publicSolAmount,
      payload.publicSplAmount,
      payload.publicSplAssetPublicKey,
      payload.zoneProgramId,
      payload.payerPublicKeyHash,
      hashChain(inputOwners),
      hashChain(outputOwners),
      signingField,
    ]),
  ).toBe(expected.publicInputHashBytes);
}

describe("P1 confidential public-input assembly", () => {
  for (const railFixture of fixture.expected.confidential.rails) {
    for (const shapeFixture of railFixture.shapes) {
      const inputs = Number(shapeFixture.shape.inputs);
      const outputs = Number(shapeFixture.shape.outputs);
      it(`${railFixture.rail} ${String(inputs)}x${String(outputs)} matches every named intermediate`, () => {
        const source = buildProofInputs(fixture, railFixture.rail, { inputs, outputs });
        const assembled = assemble(source.proofInputs, source.spendProofs);
        assertConfidentialChain(assembled, shapeFixture.chain, railFixture.rail);
      });
    }
  }

  it("matches the mixed P256 and Ed25519 owner chain", () => {
    const expected = fixture.expected.mixedOwner;
    const p256 = buildProofInputs(fixture, "p256", { inputs: 2, outputs: 2 });
    const eddsa = buildProofInputs(fixture, "eddsa", { inputs: 1, outputs: 1 });
    const p256Input = p256.proofInputs.inputUtxos[0];
    const eddsaInput = eddsa.proofInputs.inputUtxos[0];
    const p256Proof = p256.spendProofs[0];
    const eddsaProof = eddsa.spendProofs[0];
    const signature = p256.proofInputs.p256Signature();
    if (!p256Input || !eddsaInput || !p256Proof || !eddsaProof || !signature) {
      throw new Error("missing mixed fixture input");
    }
    const mixed = new SppProofInputs({
      payerPublicKeyHash: p256.proofInputs.payerPublicKeyHash,
      inputUtxos: [p256Input, eddsaInput],
      outputs: p256.proofInputs.outputs,
      externalData: p256.proofInputs.externalData,
    });
    mixed.applyP256Signature(signature);
    const proofs = [
      p256Proof,
      {
        state: {
          ...eddsaProof.state,
          leaf: eddsaInput.hash(),
          leafIndex: 1n,
          rootIndex: 50,
        },
        nullifier: {
          ...eddsaProof.nullifier,
          leaf: eddsaInput.nullifier(),
          rootIndex: 56,
        },
      },
    ];
    const assembled = assemble(mixed, proofs);
    expect(expected.inputOwnerKinds).toEqual(["p256", "eddsa"]);
    expect(assembled.instructionData.inputs.map((input) => input.eddsaSignerIndex)).toEqual([
      255, 0,
    ]);
    assertConfidentialChain(assembled, expected.chain, "p256");
  });
});

describe("P1 zone public-input assembly", () => {
  const zoneInputs = fixture.inputs.zone;
  const ZONE = encodeBase58(bytes(zoneInputs.zoneProgramIdBytes)) as Address;
  const TREE = encodeBase58(bytes(zoneInputs.treeBytes)) as Address;
  const USER_SOL = encodeBase58(bytes(zoneInputs.userSolAccountBytes)) as Address;
  const AMOUNT = BigInt(zoneInputs.inputAmount);

  function fieldByte(value: number): Bytes32 {
    const result = new Uint8Array(32);
    result[31] = value;
    return result as Bytes32;
  }

  function zoneKeypair(p256: boolean): Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }> {
    const signing = p256
      ? SigningKey.fromBytes(bytes(zoneInputs.p256SecretBytes) as Bytes32)
      : SigningKey.fromEd25519Bytes(bytes(zoneInputs.ed25519SecretBytes) as Bytes32);
    return {
      keypair: ShieldedKeypair.fromKeys(
        signing,
        NullifierKey.fromSigningKey(signing),
        ViewingKey.fromSeed(bytes(zoneInputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
      ),
      signing,
    };
  }

  function zoneSeed(): Bytes31 {
    return bytes(zoneInputs.blindingSeedBytes) as Bytes31;
  }

  function payerHash(): Bytes32 {
    return sha256Be(bytes(zoneInputs.payerBytes));
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
    owners?: readonly Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }>[],
  ): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
    const defaultOwner = zoneKeypair(p256);
    const real = shape.inputs >= 2 ? 2 : 1;
    const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) => {
      if (index >= real) return ProofInputUtxo.dummy(deriveBlinding(zoneSeed(), index));
      const owner = owners?.[index] ?? defaultOwner;
      return new ProofInputUtxo({
        utxo: new Utxo({
          owner: owner.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: AMOUNT,
          blinding: deriveBlinding(zoneSeed(), index),
          zoneProgramId: ZONE,
        }),
        nullifierKey: NullifierKey.fromSigningKey(owner.signing),
      });
    });
    const outputs = Array.from({ length: shape.outputs }, (_, index) =>
      createProofOutput({
        ownerTag: fieldByte(32 + index),
        asset: SOL_MINT,
        amount: index === 0 ? AMOUNT * BigInt(real) : 0n,
        blinding: deriveBlinding(zoneSeed(), 32 + index),
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
      userSolAccount: USER_SOL,
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
      const signing = (owners?.[0] ?? defaultOwner).signing;
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

  function assertZoneChain(
    assembled: ReturnType<typeof assembleZone> | ReturnType<typeof assembleZoneP256>,
    expected: ZoneChain,
    rail: "eddsa" | "p256",
  ): void {
    const payload = assembled.proverInputs.payload;
    expect(chainHex(payload.inputs.map((input) => input.nullifier))).toBe(expected.nullifierChain);
    expect(chainHex(payload.outputs.map((output) => output.hash))).toBe(expected.outputHashChain);
    expect(chainHex(payload.inputs.map((input) => input.utxoTreeRoot))).toBe(expected.utxoRootChain);
    expect(chainHex(payload.inputs.map((input) => input.nullifierTreeRoot))).toBe(
      expected.nullifierRootChain,
    );
    expect(payload.privateTxHash.toString()).toBe(expected.privateTxHash);
    expect(payload.externalDataHash.toString()).toBe(expected.externalDataHash);
    expect(payload.zoneProgramId.toString()).toBe(expected.zoneProgramId);
    expect(payload.zoneProgramId).not.toBe(0n);
    expect(payload.payerPublicKeyHash.toString()).toBe(expected.payerPubkeyHash);
    expect(payload.publicSolAmount.toString()).toBe(expected.publicSolAmount);
    expect(payload.publicSplAmount.toString()).toBe(expected.publicSplAmount);
    expect(payload.publicSplAssetPublicKey.toString()).toBe(expected.publicSplAssetPubkey);
    expect(chainHex(payload.inputs.map((input) => input.ownerPublicKeyHash))).toBe(
      expected.inputOwnerChain,
    );
    expect(payload.inputs.map((input) => input.ownerPublicKeyHash.toString())).toEqual(
      expected.inputOwnerPkHashes,
    );
    if (rail === "p256") {
      const p256 = assembled.proverInputs;
      if (p256.circuit !== "transferP256Zone") throw new Error("expected transferP256Zone");
      expect(p256.payload.p256MessageHashLow.toString()).toBe(expected.p256MessageHashLow);
      expect(p256.payload.p256MessageHashHigh.toString()).toBe(expected.p256MessageHashHigh);
      expect(p256.payload.p256SigningPublicKeyField.toString()).toBe(expected.p256SigningPkField);
    }
    expect(payload.publicInputHash.toString()).toBe(expected.publicInputHash);
    expect(hex(assembled.publicInputHash)).toBe(hex(bigintToBytes(payload.publicInputHash)));
  }

  for (const expected of fixture.expected.zone.transferZone) {
    const label = `${expected.shape.inputs}x${expected.shape.outputs}`;
    it(`transfer-zone ${label} matches every named intermediate`, () => {
      const shape = {
        inputs: Number(expected.shape.inputs),
        outputs: Number(expected.shape.outputs),
      };
      const { proofInputs, spendProofs } = buildZoneInputs(false, shape);
      const assembled = assembleZone(proofInputs, spendProofs, ZONE);
      assertZoneChain(assembled, expected.chain, "eddsa");
      expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
    });
  }

  for (const expected of fixture.expected.zone.transferP256Zone) {
    const label = `${expected.shape.inputs}x${expected.shape.outputs}`;
    it(`transfer-p256-zone ${label} matches every named intermediate`, () => {
      const shape = {
        inputs: Number(expected.shape.inputs),
        outputs: Number(expected.shape.outputs),
      };
      const { proofInputs, spendProofs } = buildZoneInputs(true, shape);
      const assembled = assembleZoneP256(proofInputs, spendProofs, ZONE);
      assertZoneChain(assembled, expected.chain, "p256");
      expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
    });
  }

  for (const expected of fixture.expected.zone.transferZoneAuthority) {
    const label = `${expected.shape.inputs}x${expected.shape.outputs}`;
    it(`transfer-zone-authority ${label} matches every named intermediate`, () => {
      const shape = {
        inputs: Number(expected.shape.inputs),
        outputs: Number(expected.shape.outputs),
      };
      const { proofInputs, spendProofs } = buildZoneInputs(false, shape);
      const assembled = assembleZoneAuthority(proofInputs, spendProofs, ZONE);
      expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
      expect(assembled.proverInputs.payload.zoneProgramId).not.toBe(0n);
      expect(assembled.proverInputs.payload.privateTxHash.toString()).toBe(
        expected.chain.privateTxHash,
      );
      expect(assembled.proverInputs.payload.zoneProgramId.toString()).toBe(
        expected.chain.zoneProgramId,
      );
      expect(assembled.proverInputs.payload.publicInputHash.toString()).toBe(
        expected.chain.publicInputHash,
      );
    });
  }

  it("matches the mixed P256 and Ed25519 zone owner chain", () => {
    const expected = fixture.expected.zoneMixedOwner;
    const p256 = zoneKeypair(true);
    const eddsa = zoneKeypair(false);
    const { proofInputs, spendProofs } = buildZoneInputs(true, { inputs: 2, outputs: 2 }, [
      p256,
      eddsa,
    ]);
    const assembled = assembleZoneP256(proofInputs, spendProofs, ZONE);
    expect(expected.inputOwnerKinds).toEqual(["p256", "eddsa"]);
    expect(assembled.proverInputs.payload.inputs.map((input) => input.ownerPublicKeyHash)).toEqual([
      0n,
      bytesToBigInt(eddsa.keypair.signingPublicKey().ownerPublicKeyField()),
    ]);
    assertZoneChain(assembled, expected.chain, "p256");
    expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
  });
});

describe("P1 merge owner-binding tails", () => {
  const mergeInputs = fixture.inputs.merge;
  const tree = mergeInputs.tree as Address;
  const zoneProgram = encodeBase58(bytes(mergeInputs.zoneProgramIdBytes)) as Address;

  function keypair(): Readonly<{ keypair: ShieldedKeypair; nullifierKey: NullifierKey }> {
    const signing = SigningKey.fromBytes(bytes(mergeInputs.signingSecretBytes) as Bytes32);
    const nullifierKey = NullifierKey.fromSigningKey(signing);
    return {
      keypair: ShieldedKeypair.fromKeys(
        signing,
        nullifierKey,
        ViewingKey.fromSeed(bytes(mergeInputs.viewingSeedBytes) as Bytes32, 0),
      ),
      nullifierKey,
    };
  }

  function seed(): Bytes31 {
    return bytes(mergeInputs.blindingSeedBytes) as Bytes31;
  }

  function slots(owner: ShieldedKeypair, nullifierKey: NullifierKey, zone?: Address) {
    const real = mergeInputs.realInputAmounts.map(
      (amount, index) =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: BigInt(amount),
            blinding: deriveBlinding(seed(), index),
            ...(zone === undefined ? {} : { zoneProgramId: zone }),
          }),
          nullifierKey,
        }),
    );
    const dummies = Array.from({ length: MERGE_INPUTS - real.length }, (_, index) =>
      ProofInputUtxo.dummy(deriveBlinding(seed(), real.length + index)),
    );
    return [...real, ...dummies];
  }

  function spendProof(input: ProofInputUtxo, index: number): SpendProof {
    const stateRoot = new Uint8Array(32);
    stateRoot[31] = 20 + index;
    const nullifierRoot = new Uint8Array(32);
    nullifierRoot[31] = 30 + index;
    return {
      state: {
        leaf: input.hash(),
        merkleContext: { treeType: 1, tree },
        path: Object.freeze(Array.from({ length: 32 }, () => new Uint8Array(32) as Bytes32)),
        leafIndex: BigInt(index),
        root: stateRoot as Bytes32,
        rootSeq: 1n,
        rootIndex: 40 + index,
      },
      nullifier: {
        leaf: input.nullifier(),
        merkleContext: { treeType: 1, tree },
        path: Object.freeze(Array.from({ length: 40 }, () => new Uint8Array(32) as Bytes32)),
        lowElement: new Uint8Array(32) as Bytes32,
        lowElementIndex: BigInt(index),
        highElement: new Uint8Array(32).fill(1) as Bytes32,
        highElementIndex: BigInt(index + 1),
        root: nullifierRoot as Bytes32,
        rootSeq: 1n,
        rootIndex: 50 + index,
      },
    };
  }

  it("binds the default merge with the registry owner-identity tail", () => {
    const expected = fixture.expected.merge.default;
    const { keypair: owner, nullifierKey } = keypair();
    const inputSlots = slots(owner, nullifierKey);
    const prepared = new PreparedMerge({
      inputs: [...inputSlots],
      output: createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: BigInt(mergeInputs.outputAmount),
        blinding: deriveBlinding(seed(), 2),
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: owner.signingPublicKey(),
      userViewingPublicKey: owner.viewingPublicKey(),
      txViewingSecret: bytes(mergeInputs.txViewingSecretBytes) as Bytes32,
    });
    const assembly = assembleMergeWithProofs(
      prepared,
      {
        signingPublicKey: owner.signingPublicKey(),
        viewingPublicKey: owner.viewingPublicKey(),
        nullifierKey,
      },
      inputSlots.filter((input) => !input.isDummy()).map(spendProof),
      tree,
    );
    const contribution = mergePublicContribution(
      assembly.txViewingPublicKey,
      assembly.ciphertext,
    );
    expect(chainHex(assembly.nullifiers.map(bytesToBigInt))).toBe(expected.nullifierChain);
    expect(hex(assembly.outputHash)).toBe(expected.outputHashBytes);
    expect(
      chainHex(assembly.proverInputs.inputs.map((input) => input.utxoTreeRoot)),
    ).toBe(expected.utxoRootChain);
    expect(
      chainHex(assembly.proverInputs.inputs.map((input) => input.nullifierTreeRoot)),
    ).toBe(expected.nullifierRootChain);
    expect(hex(assembly.privateTxHash)).toBe(expected.privateTxHashBytes);
    expect(hex(assembly.externalDataHash)).toBe(expected.externalDataHashBytes);
    expect(expected.ownerBindingTail["kind"]).toBe("default");
    expect(hex(owner.signingPublicKey().ownerPublicKeyField())).toBe(
      expected.ownerBindingTail["userSigningPkHashBytes"],
    );
    expect(hex(ShieldedPublicKey.fromP256(owner.viewingPublicKey()).hash())).toBe(
      expected.ownerBindingTail["userViewingPkHashBytes"],
    );
    expect(hex(contribution.txViewingPublicKeyLow)).toBe(
      expected.ownerBindingTail["txViewingPkLowBytes"],
    );
    expect(hex(contribution.txViewingPublicKeyHigh)).toBe(
      expected.ownerBindingTail["txViewingPkHighBytes"],
    );
    expect(hex(contribution.ciphertextHash)).toBe(expected.ownerBindingTail["ciphertextHashBytes"]);
    expect(hex(assembly.publicInputHash)).toBe(expected.publicInputHashBytes);
    expect(assembly.proverInputs.zoneProgramId).toBe(0n);
  });

  it("binds the zone merge with the zone field and without the registry tail", () => {
    const expected = fixture.expected.merge.zone;
    const { keypair: owner, nullifierKey } = keypair();
    const inputSlots = slots(owner, nullifierKey, zoneProgram);
    const prepared = new PreparedMergeZone({
      inputs: [...inputSlots],
      output: createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: BigInt(mergeInputs.outputAmount),
        blinding: deriveBlinding(seed(), 2),
        zoneProgramId: zoneProgram,
      }),
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      signingPublicKey: owner.signingPublicKey(),
      userViewingPublicKey: owner.viewingPublicKey(),
      txViewingSecret: bytes(mergeInputs.txViewingSecretBytes) as Bytes32,
      zoneProgramId: zoneProgram,
    });
    const assembly = assembleMergeZoneWithProofs(
      prepared,
      {
        signingPublicKey: owner.signingPublicKey(),
        viewingPublicKey: owner.viewingPublicKey(),
        nullifierKey,
      },
      inputSlots.filter((input) => !input.isDummy()).map(spendProof),
      tree,
    );
    const contribution = mergePublicContribution(
      assembly.txViewingPublicKey,
      assembly.ciphertext,
    );
    expect(expected.ownerBindingTail["kind"]).toBe("zone");
    expect(hex(contribution.txViewingPublicKeyLow)).toBe(
      expected.ownerBindingTail["txViewingPkLowBytes"],
    );
    expect(hex(contribution.txViewingPublicKeyHigh)).toBe(
      expected.ownerBindingTail["txViewingPkHighBytes"],
    );
    expect(hex(contribution.ciphertextHash)).toBe(expected.ownerBindingTail["ciphertextHashBytes"]);
    expect(hex(keypairHashField(bytes(mergeInputs.zoneProgramIdBytes)))).toBe(
      expected.ownerBindingTail["zoneProgramIdFieldBytes"],
    );
    expect(hex(assembly.publicInputHash)).toBe(expected.publicInputHashBytes);
    expect(hex(assembly.publicInputHash)).not.toBe(
      fixture.expected.merge.default.publicInputHashBytes,
    );
    expect(assembly.proverInputs.zoneProgramId).not.toBe(0n);
    // The registry owner hashes must not appear as the zone tail's last four
    // elements: swapping tails would still produce a well-formed hash.
    expect(expected.ownerBindingTail["userSigningPkHashBytes"]).toBeUndefined();
    expect(expected.ownerBindingTail["userViewingPkHashBytes"]).toBeUndefined();
  });
});
