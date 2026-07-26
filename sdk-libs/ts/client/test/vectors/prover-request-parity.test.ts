import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import { sha256Be } from "@zolana/keypair/hash";
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
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import assemblyFixtureJson from "../../../fixtures/client/public-input-assembly-v1.json" with {
  type: "json",
};
import proverShapesJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import fixtureJson from "../../../fixtures/client/prover-request-parity-v1.json" with {
  type: "json",
};
import { ClientError } from "../../src/error.js";
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import {
  checkedProverRequest,
  mergeProverRequest,
  proverRequest,
} from "../../src/prover/client.js";
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
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";
import zoneOracle from "../oracles/zone-v1.json" with { type: "json" };
import mergeOracle from "../oracles/merge-v1.json" with { type: "json" };

/// P2. Prover request parity. Request bodies come from Rust production
/// serializers (this fixture, prover-shapes, zone/merge oracles). TypeScript
/// assembles independently and compares circuitType, key set, encoding, and
/// omission-versus-null. Address-append has no TypeScript path.

const fixture = fixtureJson as ProverRequestFixture;
const assemblyFixture = assemblyFixtureJson;
const proverShapes = proverShapesJson as ProverShapesFixture;

interface RequestCase {
  readonly requestBodyJson: string;
}

interface ProverRequestFixture {
  readonly proverProtocolRevision: string;
  readonly circuitTypes: readonly string[];
  readonly typescriptPaths: Readonly<Record<string, boolean>>;
  readonly knownKeys: Readonly<Record<string, readonly string[]>>;
  readonly p256Keys: readonly string[];
  readonly expected: Readonly<{
    representatives: Readonly<Record<string, RequestCase>>;
    mixedOwner: RequestCase;
    zoneMixedOwner: RequestCase;
  }>;
}

function requestBody(value: RequestCase): Record<string, unknown> {
  return JSON.parse(value.requestBodyJson) as Record<string, unknown>;
}

const P256_KEYS = fixture.p256Keys;

function expectCode(operation: () => unknown, code: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("P2 prover request parity", () => {
  it("records the prover protocol revision and eight circuit types", () => {
    expect(fixture.proverProtocolRevision).toMatch(/^[0-9a-f]{64}$/u);
    expect(fixture.circuitTypes).toEqual([
      "transfer-confidential",
      "transfer-p256-confidential",
      "transfer-zone",
      "transfer-p256-zone",
      "transfer-zone-authority",
      "merge",
      "merge-zone",
      "address-append",
    ]);
    expect(fixture.typescriptPaths["address-append"]).toBe(false);
    for (const circuitType of fixture.circuitTypes) {
      if (circuitType === "address-append") continue;
      expect(fixture.typescriptPaths[circuitType]).toBe(true);
    }
  });

  it("rejects unknown fields and malformed field values", () => {
    const keys = fixture.knownKeys["transfer-confidential"] ?? [];
    const representative = fixture.expected.representatives["transfer-confidential"];
    if (representative === undefined) throw new Error("missing transfer-confidential representative");
    const base = requestBody(representative);
    expectCode(
      () => checkedProverRequest({ ...base, unexpectedField: "0x1" }, keys),
      "CLIENT_INVALID_FIELD",
    );
    expectCode(
      () => checkedProverRequest({ ...base, publicInputHash: "not-hex" }, keys),
      "CLIENT_INVALID_FIELD",
    );
    expectCode(
      () => checkedProverRequest({ ...base, publicInputHash: null }, keys),
      "CLIENT_INVALID_FIELD",
    );
    const withoutCircuit = { ...base };
    delete withoutCircuit["circuitType"];
    expectCode(() => checkedProverRequest(withoutCircuit, keys), "CLIENT_INVALID_FIELD");
    expect(checkedProverRequest(base, keys)["circuitType"]).toBe("transfer-confidential");
  });

  describe("confidential shapes against prover-shapes (folded)", () => {
    for (const railFixture of proverShapes.expected.rails) {
      for (const shapeFixture of railFixture.shapes) {
        const inputs = Number(shapeFixture.shape.inputs);
        const outputs = Number(shapeFixture.shape.outputs);
        it(`${railFixture.rail} ${String(inputs)}x${String(outputs)} matches Rust request bytes`, () => {
          const source = buildProofInputs(proverShapes, railFixture.rail, { inputs, outputs });
          const assembled = assemble(source.proofInputs, source.spendProofs);
          const body = proverRequest(assembled.proverInputs);
          const want = shapeFixture.proverJson;
          // prover-shapes canonicalizes object key order; values still match the
          // production serializer. Encounter order is asserted against the P2
          // knownKeys snapshot, which is taken from raw serde output.
          expect(body).toEqual(want);
          const circuitType = String(want["circuitType"]);
          const keys = fixture.knownKeys[circuitType] ?? [];
          expect(Object.keys(body)).toEqual(keys);
          expect(checkedProverRequest(body, keys)).toEqual(want);
          if (railFixture.rail === "eddsa") {
            for (const key of P256_KEYS) {
              expect(Object.hasOwn(body, key)).toBe(false);
              expect(body[key]).toBeUndefined();
            }
          } else {
            for (const key of P256_KEYS) {
              expect(typeof body[key]).toBe("string");
              expect(body[key]).not.toBeNull();
            }
          }
        });
      }
    }
  });

  it("matches the mixed-owner confidential request Rust serializes", () => {
    // Same case matrix as P1: rebuild from public-input-assembly seeds, not a
    // second hand-authored request body.
    const p256 = buildProofInputs(assemblyFixture, "p256", { inputs: 2, outputs: 2 });
    const eddsa = buildProofInputs(assemblyFixture, "eddsa", { inputs: 1, outputs: 1 });
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
    // Path bytes follow the second-input indices from the Rust mixed-owner
    // case (field_byte(47) / field_byte(51)), not the eddsa 1x1 proof's index-0
    // paths. Public-input hashes ignore path contents; the request body does not.
    const fieldByte = (value: number): Bytes32 => {
      const result = new Uint8Array(32);
      result[31] = value;
      return result as Bytes32;
    };
    const proofs = [
      p256Proof,
      {
        state: {
          ...eddsaProof.state,
          leaf: eddsaInput.hash(),
          path: Array.from({ length: 32 }, () => fieldByte(47)),
          leafIndex: 1n,
          root: fieldByte(47),
          rootIndex: 50,
        },
        nullifier: {
          ...eddsaProof.nullifier,
          leaf: eddsaInput.nullifier(),
          path: Array.from({ length: 40 }, () => fieldByte(51)),
          rootIndex: 56,
        },
      },
    ];
    const body = proverRequest(assemble(mixed, proofs).proverInputs);
    const want = requestBody(fixture.expected.mixedOwner);
    expect(body).toEqual(want);
    expect(Object.keys(body)).toEqual(Object.keys(want));
    expect(body["circuitType"]).toBe("transfer-p256-confidential");
  });

  describe("zone shapes against the zone oracle (folded)", () => {
    const ZONE = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
    const TREE = encodeBase58(bytes(zoneOracle.inputs.treeBytes)) as Address;
    const USER_SOL = encodeBase58(bytes(zoneOracle.inputs.userSolAccountBytes)) as Address;
    const AMOUNT = BigInt(zoneOracle.inputs.inputAmount);

    function fieldByte(value: number): Bytes32 {
      const result = new Uint8Array(32);
      result[31] = value;
      return result as Bytes32;
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

    function buildZone(
      p256: boolean,
      shape: Readonly<{ inputs: number; outputs: number }>,
      owners?: readonly Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }>[],
    ): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
      const defaultOwner = zoneKeypair(p256);
      const real = shape.inputs >= 2 ? 2 : 1;
      const seed = bytes(zoneOracle.inputs.blindingSeedBytes) as Bytes31;
      const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) => {
        if (index >= real) return ProofInputUtxo.dummy(deriveBlinding(seed, index));
        const owner = owners?.[index] ?? defaultOwner;
        return new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding: deriveBlinding(seed, index),
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
          blinding: deriveBlinding(seed, 32 + index),
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
        payerPublicKeyHash: sha256Be(bytes(zoneOracle.inputs.payerBytes)),
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

    for (const expected of zoneOracle.expected.transferZone as readonly Readonly<{
      shape: Readonly<{ inputs: number; outputs: number }>;
      requestBodyJson: string;
    }>[]) {
      const label = `${String(expected.shape.inputs)}x${String(expected.shape.outputs)}`;
      it(`transfer-zone ${label} request matches Rust`, () => {
        const { proofInputs, spendProofs } = buildZone(false, expected.shape);
        const body = proverRequest(assembleZone(proofInputs, spendProofs, ZONE).proverInputs);
        const want = JSON.parse(expected.requestBodyJson) as Record<string, unknown>;
        expect(body).toEqual(want);
        expect(Object.keys(body)).toEqual(Object.keys(want));
        for (const key of P256_KEYS) expect(Object.hasOwn(body, key)).toBe(false);
      });
    }

    for (const expected of zoneOracle.expected.transferP256Zone as readonly Readonly<{
      shape: Readonly<{ inputs: number; outputs: number }>;
      requestBodyJson: string;
    }>[]) {
      const label = `${String(expected.shape.inputs)}x${String(expected.shape.outputs)}`;
      it(`transfer-p256-zone ${label} request matches Rust`, () => {
        const { proofInputs, spendProofs } = buildZone(true, expected.shape);
        const body = proverRequest(assembleZoneP256(proofInputs, spendProofs, ZONE).proverInputs);
        const want = JSON.parse(expected.requestBodyJson) as Record<string, unknown>;
        expect(body).toEqual(want);
        expect(Object.keys(body)).toEqual(Object.keys(want));
      });
    }

    for (const expected of zoneOracle.expected.transferZoneAuthority as readonly Readonly<{
      shape: Readonly<{ inputs: number; outputs: number }>;
      requestBodyJson: string;
    }>[]) {
      const label = `${String(expected.shape.inputs)}x${String(expected.shape.outputs)}`;
      it(`transfer-zone-authority ${label} request matches Rust`, () => {
        const { proofInputs, spendProofs } = buildZone(false, expected.shape);
        const body = proverRequest(
          assembleZoneAuthority(proofInputs, spendProofs, ZONE).proverInputs,
        );
        const want = JSON.parse(expected.requestBodyJson) as Record<string, unknown>;
        expect(body).toEqual(want);
        expect(Object.keys(body)).toEqual(Object.keys(want));
      });
    }

    it("matches the mixed-owner zone request Rust serializes", () => {
      const p256 = zoneKeypair(true);
      const eddsa = zoneKeypair(false);
      const { proofInputs, spendProofs } = buildZone(true, { inputs: 2, outputs: 2 }, [p256, eddsa]);
      const body = proverRequest(assembleZoneP256(proofInputs, spendProofs, ZONE).proverInputs);
      const want = requestBody(fixture.expected.zoneMixedOwner);
      expect(body).toEqual(want);
      expect(Object.keys(body)).toEqual(Object.keys(want));
      expect(assemblyFixture.expected.zoneMixedOwner.inputOwnerKinds).toEqual(["p256", "eddsa"]);
    });
  });

  describe("merge rails against the merge oracle (folded)", () => {
    const TREE = mergeOracle.inputs.tree as Address;
    const ZONE_PROGRAM = encodeBase58(bytes(mergeOracle.inputs.zoneProgramIdBytes)) as Address;
    const MERGE_INPUTS = 8;

    function keypair(): Readonly<{ keypair: ShieldedKeypair; nullifierKey: NullifierKey }> {
      const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
      const nullifierKey = NullifierKey.fromSigningKey(signing);
      return {
        keypair: ShieldedKeypair.fromKeys(
          signing,
          nullifierKey,
          ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
        ),
        nullifierKey,
      };
    }

    function seed(): Bytes31 {
      return bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
    }

    function slots(owner: ShieldedKeypair, nullifierKey: NullifierKey, zone?: Address) {
      const real = mergeOracle.inputs.realInputAmounts.map(
        (amount: string, index: number) =>
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
          merkleContext: { treeType: 1, tree: TREE },
          path: Object.freeze(Array.from({ length: 32 }, () => new Uint8Array(32) as Bytes32)),
          leafIndex: BigInt(index),
          root: stateRoot as Bytes32,
          rootSeq: 1n,
          rootIndex: 40 + index,
        },
        nullifier: {
          leaf: input.nullifier(),
          merkleContext: { treeType: 1, tree: TREE },
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

    it("merge request matches Rust and always carries zoneProgramId", () => {
      const { keypair: owner, nullifierKey } = keypair();
      const inputSlots = slots(owner, nullifierKey);
      const prepared = new PreparedMerge({
        inputs: [...inputSlots],
        output: createProofOutput({
          ownerAddress: owner.shieldedAddress(),
          asset: SOL_MINT,
          amount: BigInt(mergeOracle.inputs.outputAmount),
          blinding: deriveBlinding(seed(), 2),
        }),
        expiryUnixTs: BigInt(mergeOracle.expected.merge.expiryUnixTs),
        signingPublicKey: owner.signingPublicKey(),
        userViewingPublicKey: owner.viewingPublicKey(),
        txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
      });
      const assembly = assembleMergeWithProofs(
        prepared,
        {
          signingPublicKey: owner.signingPublicKey(),
          viewingPublicKey: owner.viewingPublicKey(),
          nullifierKey,
        },
        inputSlots.filter((input) => !input.isDummy()).map(spendProof),
        TREE,
      );
      const body = mergeProverRequest(assembly.proverInputs, "merge");
      const want = JSON.parse(mergeOracle.expected.merge.requestBodyJson) as Record<
        string,
        unknown
      >;
      expect(body).toEqual(want);
      expect(Object.keys(body)).toEqual(Object.keys(want));
      expect(body["zoneProgramId"]).toBe("0x0");
      expect(Object.hasOwn(body, "zoneProgramId")).toBe(true);
    });

    it("merge-zone request matches Rust with a nonzero zone field", () => {
      const { keypair: owner, nullifierKey } = keypair();
      const inputSlots = slots(owner, nullifierKey, ZONE_PROGRAM);
      const prepared = new PreparedMergeZone({
        inputs: [...inputSlots],
        output: createProofOutput({
          ownerAddress: owner.shieldedAddress(),
          asset: SOL_MINT,
          amount: BigInt(mergeOracle.inputs.outputAmount),
          blinding: deriveBlinding(seed(), 2),
          zoneProgramId: ZONE_PROGRAM,
        }),
        expiryUnixTs: BigInt(mergeOracle.expected.mergeZone.expiryUnixTs),
        signingPublicKey: owner.signingPublicKey(),
        userViewingPublicKey: owner.viewingPublicKey(),
        txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
        zoneProgramId: ZONE_PROGRAM,
      });
      const assembly = assembleMergeZoneWithProofs(
        prepared,
        {
          signingPublicKey: owner.signingPublicKey(),
          viewingPublicKey: owner.viewingPublicKey(),
          nullifierKey,
        },
        inputSlots.filter((input) => !input.isDummy()).map(spendProof),
        TREE,
      );
      const body = mergeProverRequest(assembly.proverInputs, "merge-zone");
      const want = JSON.parse(mergeOracle.expected.mergeZone.requestBodyJson) as Record<
        string,
        unknown
      >;
      expect(body).toEqual(want);
      expect(body["zoneProgramId"]).not.toBe("0x0");
      expect(body["zoneProgramId"]).not.toBeNull();
    });
  });

  it("representative bodies match the known key sets Rust emitted", () => {
    for (const circuitType of fixture.circuitTypes) {
      const representative = fixture.expected.representatives[circuitType];
      if (representative === undefined) throw new Error(`missing representative ${circuitType}`);
      const body = requestBody(representative);
      const keys = fixture.knownKeys[circuitType] ?? [];
      expect(body["circuitType"]).toBe(circuitType);
      expect(Object.keys(body)).toEqual(keys);
      if (circuitType === "address-append") {
        expect(fixture.typescriptPaths[circuitType]).toBe(false);
        continue;
      }
      expect(checkedProverRequest(body, keys)["circuitType"]).toBe(circuitType);
    }
  });
});
