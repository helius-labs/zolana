/// <reference types="node" />

/**
 * Suite P4 — cryptographic verification.
 *
 * Always-on: the test-only Rust oracle (`xtask groth16-verify`) self-checks and
 * rejects rail/shape mismatches without a live prover.
 *
 * Live (opt-in): `ZOLANA_TEST_P4=1` builds witnesses in TypeScript, proves on the
 * pinned local prover, compresses in TypeScript, and requires the oracle (same
 * `groth16-solana` decompress + verify path as the program) to accept the
 * artifact. Rejection mutations then require stable failure codes.
 *
 * Fast gate (`ZOLANA_TEST_P4=1`): confidential 1×1 eddsa, 2×3 eddsa, 2×3 p256;
 * zone 1×1 eddsa; zone-authority 1×1; merge. Full shape set: also set
 * `ZOLANA_TEST_P4_FULL=1`.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import { SPP_SUPPORTED_SHAPES } from "@zolana/interface";
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
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import { ProverClient, proveMerge, proveMergeZone } from "../../src/prover/client.js";
import { assemble } from "../../src/prover/index.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import { compressProof } from "../../src/prover/proof.js";
import {
  assembleZone,
  assembleZoneAuthority,
  assembleZoneP256,
} from "../../src/prover/zone.js";
import type { SpendProof } from "../../src/rpc.js";
import {
  callGroth16Verify,
  flipBit,
  groth16VerifySelfCheck,
  hexBytes,
  proofWire,
  type FailCode,
  type VerifyRail,
  type VerifyRequest,
} from "../helpers/groth16-verify-oracle.js";
import { ensureLocalProver, type OwnedProver } from "../helpers/p4-live-prover.js";
import {
  buildProofInputs,
  bytes,
  hex,
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";
import mergeOracle from "../oracles/merge-v1.json" with { type: "json" };
import zoneOracle from "../oracles/zone-v1.json" with { type: "json" };

const LIVE = process.env["ZOLANA_TEST_P4"] === "1";
const FULL = process.env["ZOLANA_TEST_P4_FULL"] === "1";
const fixture = proverFixtureJson as ProverShapesFixture;

const FAST_CONFIDENTIAL: readonly {
  rail: VerifyRail;
  shape: { inputs: number; outputs: number };
}[] = [
  { rail: "eddsa", shape: { inputs: 1, outputs: 1 } },
  { rail: "eddsa", shape: { inputs: 2, outputs: 3 } },
  { rail: "p256", shape: { inputs: 2, outputs: 3 } },
];

describe("P4 cryptographic verification oracle (always on)", () => {
  it("self-checks every embedded verifying key and rejects garbage", () => {
    groth16VerifySelfCheck();
  }, 120_000);

  it("classifies commitment-on-eddsa as rail_mismatch", () => {
    const result = callGroth16Verify({
      family: "confidential",
      rail: "eddsa",
      shape: { inputs: 1, outputs: 1 },
      publicInputHashBytes: "00".repeat(32),
      proof: {
        a: "00".repeat(32),
        b: "00".repeat(64),
        c: "00".repeat(32),
        commitment: "00".repeat(32),
        commitmentPok: "00".repeat(32),
      },
    });
    expect(result).toEqual({ ok: false, code: "rail_mismatch" });
  });

  it("classifies missing-commitment-on-p256 as rail_mismatch", () => {
    const result = callGroth16Verify({
      family: "confidential",
      rail: "p256",
      shape: { inputs: 2, outputs: 3 },
      publicInputHashBytes: "00".repeat(32),
      proof: {
        a: "00".repeat(32),
        b: "00".repeat(64),
        c: "00".repeat(32),
      },
    });
    expect(result).toEqual({ ok: false, code: "rail_mismatch" });
  });

  it("classifies an unsupported shape as unknown_vk", () => {
    const result = callGroth16Verify({
      family: "confidential",
      rail: "eddsa",
      shape: { inputs: 6, outputs: 6 },
      publicInputHashBytes: "00".repeat(32),
      proof: {
        a: "00".repeat(32),
        b: "00".repeat(64),
        c: "00".repeat(32),
      },
    });
    expect(result).toEqual({ ok: false, code: "unknown_vk" });
  });

  it("rejects zero points against a real zone verifying key", () => {
    const result = callGroth16Verify({
      family: "zone",
      rail: "eddsa",
      shape: { inputs: 1, outputs: 1 },
      publicInputHashBytes: "00".repeat(32),
      proof: {
        a: "00".repeat(32),
        b: "00".repeat(64),
        c: "00".repeat(32),
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(["encoding", "verification_failure"]).toContain(result.code);
  });
});

describe.skipIf(!LIVE)("P4 live TypeScript prove → groth16-solana verify", () => {
  let owned: OwnedProver;
  let client: ProverClient;

  beforeAll(async () => {
    owned = await ensureLocalProver();
    client = new ProverClient({ url: owned.url });
  }, 180_000);

  afterAll(async () => {
    await owned.stop();
  });

  const confidentialCases = FULL
    ? (["eddsa", "p256"] as const).flatMap((rail) =>
        SPP_SUPPORTED_SHAPES.map((shape) => ({
          rail,
          shape: { inputs: shape.inputs, outputs: shape.outputs },
        })),
      )
    : FAST_CONFIDENTIAL;

  for (const { rail, shape } of confidentialCases) {
    const label = `confidential ${rail} ${String(shape.inputs)}x${String(shape.outputs)}`;
    it(
      `proves and verifies ${label}`,
      async () => {
        const artifact = await proveConfidential(client, rail, shape);
        expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
        if (rail === "eddsa" && shape.inputs === 2 && shape.outputs === 3) {
          assertRejectionMatrix(artifact);
        } else {
          assertCoreRejections(artifact);
        }
      },
      900_000,
    );
  }

  it(
    "proves and verifies zone 1x1 eddsa",
    async () => {
      const artifact = await proveZone(client, "eddsa", { inputs: 1, outputs: 1 });
      expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
      assertCoreRejections(artifact);
      expectFail({ ...artifact.request, family: "confidential" }, [
        "verification_failure",
        "encoding",
      ]);
      const mutatedHash = new Uint8Array(32);
      mutatedHash[31] = 9;
      expectFail(
        { ...artifact.request, publicInputHashBytes: hexBytes(mutatedHash) },
        ["verification_failure"],
      );
    },
    900_000,
  );

  it(
    "proves and verifies zone-authority 1x1",
    async () => {
      const artifact = await proveZoneAuthority(client, { inputs: 1, outputs: 1 });
      expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
      assertCoreRejections(artifact);
      expectFail({ ...artifact.request, family: "zone", rail: "eddsa" }, [
        "verification_failure",
        "encoding",
      ]);
    },
    900_000,
  );

  it(
    "proves and verifies merge 8x1",
    async () => {
      const artifact = await proveMergeCase(client);
      expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
      assertCoreRejections(artifact);
      const { commitment: _c, commitmentPok: _p, ...bare } = artifact.request.proof;
      expectFail({ ...artifact.request, proof: bare }, ["rail_mismatch"]);
      expectFail({ ...artifact.request, family: "merge_zone" }, [
        "verification_failure",
        "encoding",
      ]);
    },
    900_000,
  );

  if (FULL) {
    for (const shape of SPP_SUPPORTED_SHAPES) {
      it(
        `proves and verifies zone eddsa ${String(shape.inputs)}x${String(shape.outputs)}`,
        async () => {
          const artifact = await proveZone(client, "eddsa", shape);
          expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
        },
        900_000,
      );
      it(
        `proves and verifies zone p256 ${String(shape.inputs)}x${String(shape.outputs)}`,
        async () => {
          const artifact = await proveZone(client, "p256", shape);
          expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
        },
        900_000,
      );
    }
    for (const shape of [
      { inputs: 1, outputs: 1 },
      { inputs: 2, outputs: 2 },
      { inputs: 3, outputs: 3 },
      { inputs: 4, outputs: 4 },
    ] as const) {
      it(
        `proves and verifies zone-authority ${String(shape.inputs)}x${String(shape.outputs)}`,
        async () => {
          const artifact = await proveZoneAuthority(client, shape);
          expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
        },
        900_000,
      );
    }
    it(
      "proves and verifies merge_zone 8x1",
      async () => {
        const artifact = await proveMergeZoneCase(client);
        expect(callGroth16Verify(artifact.request)).toEqual({ ok: true });
      },
      900_000,
    );
  }
});

interface Artifact {
  readonly request: VerifyRequest;
  readonly compressed: ReturnType<typeof compressProof>;
  readonly publicInputHash: Uint8Array;
}

function expectFail(request: VerifyRequest, codes: readonly FailCode[]): void {
  const result = callGroth16Verify(request);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("unreachable");
  expect(codes).toContain(result.code);
}

function assertCoreRejections(artifact: Artifact): void {
  const { request, compressed, publicInputHash } = artifact;
  expectFail(
    {
      ...request,
      proof: { ...request.proof, a: hexBytes(flipBit(compressed.a, 0)) },
    },
    ["verification_failure", "encoding"],
  );
  expectFail(
    {
      ...request,
      proof: { ...request.proof, b: hexBytes(flipBit(compressed.b, 0)) },
    },
    ["verification_failure", "encoding"],
  );
  expectFail(
    {
      ...request,
      proof: { ...request.proof, c: hexBytes(flipBit(compressed.c, 0)) },
    },
    ["verification_failure", "encoding"],
  );
  const wrongHash = new Uint8Array(publicInputHash);
  wrongHash[31] ^= 1;
  expectFail({ ...request, publicInputHashBytes: hexBytes(wrongHash) }, ["verification_failure"]);
  if (request.shape.inputs !== 1 || request.shape.outputs !== 1) {
    expectFail({ ...request, shape: { inputs: 1, outputs: 1 } }, [
      "verification_failure",
      "encoding",
      "unknown_vk",
    ]);
  } else if (request.family === "confidential" || request.family === "zone") {
    expectFail({ ...request, shape: { inputs: 2, outputs: 3 } }, [
      "verification_failure",
      "encoding",
    ]);
  }
  if (request.rail === "eddsa" && request.family !== "zone_authority") {
    expectFail(
      {
        ...request,
        proof: {
          ...request.proof,
          commitment: "00".repeat(32),
          commitmentPok: "00".repeat(32),
        },
      },
      ["rail_mismatch"],
    );
  }
  if (request.rail === "p256" || request.family === "merge" || request.family === "merge_zone") {
    const { commitment: _c, commitmentPok: _p, ...bare } = request.proof;
    expectFail({ ...request, proof: bare }, ["rail_mismatch"]);
    if (compressed.commitment !== undefined) {
      expectFail(
        {
          ...request,
          proof: {
            ...request.proof,
            commitment: hexBytes(flipBit(compressed.commitment.commitment, 0)),
          },
        },
        ["verification_failure", "encoding"],
      );
      expectFail(
        {
          ...request,
          proof: {
            ...request.proof,
            commitmentPok: hexBytes(flipBit(compressed.commitment.commitmentPok, 0)),
          },
        },
        ["verification_failure", "encoding"],
      );
    }
  }
}

function assertRejectionMatrix(artifact: Artifact): void {
  assertCoreRejections(artifact);
  const { request } = artifact;
  expectFail(
    { ...request, family: request.family === "confidential" ? "zone" : "confidential" },
    ["verification_failure", "encoding"],
  );
  const altered = bytes(request.publicInputHashBytes);
  altered[0] ^= 0x80;
  expectFail({ ...request, publicInputHashBytes: hexBytes(altered) }, ["verification_failure"]);
}

async function proveConfidential(
  client: ProverClient,
  rail: VerifyRail,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const source = buildProofInputs(fixture, rail, shape);
  const assembled = assemble(source.proofInputs, source.spendProofs);
  const proof = await client.prove(assembled.proverInputs);
  const compressed = compressProof(proof);
  const publicInputHash = bigintToBytes(assembled.proverInputs.payload.publicInputHash);
  return {
    compressed,
    publicInputHash,
    request: {
      family: "confidential",
      rail,
      shape,
      publicInputHashBytes: hex(publicInputHash),
      proof: proofWire(compressed),
    },
  };
}

function fieldByte(value: number): Bytes32 {
  const result = new Uint8Array(32);
  result[31] = value;
  return result as Bytes32;
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

function zoneBuild(
  p256: boolean,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
  const zone = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
  const tree = encodeBase58(bytes(zoneOracle.inputs.treeBytes)) as Address;
  const signing = p256
    ? SigningKey.fromBytes(bytes(zoneOracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(zoneOracle.inputs.ed25519SecretBytes) as Bytes32);
  const owner = ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(bytes(zoneOracle.inputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
  );
  const seed = bytes(zoneOracle.inputs.blindingSeedBytes) as Bytes31;
  const amount = BigInt(zoneOracle.inputs.inputAmount);
  const real = shape.inputs >= 2 ? 2 : 1;
  const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) =>
    index < real
      ? new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount,
            blinding: deriveBlinding(seed, index),
            zoneProgramId: zone,
          }),
          nullifierKey: NullifierKey.fromSigningKey(signing),
        })
      : ProofInputUtxo.dummy(deriveBlinding(seed, index)),
  );
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    createProofOutput({
      ownerTag: fieldByte(32 + index),
      asset: SOL_MINT,
      amount: index === 0 ? amount * BigInt(real) : 0n,
      blinding: deriveBlinding(seed, 32 + index),
      zoneProgramId: zone,
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
    userSolAccount: encodeBase58(bytes(zoneOracle.inputs.userSolAccountBytes)) as Address,
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
  const spendProofs = proofInputs.inputUtxoHashes().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 32 }, () => fieldByte(73 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(74 + index),
      rootSeq: 75n,
      rootIndex: 76 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree },
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

async function proveZone(
  client: ProverClient,
  rail: VerifyRail,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const zone = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
  const built = zoneBuild(rail === "p256", shape);
  const assembled =
    rail === "p256"
      ? assembleZoneP256(built.proofInputs, built.spendProofs, zone)
      : assembleZone(built.proofInputs, built.spendProofs, zone);
  const proof = await client.prove(assembled.proverInputs);
  const compressed = compressProof(proof);
  return {
    compressed,
    publicInputHash: assembled.publicInputHash,
    request: {
      family: "zone",
      rail,
      shape,
      publicInputHashBytes: hex(assembled.publicInputHash),
      proof: proofWire(compressed),
    },
  };
}

async function proveZoneAuthority(
  client: ProverClient,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const zone = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
  const built = zoneBuild(false, shape);
  const assembled = assembleZoneAuthority(built.proofInputs, built.spendProofs, zone);
  const proof = await client.prove(assembled.proverInputs);
  const compressed = compressProof(proof);
  return {
    compressed,
    publicInputHash: assembled.publicInputHash,
    request: {
      family: "zone_authority",
      shape,
      publicInputHashBytes: hex(assembled.publicInputHash),
      proof: proofWire(compressed),
    },
  };
}

function mergeMaterial(owner: ShieldedKeypair, nullifierKey: NullifierKey) {
  return {
    signingPublicKey: owner.signingPublicKey(),
    viewingPublicKey: owner.viewingPublicKey(),
    nullifierKey,
  };
}

function mergeSpend(input: ProofInputUtxo, tree: Address, index: number): SpendProof {
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

async function proveMergeCase(client: ProverClient): Promise<Artifact> {
  const tree = mergeOracle.inputs.tree as Address;
  const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const owner = ShieldedKeypair.fromKeys(
    signing,
    nullifierKey,
    ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
  );
  const seed = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
  const slots = [
    ...mergeOracle.inputs.realInputAmounts.map(
      (amount, index) =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: BigInt(amount),
            blinding: deriveBlinding(seed, index),
          }),
          nullifierKey,
        }),
    ),
  ];
  while (slots.length < 8) {
    slots.push(ProofInputUtxo.dummy(deriveBlinding(seed, slots.length)));
  }
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
  const proofs = slots.filter((input) => !input.isDummy()).map((input, index) => {
    const originalIndex = slots.indexOf(input);
    return mergeSpend(input, tree, originalIndex >= 0 ? originalIndex : index);
  });
  const assembly = assembleMergeWithProofs(
    prepared,
    mergeMaterial(owner, nullifierKey),
    proofs,
    tree,
  );
  const proof = await proveMerge(client, assembly.proverInputs);
  const compressed = compressProof(proof);
  return {
    compressed,
    publicInputHash: assembly.publicInputHash,
    request: {
      family: "merge",
      shape: { inputs: 8, outputs: 1 },
      publicInputHashBytes: hex(assembly.publicInputHash),
      proof: proofWire(compressed),
    },
  };
}

async function proveMergeZoneCase(client: ProverClient): Promise<Artifact> {
  const tree = mergeOracle.inputs.tree as Address;
  const zoneProgram = encodeBase58(bytes(mergeOracle.inputs.zoneProgramIdBytes)) as Address;
  const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
  const nullifierKey = NullifierKey.fromSigningKey(signing);
  const owner = ShieldedKeypair.fromKeys(
    signing,
    nullifierKey,
    ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
  );
  const seed = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
  const slots = [
    ...mergeOracle.inputs.realInputAmounts.map(
      (amount, index) =>
        new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: BigInt(amount),
            blinding: deriveBlinding(seed, index),
            zoneProgramId: zoneProgram,
          }),
          nullifierKey,
        }),
    ),
  ];
  while (slots.length < 8) {
    slots.push(ProofInputUtxo.dummy(deriveBlinding(seed, slots.length)));
  }
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
  const proofs = slots.filter((input) => !input.isDummy()).map((input) => {
    const originalIndex = slots.indexOf(input);
    return mergeSpend(input, tree, originalIndex);
  });
  const assembly = assembleMergeZoneWithProofs(
    prepared,
    mergeMaterial(owner, nullifierKey),
    proofs,
    tree,
  );
  const proof = await proveMergeZone(client, assembly.proverInputs);
  const compressed = compressProof(proof);
  return {
    compressed,
    publicInputHash: assembly.publicInputHash,
    request: {
      family: "merge_zone",
      shape: { inputs: 8, outputs: 1 },
      publicInputHashBytes: hex(assembly.publicInputHash),
      proof: proofWire(compressed),
    },
  };
}
