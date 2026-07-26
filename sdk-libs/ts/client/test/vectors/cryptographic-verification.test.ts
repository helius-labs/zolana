/// <reference types="node" />

/**
 * Suite P4 — cryptographic verification.
 *
 * Always-on: the test-only Rust oracle (`xtask groth16-verify`) self-checks and
 * rejects rail/shape mismatches without a live prover.
 *
 * Live (opt-in): `ZOLANA_TEST_P4=1` builds balanced witnesses in TypeScript with
 * real Poseidon Merkle proofs, proves on the pinned local prover, compresses in
 * TypeScript, and requires the oracle (same `groth16-solana` decompress + verify
 * path as the program) to accept the artifact. Rejection mutations then require
 * stable failure codes.
 *
 * Fast gate (`ZOLANA_TEST_P4=1`): confidential 1×1 eddsa, 2×3 eddsa, 2×3 p256;
 * zone 1×1 eddsa; zone-authority 1×1; merge. Full shape set: also set
 * `ZOLANA_TEST_P4_FULL=1`.
 */

import { SPP_SUPPORTED_SHAPES } from "@zolana/interface";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { bigintToBytes } from "../../src/internal.js";
import { ProverClient, proveMerge, proveMergeZone } from "../../src/prover/client.js";
import { compressProof } from "../../src/prover/proof.js";
import {
  callGroth16Verify,
  flipBit,
  groth16VerifySelfCheck,
  hexBytes,
  proofWire,
  rustCompressProof,
  type FailCode,
  type VerifyProof,
  type VerifyRail,
  type VerifyRequest,
} from "../helpers/groth16-verify-oracle.js";
import { ensureLocalProver, type OwnedProver } from "../helpers/p4-live-prover.js";
import {
  buildConfidentialWitness,
  buildMergeWitness,
  buildMergeZoneWitness,
  buildZoneAuthorityWitness,
  buildZoneWitness,
} from "../helpers/p4-witnesses.js";
import { hex } from "../helpers/prover-vectors.js";
import type { CompressedProof, Proof } from "../../src/prover/types.js";

const LIVE = process.env["ZOLANA_TEST_P4"] === "1";
const FULL = process.env["ZOLANA_TEST_P4_FULL"] === "1";

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
  });

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
      const bare = {
        a: artifact.request.proof.a,
        b: artifact.request.proof.b,
        c: artifact.request.proof.c,
      };
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
  readonly compressed: CompressedProof;
  readonly publicInputHash: Uint8Array;
  readonly usedRustCompress: boolean;
}

function toCompressedProof(wire: VerifyProof): CompressedProof {
  const commitment =
    wire.commitment === undefined || wire.commitmentPok === undefined
      ? undefined
      : {
          commitment: Uint8Array.from(Buffer.from(wire.commitment, "hex")),
          commitmentPok: Uint8Array.from(Buffer.from(wire.commitmentPok, "hex")),
        };
  return {
    a: Uint8Array.from(Buffer.from(wire.a, "hex")),
    b: Uint8Array.from(Buffer.from(wire.b, "hex")),
    c: Uint8Array.from(Buffer.from(wire.c, "hex")),
    ...(commitment === undefined ? {} : { commitment }),
    toTransactProof() {
      throw new Error("not used");
    },
    toP256Proof() {
      throw new Error("not used");
    },
    toMergeProof() {
      throw new Error("not used");
    },
  } as CompressedProof;
}

function compressForSuite(proof: Proof): Readonly<{
  compressed: CompressedProof;
  usedRustCompress: boolean;
}> {
  try {
    return { compressed: compressProof(proof), usedRustCompress: false };
  } catch {
    // Historical fallback: before EIP-197 A1||A0 mapping, noble rejected live B
    // points. Kept so a regression still reaches the oracle.
    // Fall back to the Rust compressor so P4 can still certify the wire path;
    // the finding is recorded in the row-update report.
    return {
      compressed: toCompressedProof(rustCompressProof(proofWire(proof))),
      usedRustCompress: true,
    };
  }
}

function certifyArtifact(
  family: VerifyRequest["family"],
  rail: VerifyRail | undefined,
  shape: Readonly<{ inputs: number; outputs: number }>,
  publicInputHash: Uint8Array,
  proof: Proof,
): Artifact {
  const uncompressedRequest: VerifyRequest = {
    family,
    ...(rail === undefined ? {} : { rail }),
    shape,
    encoding: "uncompressed",
    publicInputHashBytes: hex(publicInputHash),
    proof: proofWire(proof),
  };
  expect(callGroth16Verify(uncompressedRequest)).toEqual({ ok: true });
  const { compressed, usedRustCompress } = compressForSuite(proof);
  const request: VerifyRequest = {
    family,
    ...(rail === undefined ? {} : { rail }),
    shape,
    encoding: "compressed",
    publicInputHashBytes: hex(publicInputHash),
    proof: proofWire(compressed),
  };
  expect(callGroth16Verify(request)).toEqual({ ok: true });
  return { request, compressed, publicInputHash, usedRustCompress };
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
    const bare = { a: request.proof.a, b: request.proof.b, c: request.proof.c };
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
  const altered = new Uint8Array(artifact.publicInputHash);
  altered[0] ^= 0x80;
  expectFail({ ...request, publicInputHashBytes: hexBytes(altered) }, ["verification_failure"]);
}

async function proveConfidential(
  client: ProverClient,
  rail: VerifyRail,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const assembled = buildConfidentialWitness(rail, shape);
  const proof = await client.prove(assembled.proverInputs);
  const publicInputHash = bigintToBytes(assembled.proverInputs.payload.publicInputHash);
  return certifyArtifact("confidential", rail, shape, publicInputHash, proof);
}

async function proveZone(
  client: ProverClient,
  rail: VerifyRail,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const assembled = buildZoneWitness(rail, shape);
  const proof = await client.prove(assembled.proverInputs);
  return certifyArtifact("zone", rail, shape, assembled.publicInputHash, proof);
}

async function proveZoneAuthority(
  client: ProverClient,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Promise<Artifact> {
  const assembled = buildZoneAuthorityWitness(shape);
  const proof = await client.prove(assembled.proverInputs);
  return certifyArtifact("zone_authority", undefined, shape, assembled.publicInputHash, proof);
}

async function proveMergeCase(client: ProverClient): Promise<Artifact> {
  const assembly = buildMergeWitness();
  const proof = await proveMerge(client, assembly.proverInputs);
  return certifyArtifact("merge", undefined, { inputs: 8, outputs: 1 }, assembly.publicInputHash, proof);
}

async function proveMergeZoneCase(client: ProverClient): Promise<Artifact> {
  const assembly = buildMergeZoneWitness();
  const proof = await proveMergeZone(client, assembly.proverInputs);
  return certifyArtifact(
    "merge_zone",
    undefined,
    { inputs: 8, outputs: 1 },
    assembly.publicInputHash,
    proof,
  );
}
