import { describe, expect, it } from "vitest";

import { compressProof, parseProof } from "../src/client/prover/proof.js";
import type { Proof } from "../src/client/prover/types.js";

const ZERO_POINT = ["0x0", "0x0"];
const ZERO_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

// Solana's canonical big-endian G2 compression test point.
const G2 = new Uint8Array([
  40, 57, 233, 205, 180, 46, 35, 111, 215, 5, 23, 93, 12, 71, 118, 225, 7, 46, 247, 147, 47, 130,
  106, 189, 184, 80, 146, 103, 141, 52, 242, 25, 0, 203, 124, 176, 110, 34, 151, 212, 66, 180, 238,
  151, 236, 189, 133, 209, 17, 137, 205, 183, 168, 196, 92, 159, 75, 174, 81, 168, 18, 86, 176, 56,
  16, 26, 210, 20, 18, 81, 122, 142, 104, 62, 251, 169, 98, 141, 21, 253, 50, 130, 182, 15, 33, 109,
  228, 31, 79, 183, 88, 147, 174, 108, 4, 22, 14, 129, 168, 6, 80, 246, 254, 100, 218, 131, 94, 49,
  247, 211, 3, 245, 22, 200, 177, 91, 60, 144, 147, 174, 90, 17, 19, 189, 62, 147, 152, 18,
]);

describe("proof compression", () => {
  it("matches Solana's c1 || c0 G2 encoding", () => {
    const proof = {
      a: new Uint8Array(64),
      b: G2,
      c: new Uint8Array(64),
    } as Proof;
    expect(compressProof(proof).b).toEqual(G2.slice(0, 64));
  });

  it("ports the standard Groth16 proof without protocol-specific fields", () => {
    expect(compressProof(parseProof({ proof: ZERO_PROOF })).toTransactProof()).toEqual({
      a: new Uint8Array(32),
      b: new Uint8Array(64),
      c: new Uint8Array(32),
    });
  });

  it("rejects stale commitments and malformed points", () => {
    expect(() => parseProof({ ...ZERO_PROOF, proofCommitment: ZERO_POINT })).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }),
    );
    expect(() => parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x1"] })).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_POINT" }),
    );
    expect(() => parseProof({ ...ZERO_PROOF, ar: ["0xzz", "0x0"] })).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }),
    );
  });

  it("matches Rust's permissive gnark JSON parsing", () => {
    const withUnknownFields = parseProof({ ...ZERO_PROOF, curve: "bn254", commitments: 0 });
    const withEmptyCommitments = parseProof({
      ...ZERO_PROOF,
      proofCommitment: [],
      proofCommitmentPok: [],
    });
    const bareCoordinates = parseProof({ ...ZERO_PROOF, ar: ["1", "2"] });
    const prefixedCoordinates = parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x2"] });

    expect(withUnknownFields).toEqual(withEmptyCommitments);
    expect(bareCoordinates.a).toEqual(prefixedCoordinates.a);
  });

  it("negates proof A over the BN254 base field before compression", () => {
    const proof = parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x2"], krs: ["0x1", "0x2"] });
    const compressed = compressProof(proof);

    expect(compressed.a[0]).toBe(0x80);
    expect(compressed.a[31]).toBe(1);
    expect((compressed.a[0] ?? 0) & 0x80).toBe(0x80);
    expect((compressed.c[0] ?? 0) & 0x80).toBe(0);
  });
});
