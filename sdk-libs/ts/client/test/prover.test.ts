import { describe, expect, it } from "vitest";

import { ClientError } from "../src/index.js";
import { compressProof } from "../src/prover/index.js";
import { parseProof } from "../src/prover/proof.js";
import "./prover/eddsa.test.js";
import "./prover/p256.test.js";

const ZERO_POINT = ["0x0", "0x0"];
const ZERO_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

function expectCode(operation: () => unknown, code: string): ClientError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return error as ClientError;
  }
  throw new Error("expected operation to fail");
}

describe("prover proof conversion", () => {
  it("ports the frozen zero-point gnark response and eddsa packing exactly", () => {
    const proof = parseProof({ proof: ZERO_PROOF }, false);
    const compressed = compressProof(proof);

    expect(compressed.a).toEqual(new Uint8Array(32));
    expect(compressed.b).toEqual(new Uint8Array(64));
    expect(compressed.c).toEqual(new Uint8Array(32));
    expect(compressed.toTransactProof()).toEqual({
      rail: "eddsa",
      a: new Uint8Array(32),
      b: new Uint8Array(64),
      c: new Uint8Array(32),
    });
  });

  it("preserves both mandatory P256 commitment points", () => {
    const proof = parseProof(
      {
        ...ZERO_PROOF,
        proof_commitment: ZERO_POINT,
        proof_commitment_pok: ZERO_POINT,
      },
      true,
    );

    expect(compressProof(proof).toTransactProof()).toEqual({
      rail: "p256",
      a: new Uint8Array(32),
      b: new Uint8Array(64),
      c: new Uint8Array(32),
      commitment: new Uint8Array(32),
      commitmentPok: new Uint8Array(32),
    });
  });

  it("rejects rail confusion, partial commitments, and malformed points", () => {
    expectCode(() => parseProof(ZERO_PROOF, true), "CLIENT_PROOF_RAIL_MISMATCH");
    expectCode(
      () => parseProof({ ...ZERO_PROOF, proof_commitment: ZERO_POINT }, true),
      "CLIENT_PROOF_PARSE",
    );
    expectCode(
      () => parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x1"] }, false),
      "CLIENT_PROOF_POINT",
    );
    expectCode(
      () => parseProof({ ...ZERO_PROOF, ar: ["0xzz", "0x0"] }, false),
      "CLIENT_PROOF_PARSE",
    );
    expectCode(() => parseProof({ ...ZERO_PROOF, ar: ["", "0x0"] }, false), "CLIENT_PROOF_PARSE");
  });

  /// `GnarkProofJson` is a plain serde struct with no `deny_unknown_fields`, so
  /// the Rust client ignores any key the prover adds. Rejecting them here would
  /// mean a prover release that adds one field keeps working through the Rust
  /// SDK and breaks only through this one.
  it("ignores gnark fields the Rust parser ignores", () => {
    const proof = parseProof({ ...ZERO_PROOF, curve: "bn254", commitments: 0 }, false);

    expect(proof.commitment).toBeUndefined();
    expect(proof.a).toEqual(new Uint8Array(64));
  });

  /// Rust decides the rail on `Vec::is_empty()`, so `proof_commitment: []` reads
  /// as an eddsa proof there. Reading a present-but-empty array as a commitment
  /// would reject a response the Rust client accepts.
  it("reads an empty commitment array as no commitment, as Rust does", () => {
    const proof = parseProof(
      { ...ZERO_PROOF, proof_commitment: [], proof_commitment_pok: [] },
      false,
    );

    expect(proof.commitment).toBeUndefined();
  });

  /// `hex_to_be_32` strips an optional `0x` and parses the rest as hexadecimal,
  /// so a producer that omits the prefix is read correctly by the Rust client.
  it("accepts a coordinate without the 0x prefix, as Rust does", () => {
    const prefixed = parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x2"] }, false);
    const bare = parseProof({ ...ZERO_PROOF, ar: ["1", "2"] }, false);

    expect(bare.a).toEqual(prefixed.a);
  });

  it("negates proof A over the BN254 base field before compression", () => {
    const proof = parseProof({ ...ZERO_PROOF, ar: ["0x1", "0x2"], krs: ["0x1", "0x2"] }, false);
    const compressed = compressProof(proof);

    expect(compressed.a[0]).toBe(0x80);
    expect(compressed.a[31]).toBe(1);
    expect((compressed.a[0] ?? 0) & 0x80).toBe(0x80);
    expect((compressed.c[0] ?? 0) & 0x80).toBe(0);
  });
});
