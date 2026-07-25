import { describe, expect, it } from "vitest";

import { parseProof } from "../../src/prover/proof.js";
import oracle from "../oracles/proof-canonical-v1.json" with { type: "json" };

/// Replays `sdk-libs/client/src/prover/ts_proof_oracle.rs`, which runs the real
/// `proof_from_gnark_json` over the inputs worth arguing about.
///
/// These two rows run against the direction of travel for this port. Nearly
/// every divergence found so far was TypeScript refusing input Rust accepts, and
/// the standing answer is to relax TypeScript. Here TypeScript was right twice
/// and Rust has been tightened to match, so the oracle exists partly to prove
/// the tightening landed and partly to keep the pair from drifting apart again
/// in the other direction.
///
/// The accept/reject column is the whole comparison. A coordinate parser that
/// agrees on well-formed input and disagrees on `0x0x1` is not a port of the
/// same function.

const ZERO_POINT = ["0x0", "0x0"];

/// The coordinate under test sits in `bs`. TypeScript checks that a nonzero G1
/// point lies on the curve and Rust defers that to compression, so an arbitrary
/// value in `ar` would compare the curve check rather than the coordinate
/// parser. Neither side curve-checks G2.
function body(coordinate: string, committed: boolean): Record<string, unknown> {
  const proof: Record<string, unknown> = {
    ar: ZERO_POINT,
    bs: [[coordinate, "0x0"], ZERO_POINT],
    krs: ZERO_POINT,
  };
  if (committed) {
    proof["proof_commitment"] = ZERO_POINT;
    proof["proof_commitment_pok"] = ZERO_POINT;
  }
  return proof;
}

function accepted(value: unknown, requireCommitment: boolean): boolean {
  try {
    parseProof(value, requireCommitment);
    return true;
  } catch {
    return false;
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("gnark coordinate parsing, against Rust", () => {
  for (const vector of oracle.coordinates) {
    it(`${vector.accepted ? "accepts" : "rejects"} ${vector.name}, as Rust does`, () => {
      const input = body(vector.value, false);
      expect(accepted(input, false)).toBe(vector.accepted);
      if (!vector.accepted) return;
      expect(hex(parseProof(input, false).b)).toBe(vector.b);
    });
  }
});

describe("the requested rail decides, not the response", () => {
  for (const vector of oracle.rails) {
    const requested = vector.requestedCommitment ? "p256" : "eddsa";
    const answered = vector.responseCommitment ? "a committed" : "an uncommitted";
    it(`${vector.accepted ? "accepts" : "rejects"} ${answered} proof on the ${requested} rail`, () => {
      const input = body("0x0", vector.responseCommitment);
      expect(accepted(input, vector.requestedCommitment)).toBe(vector.accepted);
      if (!vector.accepted) return;
      const proof = parseProof(input, vector.requestedCommitment);
      expect(proof.commitment !== undefined).toBe(vector.hasCommitment);
    });
  }

  /// The two commitment fields are one value. Half of it is not a commitment and
  /// must not be read as one with the other half defaulted away.
  for (const vector of oracle.halfCommitments) {
    it(`rejects ${vector.name}, as Rust does`, () => {
      expect(accepted(JSON.parse(vector.body), true)).toBe(vector.accepted);
    });
  }
});
