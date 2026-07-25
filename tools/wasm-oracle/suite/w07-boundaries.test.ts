import { describe, expect, it } from "vitest";

import { oracle, parseOutcome } from "./oracle.js";

/** `HIGHEST_ADDRESS_PLUS_ONE`, the sentinel that closes the indexed range. */
const HIGHEST_ADDRESS_PLUS_ONE = (1n << 248n) - 1n;

function roundTrip(value: bigint): ReturnType<typeof parseOutcome> {
  return parseOutcome(
    oracle.indexed_non_inclusion_proof_round_trip(
      JSON.stringify({
        hasher: "poseidon",
        height: "2",
        canopyDepth: "0",
        values: [],
        value: value.toString(),
      }),
    ),
  );
}

/**
 * Names the edge behind the indexed divergence the sampling pass found. The
 * round trip keeps both calls on one tree in Rust, so a rejection is Rust
 * disagreeing with itself and not an artifact of the boundary.
 */
describe("W-07 boundaries", () => {
  it("verifies its own proof strictly inside the range", () => {
    expect(roundTrip(1n).arm).toBe("ok");
    expect(roundTrip(HIGHEST_ADDRESS_PLUS_ONE - 1n).arm).toBe("ok");
  });

  /**
   * Rust used to hand back a proof here and then reject it with
   * `NonInclusionProofFailedHigherBoundViolated`. The value is now refused
   * before a proof is built, which is what TypeScript has always done.
   */
  it("refuses to build a proof at or above the sentinel", () => {
    for (const value of [HIGHEST_ADDRESS_PLUS_ONE, HIGHEST_ADDRESS_PLUS_ONE + 1n, 1n << 248n]) {
      const outcome = roundTrip(value);
      expect(outcome.arm).toBe("err");
      if (outcome.arm !== "err") return;
      expect(outcome.code).toBe("ValueOutsideIndexedRange");
    }
  });
});
