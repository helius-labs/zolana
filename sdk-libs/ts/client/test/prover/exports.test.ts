import { describe, expect, it } from "vitest";

import * as prover from "../../src/prover/index.js";

/// Frozen runtime surface of `@zolana/client/prover`. A dropped or added name
/// fails here, which is the only evidence that catches an accidental change to
/// the subpath: the zone and forester prover entry points that Rust
/// `prover::mod` also re-exports are deferred to PKP-05 and must stay absent
/// until they are ported with their fixtures.
const EXPORTS = [
  "DEFAULT_ASYNC_POLL_CONFIG",
  "PROVE_PATH",
  "ProofInputUtxo",
  "ProverClient",
  "SERVER_ADDRESS",
  "SPP_SUPPORTED_SHAPES",
  "assemble",
  "canonicalShape",
  "compressProof",
  "compressedProof",
  "createDummyTransferInput",
  "intoProver",
  "parseProof",
  "proveMerge",
  "proveMergeZone",
  "resolveShape",
] as const;

describe("prover subpath exports", () => {
  it("exports exactly the frozen name set", () => {
    expect(Object.keys(prover).sort()).toEqual([...EXPORTS].sort());
  });

  it("resolves shapes through the transaction implementation", () => {
    expect(prover.canonicalShape(1, 2)).toEqual({ inputs: 1, outputs: 2 });
    expect(prover.resolveShape(1, 2, { inputs: 1, outputs: 2 })).toEqual({
      inputs: 1,
      outputs: 2,
    });
    expect(prover.SPP_SUPPORTED_SHAPES.length).toBeGreaterThan(0);
  });
});
