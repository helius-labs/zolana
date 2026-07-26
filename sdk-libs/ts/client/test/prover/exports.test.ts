import { describe, expect, it } from "vitest";

import * as prover from "../../src/prover/index.js";

/// Frozen runtime surface of `@zolana/client/prover`. A dropped or added name
/// fails here, which is the only evidence that catches an accidental change to
/// the subpath. The three zone assemblers and the zone-authority proof-inputs
/// bridge joined it when the ruling of 2026-07-25 withdrew their deferral; the
/// forester's address-append entry point stays absent, because TypeScript ships
/// no forester to call it.
const EXPORTS = [
  "DEFAULT_ASYNC_POLL_CONFIG",
  "PROVE_PATH",
  "SppProofInputUtxo",
  "ProverClient",
  "SERVER_ADDRESS",
  "SPP_SUPPORTED_SHAPES",
  "assemble",
  "assembleZone",
  "assembleZoneAuthority",
  "assembleZoneAuthorityProofInputs",
  "assembleZoneP256",
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
