import { PROVING_KEY_SHA256S } from "../../src/interface/proving-keys.js";

const ZERO_POINT = ["0x0", "0x0"];

/**
 * The key file the Go prover proves a posted request with, mirroring its
 * `determineTransferKeyPath`, `mergeKeyPath` and `determineRingKeyPath`.
 */
function provingKeyNameOf(body: Record<string, unknown>): string {
  const circuitType = String(body["circuitType"]);
  if (circuitType === "merge") return `merge_${(body["inputs"] as unknown[]).length}_1.key`;
  if (circuitType.startsWith("custom-ring-")) return `${circuitType.replaceAll("-", "_")}.key`;
  return `${circuitType.replaceAll("-", "_")}_${String(body["nInputs"])}_${String(body["nOutputs"])}.key`;
}

/**
 * A zero proof as the prover returns it for a posted request (the JSON body
 * or its parsed value), reporting the proving key that request is proven with.
 */
export function proofFor(body: unknown): Record<string, unknown> {
  const request = (typeof body === "string" ? JSON.parse(body) : body) as Record<string, unknown>;
  const sha256 = PROVING_KEY_SHA256S[provingKeyNameOf(request)];
  if (sha256 === undefined) throw new Error("the posted shape has no proving key");
  return {
    ar: ZERO_POINT,
    bs: [ZERO_POINT, ZERO_POINT],
    krs: ZERO_POINT,
    provingKeySha256: sha256,
  };
}
