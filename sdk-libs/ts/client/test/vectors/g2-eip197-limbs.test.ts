import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { compressProof } from "../../src/prover/proof.js";
import type { Proof } from "../../src/prover/types.js";
import { proofWire, rustCompressProof } from "../helpers/groth16-verify-oracle.js";

const vectorPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../vectors/g2-eip197-live-v1.json",
);

interface LiveVector {
  readonly uncompressedBHex: string;
}

describe("G2 gnark c1-first limbs (live prover B)", () => {
  const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as LiveVector;
  const b = Uint8Array.from(Buffer.from(vector.uncompressedBHex, "hex"));

  it("compressProof accepts the live point and matches Solana compress", () => {
    const proof: Proof = Object.freeze({
      a: new Uint8Array(64),
      b,
      c: new Uint8Array(64),
    });
    const compressed = compressProof(proof);
    const rust = rustCompressProof(proofWire(proof));
    expect(Buffer.from(compressed.b).toString("hex")).toBe(rust.b);
  });
});
