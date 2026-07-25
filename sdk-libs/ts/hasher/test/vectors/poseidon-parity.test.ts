import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { HasherWasmError, MAX_POSEIDON_INPUTS, poseidon } from "../../src/index.js";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// The same vectors the five hand-written copies are held to, replayed against
// the compiled Rust. If the artifact is stale or was built from a different
// hasher, these are what say so.
describe("Poseidon vectors against zolana-hasher", () => {
  for (const vector of fixture.vectors) {
    it(vector.id, () => {
      expect(bytesToHex(poseidon(vector.inputsBytes.map(hexToBytes)))).toBe(vector.expectedBytes);
    });
  }

  it("covers every supported arity", () => {
    const arities = new Set(fixture.vectors.map((vector) => vector.inputsBytes.length));
    for (let arity = 1; arity <= fixture.parameters.maxInputs; arity += 1) {
      expect(arities).toContain(arity);
    }
  });

  it("reads its arity ceiling off the module", () => {
    expect(MAX_POSEIDON_INPUTS).toBe(fixture.parameters.maxInputs);
  });
});

describe("Poseidon inputs the Rust hasher refuses", () => {
  for (const reject of fixture.rejects.filter((entry) => entry.kind !== "shorterThan32")) {
    it(reject.id, () => {
      expect(() => poseidon(reject.inputsBytes.map(hexToBytes))).toThrow(HasherWasmError);
    });
  }
});

// Shorter inputs are a wider domain than the Rust hasher accepts, not a
// different digest. The wrapper right-aligns them, so each one has to land on
// the Rust hash of the same value padded into 32 bytes.
describe("Poseidon short inputs", () => {
  for (const short of fixture.shortInputs) {
    it(short.id, () => {
      expect(bytesToHex(poseidon([hexToBytes(short.shortBytes)]))).toBe(short.expectedBytes);
      expect(bytesToHex(poseidon([hexToBytes(short.alignedBytes)]))).toBe(short.expectedBytes);
    });
  }
});
