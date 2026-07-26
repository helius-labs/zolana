import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants } from "@noble/curves/abstract/poseidon.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { InterfaceError } from "../../src/errors.js";
import {
  ciphertextHash,
  ownerPkFieldCompressed,
  pkFieldCompressed,
} from "../../src/merge-utils.js";

const MODULUS = BigInt(fixture.field.modulus);
const Fp = Field(MODULUS);

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

function fieldToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function digest(values: readonly bigint[]): string {
  const bytes = new Uint8Array(values.length * 32);
  values.forEach((value, index) => {
    bytes.set(fieldToBytes(value), index * 32);
  });
  return bytesToHex(sha256(bytes));
}

describe("Poseidon parameters against zolana-hasher", () => {
  it("uses the BN254 scalar field", () => {
    expect(Fp.ORDER).toBe(MODULUS);
  });

  for (const arity of fixture.parameters.perArity) {
    it(`generates the Rust round constants and MDS matrix for ${String(arity.inputs)} inputs`, () => {
      const { roundConstants, mds } = grainGenConstants({
        Fp,
        t: arity.width,
        roundsFull: fixture.parameters.roundsFull,
        roundsPartial: arity.roundsPartial,
        sboxPower: fixture.parameters.alpha,
      });
      expect(digest(roundConstants.flat())).toBe(arity.arkSha256);
      expect(digest(mds.flat())).toBe(arity.mdsSha256);
    });
  }
});

// `merge-utils.ts` keeps its Poseidon private, and `ciphertextHash` is the way
// through it: the ciphertext is cut into 16-byte big-endian chunks, so the
// chunk count is the arity and 1 to 192 bytes walks every arity the Rust hasher
// supports. 193 bytes is the first length that needs a thirteenth input.
describe("ciphertextHash against zolana-interface", () => {
  const hashes = fixture.ciphertextHashes.filter((entry) => "expectedBytes" in entry);
  const rejects = fixture.ciphertextHashes.filter((entry) => "reason" in entry);

  it("walks every supported arity", () => {
    const counts = new Set(hashes.map((entry) => entry.chunkCount));
    for (let arity = 1; arity <= fixture.parameters.maxInputs; arity += 1) {
      expect(counts).toContain(arity);
    }
  });

  for (const entry of hashes) {
    it(entry.id, () => {
      expect("expectedBytes" in entry).toBe(true);
      if (!("expectedBytes" in entry)) return;
      expect(bytesToHex(ciphertextHash(hexToBytes(entry.ciphertextBytes)))).toBe(
        entry.expectedBytes,
      );
    });
  }

  for (const entry of rejects) {
    it(entry.id, () => {
      expect(() => ciphertextHash(hexToBytes(entry.ciphertextBytes))).toThrow(InterfaceError);
    });
  }
});

// The two compressed-P256 hashes pin the input order of the low and high halves
// of `x`, which a Poseidon that agreed on every symmetric vector could still
// get backwards.
describe("P256 field hashes against zolana-interface", () => {
  for (const entry of fixture.mergeUtils.pkFields) {
    it(entry.id, () => {
      const compressed = hexToBytes(entry.compressedBytes);
      expect(bytesToHex(pkFieldCompressed(compressed))).toBe(entry.pkFieldBytes);
      expect(bytesToHex(ownerPkFieldCompressed(compressed))).toBe(entry.ownerPkFieldBytes);
    });
  }
});
