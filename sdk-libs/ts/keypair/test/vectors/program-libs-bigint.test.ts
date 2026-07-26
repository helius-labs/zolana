import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { bigIntToBytes } from "../../src/bytes.js";
import { KeypairError } from "../../src/error.js";

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// `merkle-tree` compares its copy of this conversion against the same Rust
// vectors. The keypair copy is separate and was unchecked, which is how it kept
// truncating silently after the other one stopped.
describe("program-libs/hasher/src/bigint.rs against keypair bigIntToBytes", () => {
  for (const vector of fixture.hasher.bigint.vectors) {
    it(`writes ${vector.name} big-endian into 32 bytes`, () => {
      expect(bytesToHex(bigIntToBytes(BigInt(vector.decimal)))).toBe(vector.be32);
    });
  }

  for (const reject of fixture.hasher.bigint.rejects) {
    it(`refuses ${reject.name}, as bigint_to_be_bytes_array does`, () => {
      expect(() => bigIntToBytes(BigInt(reject.decimal))).toThrow(KeypairError);
    });
  }

  // `bigint_to_be_bytes_array` takes a `BigUint`, so a negative value has no
  // big-endian form at all. Two's complement would silently encode a different
  // number.
  it("refuses a negative value, which BigUint cannot represent", () => {
    expect(() => bigIntToBytes(-1n)).toThrow(KeypairError);
  });

  it("honours a narrower width the way the const generic does", () => {
    expect(bytesToHex(bigIntToBytes(0xabcdn, 8))).toBe("000000000000abcd");
    expect(() => bigIntToBytes(0x1_0000_0000_0000_0000n, 8)).toThrow(KeypairError);
  });
});
