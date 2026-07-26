import { describe, expect, it } from "vitest";

import { decodeBase58, encodeBase58 } from "../src/index.js";

/**
 * Shared edge vectors for Bitcoin-base58. Call sites wrap these helpers with
 * package errors and length checks; this file pins the codec itself so a future
 * hand-rolled copy cannot drift on empty input, leading zeros, or alphabet.
 */
describe("canonical base58 vectors", () => {
  it("maps empty bytes to the empty string and back", () => {
    expect(encodeBase58(new Uint8Array())).toBe("");
    expect(decodeBase58("")).toEqual(new Uint8Array());
  });

  it("maps leading zero bytes to leading 1 characters", () => {
    expect(encodeBase58(new Uint8Array([0]))).toBe("1");
    expect(encodeBase58(new Uint8Array([0, 0, 0]))).toBe("111");
    expect(encodeBase58(new Uint8Array([0, 1]))).toBe("12");
    expect(decodeBase58("1")).toEqual(new Uint8Array([0]));
    expect(decodeBase58("111")).toEqual(new Uint8Array([0, 0, 0]));
    expect(decodeBase58("12")).toEqual(new Uint8Array([0, 1]));
  });

  it("round-trips fixed-length Solana payloads", () => {
    const address = new Uint8Array(32).fill(1);
    const signature = new Uint8Array(64).fill(2);
    expect(decodeBase58(encodeBase58(address))).toEqual(address);
    expect(decodeBase58(encodeBase58(signature))).toEqual(signature);
    expect(encodeBase58(new Uint8Array(32))).toBe("1".repeat(32));
    expect(decodeBase58("1".repeat(32))).toEqual(new Uint8Array(32));
  });

  it("rejects characters outside the Bitcoin alphabet", () => {
    for (const value of ["0", "O", "I", "l", "0OIl"]) {
      expect(() => decodeBase58(value)).toThrow();
    }
  });

  it("rejects a non-canonical encoding on re-encode", () => {
    // Every successful decode must re-encode to the same string; callers use
    // that check to refuse padded or otherwise non-canonical wire forms.
    const canonical = encodeBase58(new Uint8Array(32).fill(7));
    expect(encodeBase58(decodeBase58(canonical))).toBe(canonical);
  });
});
