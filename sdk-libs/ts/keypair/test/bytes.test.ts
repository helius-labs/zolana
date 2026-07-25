import { describe, expect, it } from "vitest";

import { bigIntToBytes, bytesToBigInt } from "../src/bytes.js";
import { KeypairError } from "../src/error.js";

/**
 * `bigIntToBytes` is the port of `bigint_to_be_bytes_array` in
 * `program-libs/hasher/src/bigint.rs`. Rust takes a `BigUint`, so a negative
 * value cannot reach it, and it returns `HasherError::InvalidInputLength(
 * BYTES_SIZE, bytes.len())` when the value needs more bytes than the array
 * holds. The width cases below are the ones
 * `program-libs/hasher/tests/bigint.rs::test_bigint_conversion_invalid_size`
 * pins, read back as `(expected, actual)` on the thrown error.
 */
describe("big-endian bigint conversion", () => {
  it("right-aligns a value that fits", () => {
    expect(bigIntToBytes(0n)).toEqual(new Uint8Array(32));
    expect(bigIntToBytes(1n, 4)).toEqual(Uint8Array.of(0, 0, 0, 1));
    expect(bigIntToBytes(0x0102_0304n, 4)).toEqual(Uint8Array.of(1, 2, 3, 4));
    const widest = (1n << 256n) - 1n;
    expect(bigIntToBytes(widest)).toEqual(new Uint8Array(32).fill(0xff));
    expect(bytesToBigInt(bigIntToBytes(widest))).toBe(widest);
  });

  it("rejects a value wider than the array instead of truncating", () => {
    const eightBytes = bytesToBigInt(new Uint8Array(8).fill(1));
    for (const [length, actual] of [
      [1, 8],
      [7, 8],
    ] as const) {
      expectInvalidLength(() => bigIntToBytes(eightBytes, length), length, actual);
    }
    expect(bigIntToBytes(eightBytes, 8)).toEqual(new Uint8Array(8).fill(1));

    const thirtyTwoBytes = bytesToBigInt(new Uint8Array(32).fill(1));
    expectInvalidLength(() => bigIntToBytes(thirtyTwoBytes, 31), 31, 32);
    expect(bigIntToBytes(thirtyTwoBytes, 32)).toEqual(new Uint8Array(32).fill(1));

    // The default width is the one every Poseidon field crosses.
    expectInvalidLength(() => bigIntToBytes(1n << 256n), 32, 33);
  });

  it("rejects a negative value, which Rust cannot represent", () => {
    // Two's complement made `-1n` the same 32 bytes as `2n ** 256n - 1n`.
    for (const value of [-1n, -(1n << 255n)]) {
      expectInvalidLength(() => bigIntToBytes(value), 32, -1);
    }
  });
});

function expectInvalidLength(operation: () => unknown, expected: number, actual: number): void {
  try {
    operation();
    throw new Error("expected the conversion to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(KeypairError);
    expect(error).toMatchObject({
      code: "KEYPAIR_INVALID_LENGTH",
      details: { name: "bigIntToBytes", expected, actual },
    });
  }
}
