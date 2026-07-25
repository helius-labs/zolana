import { hashField, splitBigEndian128 } from "@zolana/keypair/hash";
import { describe, expect, it } from "vitest";

import { hex, oracle, outcomeOf, parseOutcome } from "./oracle.js";

/**
 * Names the exact edge behind each divergence the sampling pass found, so the
 * report carries a boundary rather than one shrunk case.
 */
describe("W-03 boundaries", () => {
  it("records every input length hashField accepts that hash_field refuses", () => {
    const accepted: number[] = [];
    for (let length = 0; length <= 64; length += 1) {
      const value = new Uint8Array(length).fill(1);
      const rust = parseOutcome(oracle.hash_field(hex(value)));
      const typescript = outcomeOf(() => hex(hashField(value)));
      if (rust.arm === "err" && typescript.arm === "ok") accepted.push(length);
    }
    // Every length except 32.
    expect(accepted).toEqual([
      ...Array.from({ length: 32 }, (_, index) => index),
      ...Array.from({ length: 32 }, (_, index) => index + 33),
    ]);
  });

  it("records that splitBigEndian128 truncates above 32 bytes", () => {
    const short = new Uint8Array(16).fill(0xab);
    const long = new Uint8Array(48).fill(0xab);
    const exact = new Uint8Array(32).fill(0xab);
    expect(splitBigEndian128(long).map(hex)).toEqual(splitBigEndian128(exact).map(hex));
    // A 16-byte input lands entirely in the high half and leaves the low half zero.
    expect(hex(splitBigEndian128(short)[0])).toBe("0".repeat(64));
    expect(parseOutcome(oracle.split_be_128(hex(short))).arm).toBe("err");
    expect(parseOutcome(oracle.split_be_128(hex(long))).arm).toBe("err");
  });

  it("records the i64 edge signed_to_field carries", () => {
    const min = -(1n << 63n);
    const max = (1n << 63n) - 1n;
    expect(parseOutcome(oracle.signed_to_field(min.toString())).arm).toBe("ok");
    expect(parseOutcome(oracle.signed_to_field(max.toString())).arm).toBe("ok");
    expect(parseOutcome(oracle.signed_to_field((min - 1n).toString())).arm).toBe("err");
    expect(parseOutcome(oracle.signed_to_field((max + 1n).toString())).arm).toBe("err");
  });
});
