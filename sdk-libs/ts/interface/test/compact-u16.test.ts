import { describe, expect, it } from "vitest";

import { decodeCompactU16, encodeCompactU16 } from "../src/index.js";

/**
 * Shared edge vectors for Solana compact-u16 (shortvec). Pins boundary widths
 * and the Alias rejection from `solana_short_vec` so a future loose decoder
 * cannot accept non-canonical multi-byte encodings of small values.
 */
describe("canonical compact-u16 vectors", () => {
  it("encodes boundary values at the minimum width", () => {
    expect(Array.from(encodeCompactU16(0))).toEqual([0x00]);
    expect(Array.from(encodeCompactU16(127))).toEqual([0x7f]);
    expect(Array.from(encodeCompactU16(128))).toEqual([0x80, 0x01]);
    expect(Array.from(encodeCompactU16(16_383))).toEqual([0xff, 0x7f]);
    expect(Array.from(encodeCompactU16(16_384))).toEqual([0x80, 0x80, 0x01]);
    expect(Array.from(encodeCompactU16(65_535))).toEqual([0xff, 0xff, 0x03]);
  });

  it("round-trips every boundary value", () => {
    for (const value of [0, 1, 127, 128, 16_383, 16_384, 65_535]) {
      const encoded = encodeCompactU16(value);
      expect(decodeCompactU16(encoded)).toEqual({ value, length: encoded.length });
    }
  });

  it("rejects values outside u16", () => {
    for (const value of [-1, 65_536, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => encodeCompactU16(value)).toThrow();
    }
  });

  it("rejects non-canonical multi-byte aliases of small values", () => {
    // Solana VisitError::Alias: a zero byte after the first is never valid.
    for (const bytes of [
      [0x80, 0x00],
      [0x80, 0x80, 0x00],
      [0xff, 0x00],
      [0x80, 0x81, 0x00],
      [0xff, 0xff, 0x00],
    ]) {
      expect(() => decodeCompactU16(Uint8Array.from(bytes))).toThrow();
    }
  });

  it("rejects truncated, overflowing, and over-long encodings", () => {
    expect(() => decodeCompactU16(Uint8Array.from([0x80]))).toThrow();
    expect(() => decodeCompactU16(Uint8Array.from([0x80, 0x80]))).toThrow();
    expect(() => decodeCompactU16(Uint8Array.from([0x80, 0x80, 0x80]))).toThrow();
    expect(() => decodeCompactU16(Uint8Array.from([0x80, 0x80, 0x04]))).toThrow();
  });
});
