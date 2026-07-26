import { describe, expect, it } from "vitest";

import { decodeBase64, encodeBase64 } from "../src/index.js";

/**
 * Shared edge vectors for standard base64. Call sites wrap these helpers with
 * package errors; this file pins the codec so a future hand-rolled copy cannot
 * drift on empty input, padding, or non-canonical leftover bits.
 */
describe("canonical base64 vectors", () => {
  it("maps empty bytes to the empty string and back", () => {
    expect(encodeBase64(new Uint8Array())).toBe("");
    expect(decodeBase64("")).toEqual(new Uint8Array());
  });

  it("round-trips short payloads with required padding", () => {
    expect(encodeBase64(new Uint8Array([0]))).toBe("AA==");
    expect(encodeBase64(new Uint8Array([1]))).toBe("AQ==");
    expect(encodeBase64(new Uint8Array([1, 2]))).toBe("AQI=");
    expect(encodeBase64(new Uint8Array([1, 2, 3]))).toBe("AQID");
    expect(decodeBase64("AA==")).toEqual(new Uint8Array([0]));
    expect(decodeBase64("AQ==")).toEqual(new Uint8Array([1]));
    expect(decodeBase64("AQI=")).toEqual(new Uint8Array([1, 2]));
    expect(decodeBase64("AQID")).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("requires = padding when the byte length needs it", () => {
    for (const value of ["AQ", "AQI", "AA", "A"]) {
      expect(() => decodeBase64(value)).toThrow();
    }
  });

  it("rejects URL-safe alphabets, whitespace, and non-alphabet characters", () => {
    for (const value of ["AA-_", "@@@@", "AQID ", "AQID\n", "====", "A==="]) {
      expect(() => decodeBase64(value)).toThrow();
    }
  });

  it("rejects non-canonical padding bits that do not re-encode to themselves", () => {
    // AB== decodes to [0] under a bit-accumulating decoder, but canonical
    // encode of [0] is AA==. AQI= with leftover bits similarly fails.
    expect(() => decodeBase64("AB==")).toThrow();
    expect(() => decodeBase64("AAB=")).toThrow();
  });

  it("accepts only the canonical form of a padded payload", () => {
    const bytes = new Uint8Array([0xff, 0x00, 0x7e]);
    const encoded = encodeBase64(bytes);
    expect(decodeBase64(encoded)).toEqual(bytes);
    expect(encodeBase64(decodeBase64(encoded))).toBe(encoded);
  });
});
