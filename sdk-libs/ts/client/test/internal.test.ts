import { describe, expect, it } from "vitest";

import { compareBytes } from "../src/internal.js";

describe("compareBytes", () => {
  it("orders equal buffers as equal", () => {
    expect(compareBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(0);
  });

  it("orders by the first differing byte", () => {
    expect(compareBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 9, 3))).toBeLessThan(0);
    expect(compareBytes(Uint8Array.of(1, 9, 3), Uint8Array.of(1, 2, 3))).toBeGreaterThan(0);
  });

  it("treats a proper prefix as shorter, not equal", () => {
    const prefix = Uint8Array.of(1, 2, 3);
    const extension = Uint8Array.of(1, 2, 3, 4);
    // The old client helper stopped at left.length and returned 0 here.
    expect(compareBytes(prefix, extension)).toBeLessThan(0);
    expect(compareBytes(extension, prefix)).toBeGreaterThan(0);
  });
});
