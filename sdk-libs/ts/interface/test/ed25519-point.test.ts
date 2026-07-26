import { describe, expect, it } from "vitest";

import { isEd25519Point } from "../src/pda/index.js";

describe("isEd25519Point", () => {
  it("rejects the x == 0 && sign == 1 compressed encoding", () => {
    // y = 1 => x² = 0; sign bit set makes the encoding invalid on Ed25519.
    const encoding = new Uint8Array(32);
    encoding[0] = 1;
    encoding[31] = 0x80;
    expect(isEd25519Point(encoding)).toBe(false);
  });

  it("accepts y = 1 with sign == 0 as the identity encoding", () => {
    const encoding = new Uint8Array(32);
    encoding[0] = 1;
    expect(isEd25519Point(encoding)).toBe(true);
  });
});
