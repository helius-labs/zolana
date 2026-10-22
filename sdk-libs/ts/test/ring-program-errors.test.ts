import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RingProgramError } from "../src/ring/error.js";

describe("RingProgramError", () => {
  it("names every code of the Rust `CustomRingError` and no retired one", () => {
    const rust = readFileSync(
      new URL("../../../custom-rings/interface/src/error.rs", import.meta.url),
      "utf8",
    );
    const codes = [...rust.matchAll(/^\s+([A-Z][A-Za-z0-9]*) = (\d+) =>/gmu)].map(
      ([, name = "", code = ""]) => [`${name[0]?.toLowerCase()}${name.slice(1)}`, Number(code)],
    );
    expect(codes).toContainEqual(["insertFeeAboveMax", 8235]);
    expect(Object.entries(RingProgramError)).toEqual(codes);
    expect(Object.values(RingProgramError)).not.toContain(8154);
  });
});
