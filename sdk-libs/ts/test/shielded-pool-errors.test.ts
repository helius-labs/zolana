import { describe, expect, it } from "vitest";

import expected from "../../../test-vectors/shielded_pool_errors.json" with { type: "json" };
import { ShieldedPoolError, decodeShieldedPoolError } from "../src/interface/index.js";

describe("shielded-pool error codes", () => {
  it("matches the shared Rust error-code fixture exactly", () => {
    expect(ShieldedPoolError).toEqual(expected);
  });

  it.each(Object.entries(expected))("decodes %s from the program's code", (name, code) => {
    expect(decodeShieldedPoolError(code)).toEqual({ kind: "known", code, name });
  });

  it.each([6999, 7066, 7071, 0xffffffff])("keeps unknown code %i unnamed", (code) => {
    expect(decodeShieldedPoolError(code)).toEqual({ kind: "unknown", code });
  });
});
