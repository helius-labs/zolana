import { describe, expect, it } from "vitest";

import * as api from "../src/index.js";

describe("browser root exports", () => {
  it("exports only the async transport and its error", () => {
    expect(Object.keys(api).sort()).toEqual(["ApiError", "ZolanaApi"]);
    expect("BlockingZolanaApi" in api).toBe(false);
    expect("GET_MERKLE_PROOFS" in api).toBe(false);
  });
});
