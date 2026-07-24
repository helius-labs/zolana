import { describe, expect, it } from "vitest";

import * as api from "../src/index.js";
import { ApiError, ZolanaApi, type ZolanaApiConfig } from "../src/index.js";

const CONFIG = {
  url: "https://rpc.example.test",
} satisfies ZolanaApiConfig;

describe("browser root exports", () => {
  it("exports only the async transport and its error", () => {
    expect(Object.keys(api).sort()).toEqual(["ApiError", "ZolanaApi"]);
    expect(api.ApiError).toBe(ApiError);
    expect(api.ZolanaApi).toBe(ZolanaApi);
    expect(new ZolanaApi(CONFIG)).toBeInstanceOf(ZolanaApi);
    expect("BlockingZolanaApi" in api).toBe(false);
    expect("GET_MERKLE_PROOFS" in api).toBe(false);
  });
});
