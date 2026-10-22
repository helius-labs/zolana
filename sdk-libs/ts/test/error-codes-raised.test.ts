import { describe, expect, it } from "vitest";

import { RING_ERROR_CODES } from "../src/ring/error.js";
import { WALLET_ERROR_CODES } from "../src/wallet/error.js";

import { sourceTexts } from "./helpers/sources.js";

function unraised(table: readonly string[], home: string): string[] {
  const text = [...sourceTexts()]
    .filter(([path]) => path !== home)
    .map(([, source]) => source)
    .join("\n");
  return table.filter((code) => !text.includes(`"${code}"`));
}

describe("public error codes", () => {
  it("lists only wallet and ring codes the SDK raises", () => {
    expect(unraised(WALLET_ERROR_CODES, "wallet/error.ts")).toEqual([]);
    expect(unraised(RING_ERROR_CODES, "ring/error.ts")).toEqual([]);
  });
});
