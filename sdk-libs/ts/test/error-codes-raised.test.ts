import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RING_ERROR_CODES } from "../src/ring/error.js";
import { WALLET_ERROR_CODES } from "../src/wallet/error.js";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

function unraised(table: readonly string[], home: string): string[] {
  const text = sources(SRC)
    .filter((path) => relative(SRC, path) !== home)
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  return table.filter((code) => !text.includes(`"${code}"`));
}

describe("public error codes", () => {
  it("lists only wallet and ring codes the SDK raises", () => {
    expect(unraised(WALLET_ERROR_CODES, "wallet/error.ts")).toEqual([]);
    expect(unraised(RING_ERROR_CODES, "ring/error.ts")).toEqual([]);
  });
});
