import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";

function packageManifest(): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as Record<
    string,
    unknown
  >;
}

describe("public exports", () => {
  it("pins the runtime export surface", () => {
    expect(Object.keys(root).sort()).toEqual([
      "KitError",
      "createKitRpc",
      "fromAccountRole",
      "fromKitAddress",
      "fromKitInstruction",
      "fromKitSigner",
      "fromKitTransaction",
      "toAccountRole",
      "toKitAddress",
      "toKitInstruction",
      "toKitSigner",
      "toKitTransaction",
    ]);
  });

  it("keeps the builders on their own entry point", () => {
    const manifest = packageManifest();
    expect(Object.keys(manifest["exports"] as object)).toEqual([".", "./instructions"]);
    expect(manifest["files"]).toEqual(["dist"]);
    expect(manifest["sideEffects"]).toBe(false);
  });

  it("keeps @solana/kit an optional peer so no consumer downloads it unasked", () => {
    const manifest = packageManifest();
    const dependencies = manifest["dependencies"] as Record<string, string>;
    expect(dependencies).toEqual({
      "@zolana/client": "0.1.0",
      "@zolana/interface": "0.1.0",
    });
    expect(Object.keys(dependencies).filter((name) => name.startsWith("@solana/"))).toEqual([]);
    expect(manifest["peerDependencies"]).toEqual({ "@solana/kit": "^7.0.0" });
    expect(manifest["peerDependenciesMeta"]).toEqual({ "@solana/kit": { optional: true } });
  });
});
