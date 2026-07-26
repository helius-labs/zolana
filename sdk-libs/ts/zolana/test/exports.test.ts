import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

function packageManifest(): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as Record<
    string,
    unknown
  >;
}

describe("@helius/zolana", () => {
  it("publishes the root and kit entry points", () => {
    const manifest = packageManifest();
    expect(manifest["name"]).toBe("@helius/zolana");
    expect(Object.keys(manifest["exports"] as object)).toEqual([".", "./kit"]);
    expect(manifest["files"]).toEqual(["dist"]);
    expect(manifest["sideEffects"]).toBe(false);
  });

  it("depends on the fine-grained packages without pulling @solana/kit at the root", () => {
    const manifest = packageManifest();
    expect(manifest["dependencies"]).toEqual({
      "@zolana/client": "0.1.0",
      "@zolana/interface": "0.1.0",
      "@zolana/keypair": "0.1.0",
      "@zolana/kit": "0.1.0",
      "@zolana/transaction": "0.1.0",
      "@zolana/wallet": "0.1.0",
    });
    expect(manifest["peerDependencies"]).toBeUndefined();
  });
});
