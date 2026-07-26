import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";

const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;
const packageJson = (): Record<string, unknown> =>
  JSON.parse(readText(new URL("../package.json", import.meta.url), "utf8")) as Record<
    string,
    unknown
  >;

describe("public exports", () => {
  it("pins the runtime export surface", () => {
    expect(Object.keys(root).sort()).toEqual([
      "IndexedMerkleTree",
      "IndexedMerkleTreeError",
      "MerkleTree",
      "MerkleTreeError",
      "keccakHasher",
      "poseidonHasher",
      "sha256Hasher",
      "verifyNonInclusionProof",
    ]);
  });

  /**
   * The crate is two modules, `lib.rs` and `indexed`, and the port publishes one
   * entry point covering both. Asserted so a subpath added here has to be a
   * decision rather than a side effect of adding a file.
   */
  it("publishes one entry point, matching the crate's single public surface", () => {
    const manifest = packageJson();
    expect(Object.keys(manifest.exports as Record<string, unknown>)).toEqual(["."]);
    expect(manifest.files).toEqual(["dist"]);
    expect(manifest.sideEffects).toBe(false);
  });

  it("names one error type per Rust error enum", () => {
    const source = readText(new URL("../../../merkle-tree/src/lib.rs", import.meta.url), "utf8");
    const indexed = readText(
      new URL("../../../merkle-tree/src/indexed.rs", import.meta.url),
      "utf8",
    );
    expect(source).toContain("pub enum ReferenceMerkleTreeError");
    expect(indexed).toContain("pub enum IndexedReferenceMerkleTreeError");
    expect(new root.MerkleTreeError("MERKLE_TREE_INDEX", "x").name).toBe("MerkleTreeError");
    expect(new root.IndexedMerkleTreeError("INDEXED_MERKLE_TREE_INDEX", "x").name).toBe(
      "IndexedMerkleTreeError",
    );
  });
});
