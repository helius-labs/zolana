// The file-loading entry point, held against the inlined one. Two ways to
// reach a hasher is the shape the five hand-written Poseidons had, so what
// matters here is that only the loading differs: the artifact on disk has to be
// the artifact in the base64, and the digests have to be the fixture's.
//
// Reading the file with `node:fs` is this test's business, not the package's.
// `@zolana/hasher/slim` takes what the caller resolved precisely so that the
// host call stays outside the browser gate.
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

import { build } from "esbuild";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import fixture from "../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { initializePoseidon, POSEIDON_ARTIFACT_BYTES, resetPoseidonForTests } from "@zolana/hasher";
import * as slim from "@zolana/hasher/slim";

const require = createRequire(import.meta.url);
const artifactPath = require.resolve("@zolana/hasher/poseidon.wasm");
let artifact: Uint8Array;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

beforeAll(async () => {
  artifact = await readFile(artifactPath);
});

// Both entry points hold one instance, so a test that loads the file has to put
// the suite's inlined instance back.
afterEach(async () => {
  resetPoseidonForTests();
  await initializePoseidon();
});

describe("@zolana/hasher/slim", () => {
  it("ships the same artifact the default entry point inlines", () => {
    expect(artifact.byteLength).toBe(POSEIDON_ARTIFACT_BYTES);
  });

  it("hashes every Poseidon vector from the file", async () => {
    resetPoseidonForTests();
    await slim.initializePoseidon(artifact);
    expect(fixture.vectors.length).toBeGreaterThan(0);
    for (const vector of fixture.vectors) {
      expect(bytesToHex(slim.poseidon(vector.inputsBytes.map(hexToBytes)))).toBe(
        vector.expectedBytes,
      );
    }
  });

  // A browser reaches the file through `fetch`, and a host that labels it
  // `application/octet-stream` sends the loader down its buffered fallback.
  // Both arrive at the same digest or the fallback is not a fallback.
  it.each(["application/wasm", "application/octet-stream"])(
    "accepts a Response served as %s",
    async (contentType) => {
      const [vector] = fixture.vectors;
      if (vector === undefined) throw new Error("the Poseidon fixture is empty");
      resetPoseidonForTests();
      await slim.initializePoseidon(
        new Response(artifact, { headers: { "content-type": contentType } }),
      );
      expect(bytesToHex(slim.poseidon(vector.inputsBytes.map(hexToBytes)))).toBe(
        vector.expectedBytes,
      );
    },
  );

  it("refuses to hash before it is loaded, naming the missing call", () => {
    resetPoseidonForTests();
    expect(() => slim.poseidon([hexToBytes("01")])).toThrow(/initializePoseidon/);
  });

  // The saving is the whole reason this entry point exists, so it is asserted
  // rather than described. The inlined build is what a consumer pays today.
  it("bundles without the inlined artifact", async () => {
    const bundle = async (entryPoint: string): Promise<number> => {
      const result = await build({
        stdin: { contents: `export * from ${JSON.stringify(entryPoint)};`, resolveDir: import.meta.dirname },
        bundle: true,
        write: false,
        conditions: ["browser", "import"],
        format: "esm",
        platform: "browser",
        target: "es2022",
        minify: true,
      });
      return result.outputFiles[0]?.contents.byteLength ?? 0;
    };
    expect(await bundle("@zolana/hasher/slim")).toBeLessThan(4_096);
    expect(await bundle("@zolana/hasher")).toBeGreaterThan(POSEIDON_ARTIFACT_BYTES);
  });
});
