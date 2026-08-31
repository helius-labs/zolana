import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SRC = [join(ROOT, "src")];
const TESTS = ["test", "api/test", "transaction/test", "wallet/test"].map((dir) => join(ROOT, dir));

/** Compile-time program id constants, the one place a bare brand cast is trusted. */
const ALLOWED_AS_ADDRESS = new Set(["src/ring/config.ts"]);
/** The checked Kit signature bridge, both sides are 64-byte brands over the same bytes. */
const ALLOWED_DOUBLE_CAST = new Set(["src/keypair/shielded.ts"]);
/** The one audited launder for partial client fakes. */
const ALLOWED_FAKE_LAUNDER = new Set(["test/helpers/clients.ts"]);

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

function offenders(
  roots: readonly string[],
  pattern: RegExp,
  allowed: ReadonlySet<string>,
): string[] {
  return roots
    .flatMap(sourceFiles)
    .map((path) => relative(ROOT, path))
    .filter((file) => !allowed.has(file) && pattern.test(readFileSync(join(ROOT, file), "utf8")));
}

describe("cast restrictions", () => {
  it("decodes wire strings instead of casting them to Address or Signature", () => {
    expect(offenders(SRC, /as (Address|Signature)[^A-Za-z]/u, ALLOWED_AS_ADDRESS)).toEqual([]);
  });

  it("keeps double casts out of production code", () => {
    expect(offenders(SRC, /as unknown as/u, ALLOWED_DOUBLE_CAST)).toEqual([]);
  });

  it("builds client fakes through the shared helpers, not casts", () => {
    const launder = /as (?:object|never|unknown) as \w*(?:Client|Reader|Assembler|RpcAccess)/u;
    expect(offenders(TESTS, launder, ALLOWED_FAKE_LAUNDER)).toEqual([]);
  });
});
