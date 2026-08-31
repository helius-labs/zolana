import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

/** Compile-time program id constants, the one place a bare brand cast is trusted. */
const ALLOWED_AS_ADDRESS = new Set(["ring/config.ts"]);
/** The checked Kit signature bridge, both sides are 64-byte brands over the same bytes. */
const ALLOWED_DOUBLE_CAST = new Set(["keypair/shielded.ts"]);

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

function offenders(pattern: RegExp, allowed: ReadonlySet<string>): string[] {
  return sourceFiles(SRC).flatMap((path) => {
    const file = relative(SRC, path);
    if (allowed.has(file)) return [];
    return pattern.test(readFileSync(path, "utf8")) ? [file] : [];
  });
}

describe("cast restrictions", () => {
  it("decodes wire strings instead of casting them to Address or Signature", () => {
    expect(offenders(/as (Address|Signature)[^A-Za-z]/u, ALLOWED_AS_ADDRESS)).toEqual([]);
  });

  it("keeps double casts out of production code", () => {
    expect(offenders(/as unknown as/u, ALLOWED_DOUBLE_CAST)).toEqual([]);
  });
});
