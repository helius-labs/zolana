import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = resolve(__dirname, "../src");

/** Root modules and the barrel are unconstrained, every directory is a layer. */
const ALLOWED: Readonly<Record<string, readonly string[]>> = {
  errors: [],
  hasher: [],
  interface: ["errors", "hasher"],
  keypair: ["errors", "hasher", "interface"],
  services: ["interface"],
  indexer: ["interface"],
  transaction: ["errors", "hasher", "interface", "keypair"],
  api: ["indexer", "interface", "services"],
  flows: ["client", "interface", "transaction"],
  client: [
    "<root>",
    "api",
    "errors",
    "flows",
    "hasher",
    "indexer",
    "interface",
    "keypair",
    "services",
    "transaction",
  ],
  wallet: ["client", "errors", "flows", "hasher", "interface", "keypair", "transaction"],
  ring: [
    "client",
    "errors",
    "flows",
    "hasher",
    "interface",
    "keypair",
    "services",
    "transaction",
    "wallet",
  ],
};

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return walk(path);
    return entry.endsWith(".ts") ? [path] : [];
  });
}

function layerOf(path: string): string {
  const rel = path.slice(SRC.length + 1);
  return rel.includes(sep) ? (rel.split(sep)[0] as string) : "<root>";
}

describe("module boundaries", () => {
  it("keeps every import inside its layer's allowed set", () => {
    const violations: string[] = [];
    for (const file of walk(SRC)) {
      const layer = layerOf(file);
      if (layer === "<root>") continue;
      const allowed = ALLOWED[layer];
      expect(allowed, `unknown layer ${layer}`).toBeDefined();
      for (const match of readFileSync(file, "utf8").matchAll(/from "(\.[^"]+)"/gu)) {
        const target = resolve(file, "..", match[1] as string);
        if (!target.startsWith(SRC)) continue;
        const targetLayer = layerOf(target.endsWith(".js") ? target : join(target, "x"));
        if (targetLayer === layer) continue;
        if (!(allowed as readonly string[]).includes(targetLayer)) {
          violations.push(`${file.slice(SRC.length + 1)} -> ${targetLayer}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
