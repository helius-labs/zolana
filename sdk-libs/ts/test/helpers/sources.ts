import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = fileURLToPath(new URL("../../src", import.meta.url));

/** Every TypeScript source of the package, by its path under `src`. */
export function sourceTexts(directory = SRC): ReadonlyMap<string, string> {
  const walk = (at: string): string[] =>
    readdirSync(at, { withFileTypes: true }).flatMap((entry) => {
      const path = join(at, entry.name);
      if (entry.isDirectory()) return walk(path);
      return entry.name.endsWith(".ts") ? [path] : [];
    });
  return new Map(walk(directory).map((path) => [relative(SRC, path), readFileSync(path, "utf8")]));
}
