import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const declarations = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "web",
  "pkg",
  "timelock_escrow_wasm.d.ts",
);
const text = readFileSync(declarations, "utf8");
const publicSurface = text.replace(/export interface InitOutput \{[\s\S]*?\n\}\n/, "");
const untyped = publicSurface
  .split("\n")
  .map((line, index) => ({ line, number: index + 1 }))
  .filter(({ line }) => /\bany\b/.test(line) && !line.trimStart().startsWith("*"));

if (untyped.length > 0) {
  for (const { line, number } of untyped) {
    console.error(`${declarations}:${number}: ${line.trim()}`);
  }
  console.error("the generated declarations type an export as `any`");
  process.exit(1);
}
console.log("every export in the generated declarations is typed");
