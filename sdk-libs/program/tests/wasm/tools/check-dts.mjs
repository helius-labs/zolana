import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const declarations = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "web",
  "pkg",
  "wasm_test_program.d.ts",
);
// Xark's runtime, which spr-program links into the module, takes these
// functions' inputs and options as untyped values in its 0.3.0 release.
const XARK_RUNTIME_UNTYPED = new Set([
  "beginKeyTranscode",
  "beginStreamingProof",
  "encodeInputs",
  "preloadStreaming",
  "prove",
  "proveStreaming",
  "proveStreamingPreloaded",
  "prove_preloaded",
]);
const exportName = line => line.match(/^\s*(?:export function\s+)?([A-Za-z_]\w*)\s*\(/)?.[1];
const text = readFileSync(declarations, "utf8");
const publicSurface = text.replace(/export interface InitOutput \{[\s\S]*?\n\}\n/, "");
const untyped = publicSurface
  .split("\n")
  .map((line, index) => ({ line, number: index + 1 }))
  .filter(({ line }) => /\bany\b/.test(line) && !line.trimStart().startsWith("*"))
  .filter(({ line }) => !XARK_RUNTIME_UNTYPED.has(exportName(line)));

if (untyped.length > 0) {
  for (const { line, number } of untyped) {
    console.error(`${declarations}:${number}: ${line.trim()}`);
  }
  console.error("the generated declarations type an export as `any`");
  process.exit(1);
}
console.log("every export in the generated declarations is typed");
