import { execFileSync } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const typescript = path.resolve(packagesRoot, "../../node_modules/typescript/bin/tsc");
const selectedPackages = process.argv[2] ? [process.argv[2]] : packageNames;

/**
 * Type-level assertions written in a test file are checked by nothing: the
 * package project compiles `src/**` only, and eslint's typed rules report lint
 * findings rather than compile errors. A package that needs one puts it under
 * `test/types` with its own project, which this gate compiles alongside the
 * sources so the assertion fails the build rather than sitting there decorative.
 */
const TYPE_TEST_PROJECT = path.join("test", "types", "tsconfig.json");

async function exists(target) {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function compile(project) {
  execFileSync(process.execPath, [typescript, "--noEmit", "--project", project], {
    stdio: "inherit",
  });
}

for (const packageName of selectedPackages) {
  if (!packageNames.includes(packageName)) throw new Error(`unknown package: ${packageName}`);
  const packageDirectory = path.join(packagesRoot, packageName);
  let sources = [];
  try {
    sources = await readdir(path.join(packageDirectory, "src"), { recursive: true });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (!sources.some((source) => source.endsWith(".ts"))) continue;
  compile(path.join(packageDirectory, "tsconfig.json"));
  const typeTests = path.join(packageDirectory, TYPE_TEST_PROJECT);
  if (await exists(typeTests)) compile(typeTests);
}
