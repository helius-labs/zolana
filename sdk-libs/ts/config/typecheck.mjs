import { execFileSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const typescript = path.resolve(packagesRoot, "../../node_modules/typescript/bin/tsc");
const selectedPackages = process.argv[2] ? [process.argv[2]] : packageNames;

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
  execFileSync(
    process.execPath,
    [typescript, "--noEmit", "--project", path.join(packageDirectory, "tsconfig.json")],
    {
      stdio: "inherit",
    },
  );
}
