import { execFileSync } from "node:child_process";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageNames } from "./packages.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const typescript = path.resolve(root, "../../node_modules/typescript/bin/tsc");

async function hasTypeScriptSource(directory) {
  try {
    const entries = await readdir(directory, { recursive: true });
    return entries.some((entry) => entry.endsWith(".ts"));
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function outputStem(exportPath) {
  return exportPath === "." ? "index" : `${exportPath.slice(2)}/index`;
}

async function writeEmptyEntry(packageDirectory, exportPath) {
  const stem = outputStem(exportPath);
  const destination = path.join(packageDirectory, "dist", stem);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(
    `${destination}.js`,
    `export {};\n//# sourceMappingURL=${path.basename(stem)}.js.map\n`,
  );
  await writeFile(
    `${destination}.js.map`,
    `${JSON.stringify({ version: 3, file: `${path.basename(stem)}.js`, sources: [], names: [], mappings: "" })}\n`,
  );
  await writeFile(
    `${destination}.d.ts`,
    `export {};\n//# sourceMappingURL=${path.basename(stem)}.d.ts.map\n`,
  );
  await writeFile(
    `${destination}.d.ts.map`,
    `${JSON.stringify({ version: 3, file: `${path.basename(stem)}.d.ts`, sources: [], names: [], mappings: "" })}\n`,
  );
}

const selectedPackages = process.argv[2] ? [process.argv[2]] : packageNames;
for (const packageName of selectedPackages) {
  if (!packageNames.includes(packageName)) throw new Error(`unknown package: ${packageName}`);
  const packageDirectory = path.join(root, packageName);
  const manifest = JSON.parse(await readFile(path.join(packageDirectory, "package.json"), "utf8"));
  await rm(path.join(packageDirectory, "dist"), { recursive: true, force: true });
  if (await hasTypeScriptSource(path.join(packageDirectory, "src"))) {
    execFileSync(
      process.execPath,
      [typescript, "--project", path.join(packageDirectory, "tsconfig.json")],
      { stdio: "inherit" },
    );
    continue;
  }
  for (const exportPath of Object.keys(manifest.exports)) {
    await writeEmptyEntry(packageDirectory, exportPath);
  }
}
