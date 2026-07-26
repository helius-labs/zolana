// Emits each package twice: `dist/es` from `tsc`, and `dist/cjs` transpiled
// from it.
//
// The CommonJS half is not a second `tsc` invocation. `tsc` takes a file's
// module format from the nearest `package.json`, which says `"type": "module"`
// for the sources, so a CommonJS emit would mean either a second manifest
// beside the sources or turning off `verbatimModuleSyntax`. Transpiling the
// already-checked ESM output leaves the type checking arrangement untouched and
// cannot disagree with it. The declarations are the same text in both trees; it
// is the `package.json` written into each that tells TypeScript how to read
// them.
import { execFileSync } from "node:child_process";
import { access, copyFile, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build as esbuild } from "esbuild";

import { packageNames, productionPackageNames } from "./packages.mjs";

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

async function writeFormatManifest(distDirectory, format) {
  await mkdir(path.join(distDirectory, format), { recursive: true });
  await writeFile(
    path.join(distDirectory, format, "package.json"),
    `${JSON.stringify({ type: format === "cjs" ? "commonjs" : "module" }, undefined, 2)}\n`,
  );
}

async function writeEmptyEntry(distDirectory, format, exportPath) {
  const stem = outputStem(exportPath);
  const destination = path.join(distDirectory, format, stem);
  const base = path.basename(stem);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(
    `${destination}.js`,
    format === "cjs" ? '"use strict";\n' : `export {};\n//# sourceMappingURL=${base}.js.map\n`,
  );
  if (format === "es") {
    await writeFile(
      `${destination}.js.map`,
      `${JSON.stringify({ version: 3, file: `${base}.js`, sources: [], names: [], mappings: "" })}\n`,
    );
  }
  await writeFile(`${destination}.d.ts`, `export {};\n//# sourceMappingURL=${base}.d.ts.map\n`);
  await writeFile(
    `${destination}.d.ts.map`,
    `${JSON.stringify({ version: 3, file: `${base}.d.ts`, sources: [], names: [], mappings: "" })}\n`,
  );
}

async function transpileToCommonJs(distDirectory) {
  const esDirectory = path.join(distDirectory, "es");
  const cjsDirectory = path.join(distDirectory, "cjs");
  const entries = await readdir(esDirectory, { recursive: true });

  const modules = entries.filter((entry) => entry.endsWith(".js"));
  if (modules.length > 0) {
    await esbuild({
      entryPoints: modules.map((entry) => path.join(esDirectory, entry)),
      outdir: cjsDirectory,
      // Each module is transpiled in place. Bundling would inline the workspace
      // dependencies and give a consumer several copies of the artifact.
      bundle: false,
      format: "cjs",
      platform: "neutral",
      target: "es2022",
      sourcemap: true,
      logLevel: "warning",
    });
  }

  // The same declarations, read as CommonJS because of the manifest beside
  // them. Both trees sit two directories below the package root, so the source
  // paths in the declaration maps stay correct.
  for (const entry of entries.filter(
    (name) => name.endsWith(".d.ts") || name.endsWith(".d.ts.map"),
  )) {
    const destination = path.join(cjsDirectory, entry);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(path.join(esDirectory, entry), destination);
  }
}

// A package whose sources or shipped files are generated declares
// `scripts/build-hooks.mjs`, and the build runs it. `beforeBuild` returns a
// context handed back to `afterBuild`, so a hook computes what it needs once
// rather than reading its own output back off disk. Running them from here
// rather than from the package's `build` script is deliberate: the repository
// build invokes this file directly for every package, so a hook wired to the
// script would be skipped by exactly the build that CI runs.
async function loadBuildHooks(packageDirectory) {
  const hooks = path.join(packageDirectory, "scripts/build-hooks.mjs");
  try {
    await access(hooks);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  return import(pathToFileURL(hooks).href);
}

const selectedPackages = process.argv[2] ? [process.argv[2]] : packageNames;
for (const packageName of selectedPackages) {
  if (!packageNames.includes(packageName)) throw new Error(`unknown package: ${packageName}`);
  const packageDirectory = path.join(root, packageName);
  const distDirectory = path.join(packageDirectory, "dist");
  const manifest = JSON.parse(await readFile(path.join(packageDirectory, "package.json"), "utf8"));
  // `test-kit` reads `import.meta.url` to find the workspace and is never
  // published, so it stays ESM only.
  const dual = productionPackageNames.includes(packageName);
  const hooks = await loadBuildHooks(packageDirectory);
  const context = await hooks?.beforeBuild?.();
  await rm(distDirectory, { recursive: true, force: true });

  if (await hasTypeScriptSource(path.join(packageDirectory, "src"))) {
    execFileSync(
      process.execPath,
      [typescript, "--project", path.join(packageDirectory, "tsconfig.json")],
      { stdio: "inherit" },
    );
    await writeFormatManifest(distDirectory, "es");
    if (dual) {
      await transpileToCommonJs(distDirectory);
      await writeFormatManifest(distDirectory, "cjs");
    }
  } else {
    await writeFormatManifest(distDirectory, "es");
    if (dual) await writeFormatManifest(distDirectory, "cjs");
    for (const [exportPath, target] of Object.entries(manifest.exports)) {
      // A shipped asset is a path rather than a module, so there is no entry
      // point to stub out for it.
      if (typeof target === "string") continue;
      await writeEmptyEntry(distDirectory, "es", exportPath);
      if (dual) await writeEmptyEntry(distDirectory, "cjs", exportPath);
    }
  }

  await hooks?.afterBuild?.(distDirectory, context);
}
