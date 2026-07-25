import { build } from "esbuild";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  browserDependencyEntryPoints,
  browserEntryPoints,
  packageConfigurations,
} from "./packages.mjs";

/// Node-only globals no browser package may reach. The `process` alternative
/// tolerates an optional-chaining `?`, because `globalThis.process?.env` reads
/// the environment just as surely as `process.env` does and once slipped a
/// `ZOLANA_PROVER_URL` lookup past this scan into `@zolana/client`.
const NODE_GLOBAL = String.raw`\bBuffer\b|\brequire\s*\(|\bprocess\s*\??\s*(?:\.|\[)|typeof\s+process|\b(?:globalThis|window|self)\s*\.\s*process\b`;
const forbiddenInSource = new RegExp(`${NODE_GLOBAL}|["']node:`, "u");
const forbiddenInBundle = new RegExp(NODE_GLOBAL, "u");

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageName = process.argv[2];
const selectedConfiguration = packageName ? packageConfigurations[packageName] : undefined;
if (packageName && (!selectedConfiguration || !selectedConfiguration.browser)) {
  throw new Error(`unknown browser package: ${packageName}`);
}
const selectedBrowserEntryPoints = packageName
  ? { [packageName]: browserEntryPoints[packageName] }
  : browserEntryPoints;
const selectedDependencyEntryPoints = packageName
  ? (selectedConfiguration.browserDependencies ?? [])
  : browserDependencyEntryPoints;

async function checkBrowserSource(packageName) {
  const sourceRoot = path.join(packagesRoot, packageName, "src");
  let entries;
  try {
    entries = await readdir(sourceRoot, { recursive: true });
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  for (const entry of entries.filter((name) => name.endsWith(".ts"))) {
    const source = await readFile(path.join(sourceRoot, entry), "utf8");
    const forbidden = forbiddenInSource.exec(source);
    if (forbidden) throw new Error(`@zolana/${packageName} source contains ${forbidden[0]}`);
  }
}

for (const selectedPackageName of Object.keys(selectedBrowserEntryPoints)) {
  await checkBrowserSource(selectedPackageName);
}

const directory = await mkdtemp(path.join(tmpdir(), "zolana-browser-"));
try {
  const imports = selectedDependencyEntryPoints.map(
    (dependency) => `import(${JSON.stringify(dependency)})`,
  );
  for (const [selectedPackageName, entryPoints] of Object.entries(selectedBrowserEntryPoints)) {
    for (const entryPoint of entryPoints ?? []) {
      const suffix = entryPoint === "." ? "" : entryPoint.slice(1);
      imports.push(`import(${JSON.stringify(`@zolana/${selectedPackageName}${suffix}`)})`);
    }
  }
  const entry = path.join(directory, "consumer.mjs");
  const output = path.join(directory, "bundle.mjs");
  await writeFile(
    entry,
    `globalThis.__zolanaBrowserSmoke = await Promise.all([${imports.join(",")}]);\n`,
  );
  const result = await build({
    entryPoints: [entry],
    outfile: output,
    bundle: true,
    conditions: ["browser", "import"],
    format: "esm",
    platform: "browser",
    target: "es2022",
    metafile: true,
    nodePaths: [path.resolve(packagesRoot, "../../node_modules")],
  });
  const forbiddenImport = Object.keys(result.metafile.inputs).find((input) =>
    input.startsWith("node:"),
  );
  if (forbiddenImport) throw new Error(`browser graph imports ${forbiddenImport}`);
  const bundle = await readFile(output, "utf8");
  const forbiddenGlobal = forbiddenInBundle.exec(bundle);
  if (forbiddenGlobal) throw new Error(`browser bundle contains ${forbiddenGlobal[0]}`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
