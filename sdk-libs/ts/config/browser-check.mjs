import { build } from "esbuild";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { browserDependencyEntryPoints, browserEntryPoints } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
    const forbidden =
      /\bBuffer\b|\brequire\s*\(|["']node:|\bprocess\s*(?:\.|\[)|typeof\s+process|\b(?:globalThis|window|self)\.process\b/u.exec(
        source,
      );
    if (forbidden) throw new Error(`@zolana/${packageName} source contains ${forbidden[0]}`);
  }
}

for (const packageName of Object.keys(browserEntryPoints)) {
  await checkBrowserSource(packageName);
}

const directory = await mkdtemp(path.join(tmpdir(), "zolana-browser-"));
try {
  const imports = browserDependencyEntryPoints.map(
    (dependency) => `import(${JSON.stringify(dependency)})`,
  );
  for (const [packageName, entryPoints] of Object.entries(browserEntryPoints)) {
    for (const entryPoint of entryPoints) {
      const suffix = entryPoint === "." ? "" : entryPoint.slice(1);
      imports.push(`import(${JSON.stringify(`@zolana/${packageName}${suffix}`)})`);
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
  const forbiddenGlobal =
    /\bBuffer\b|\brequire\s*\(|\bprocess\s*(?:\.|\[)|typeof\s+process|\b(?:globalThis|window|self)\.process\b/u.exec(
      bundle,
    );
  if (forbiddenGlobal) throw new Error(`browser bundle contains ${forbiddenGlobal[0]}`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
