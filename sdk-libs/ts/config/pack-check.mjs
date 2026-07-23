import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

import { browserEntryPoints, productionPackageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const typescript = path.resolve(packagesRoot, "../../node_modules/typescript/bin/tsc");
const directory = await mkdtemp(path.join(tmpdir(), "zolana-pack-"));

try {
  const tarballs = [];
  for (const packageName of productionPackageNames) {
    const manifest = JSON.parse(
      await readFile(path.join(packagesRoot, packageName, "package.json"), "utf8"),
    );
    const output = execFileSync(
      "npm",
      ["pack", path.join(packagesRoot, packageName), "--json", "--pack-destination", directory],
      { encoding: "utf8" },
    );
    const [{ filename, files }] = JSON.parse(output);
    const packedPaths = new Set(files.map((file) => file.path));
    const unexpectedFile = files.find(
      (file) => file.path !== "package.json" && !file.path.startsWith("dist/"),
    );
    if (unexpectedFile) {
      throw new Error(`@zolana/${packageName} tarball contains ${unexpectedFile.path}`);
    }
    const buildMetadata = files.find((file) => file.path.endsWith(".tsbuildinfo"));
    if (buildMetadata) {
      throw new Error(`@zolana/${packageName} tarball contains ${buildMetadata.path}`);
    }
    for (const conditions of Object.values(manifest.exports)) {
      for (const target of new Set(Object.values(conditions))) {
        if (!packedPaths.has(target.slice(2))) {
          throw new Error(`@zolana/${packageName} tarball lacks ${target}`);
        }
      }
    }
    tarballs.push(path.join(directory, filename));
  }

  execFileSync("npm", ["init", "--yes", "--scope", "zolana-consumer"], {
    cwd: directory,
    stdio: "ignore",
  });
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs], {
    cwd: directory,
    stdio: "inherit",
  });

  const imports = [];
  for (const [packageName, entryPoints] of Object.entries(browserEntryPoints)) {
    for (const entryPoint of entryPoints) {
      const suffix = entryPoint === "." ? "" : entryPoint.slice(1);
      imports.push(`@zolana/${packageName}${suffix}`);
    }
  }
  const nodeConsumer = path.join(directory, "node-consumer.mjs");
  await writeFile(
    nodeConsumer,
    `${imports.map((specifier) => `await import(${JSON.stringify(specifier)});`).join("\n")}\n`,
  );
  for (const major of ["20", "22"]) {
    execFileSync("npm", ["exec", "--yes", `--package=node@${major}`, "--", "node", nodeConsumer], {
      cwd: directory,
      stdio: "inherit",
    });
  }

  const typeConsumer = path.join(directory, "type-consumer.mts");
  await writeFile(
    typeConsumer,
    `${imports.map((specifier) => `import ${JSON.stringify(specifier)};`).join("\n")}\n`,
  );
  const typeScriptConfig = path.join(directory, "tsconfig.json");
  await writeFile(
    typeScriptConfig,
    `${JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        noEmit: true,
        strict: true,
        target: "ES2022",
        types: [],
      },
      files: ["type-consumer.mts"],
    })}\n`,
  );
  execFileSync(process.execPath, [typescript, "--project", typeScriptConfig], {
    cwd: directory,
    stdio: "inherit",
  });

  const browserOutput = path.join(directory, "browser-consumer.mjs");
  const browserBuild = await build({
    entryPoints: [nodeConsumer],
    outfile: browserOutput,
    bundle: true,
    conditions: ["browser", "import"],
    format: "esm",
    platform: "browser",
    target: "es2022",
    metafile: true,
  });
  const forbiddenImport = Object.keys(browserBuild.metafile.inputs).find((input) =>
    input.startsWith("node:"),
  );
  if (forbiddenImport) throw new Error(`packed browser graph imports ${forbiddenImport}`);
  const browserBundle = await readFile(browserOutput, "utf8");
  const forbiddenGlobal = /\b(Buffer|process|require)\b/u.exec(browserBundle);
  if (forbiddenGlobal) throw new Error(`packed browser bundle contains ${forbiddenGlobal[1]}`);

  const installedTestKit = path.join(directory, "node_modules/@zolana/test-kit/package.json");
  try {
    await readFile(installedTestKit);
    throw new Error("@zolana/test-kit was installed by a production package");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
