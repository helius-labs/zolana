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
      const targets = Object.values(conditions).flatMap((target) =>
        typeof target === "string" ? [target] : Object.values(target),
      );
      for (const target of new Set(targets)) {
        if (!packedPaths.has(target.slice(2))) {
          throw new Error(`@zolana/${packageName} tarball lacks ${target}`);
        }
      }
    }
    // Node reads the module format of a build from the manifest beside it, so
    // the tarball is broken without them however complete the exports map is.
    for (const marker of ["dist/es/package.json", "dist/cjs/package.json"]) {
      if (!packedPaths.has(marker)) {
        throw new Error(`@zolana/${packageName} tarball lacks ${marker}`);
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
    `${imports.map((specifier) => `await import(${JSON.stringify(specifier)});`).join("\n")}
const api = await import("@zolana/api");
const apiExports = JSON.stringify(Object.keys(api).sort());
if (apiExports !== '["ApiError","ZolanaApi"]') {
  throw new Error(\`@zolana/api exports \${apiExports}\`);
}
`,
  );
  // The CommonJS half, required to resolve and to agree with the ESM half
  // digest for digest. Two builds of one hasher that disagree would be the
  // duplication this work removed, reintroduced by the packaging.
  const commonJsConsumer = path.join(directory, "cjs-consumer.cjs");
  await writeFile(
    commonJsConsumer,
    `${imports.map((specifier) => `require(${JSON.stringify(specifier)});`).join("\n")}
const cjs = require("@zolana/hasher");
const input = [Uint8Array.from([1]), Uint8Array.from([2])];
const hex = (bytes) => Buffer.from(bytes).toString("hex");
void (async () => {
  await cjs.initializePoseidon();
  const fromRequire = hex(cjs.poseidon(input));
  const esm = await import("@zolana/hasher");
  await esm.initializePoseidon();
  const fromImport = hex(esm.poseidon(input));
  if (fromRequire !== fromImport) {
    throw new Error(\`require gives \${fromRequire} where import gives \${fromImport}\`);
  }
})();
`,
  );
  for (const major of ["20", "22"]) {
    for (const consumer of [nodeConsumer, commonJsConsumer]) {
      execFileSync("npm", ["exec", "--yes", `--package=node@${major}`, "--", "node", consumer], {
        cwd: directory,
        stdio: "inherit",
      });
    }
  }

  const typeConsumer = path.join(directory, "type-consumer.mts");
  await writeFile(
    typeConsumer,
    `${imports.map((specifier) => `import ${JSON.stringify(specifier)};`).join("\n")}
import { ApiError, ZolanaApi, type ZolanaApiConfig } from "@zolana/api";
const apiConfig: ZolanaApiConfig = { url: "https://rpc.example.test" };
const apiClient: ZolanaApi = new ZolanaApi(apiConfig);
const apiError: ApiError = new ApiError("API_TEST", "test");
void [apiClient, apiError];
`,
  );
  // The same surface reached by `require`, which resolves the CommonJS
  // declarations. A tarball whose `require` types point into the ESM build
  // typechecks here as a default import that does not exist.
  await writeFile(
    path.join(directory, "type-consumer.cts"),
    `${imports
      .map(
        (specifier, index) =>
          `import required${String(index)} = require(${JSON.stringify(specifier)});\nvoid required${String(index)};`,
      )
      .join("\n")}
import { ApiError, ZolanaApi, type ZolanaApiConfig } from "@zolana/api";
import { initializePoseidon, poseidon } from "@zolana/hasher";
const apiConfig: ZolanaApiConfig = { url: "https://rpc.example.test" };
const apiClient: ZolanaApi = new ZolanaApi(apiConfig);
const apiError: ApiError = new ApiError("API_TEST", "test");
const digest: Promise<Uint8Array> = initializePoseidon().then(() =>
  poseidon([Uint8Array.from([1]), Uint8Array.from([2])]),
);
void [apiClient, apiError, digest];
`,
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
      files: ["type-consumer.mts", "type-consumer.cts"],
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
  const forbiddenGlobal =
    /\bBuffer\b|\brequire\s*\(|\bprocess\s*(?:\.|\[)|typeof\s+process|\b(?:globalThis|window|self)\.process\b/u.exec(
      browserBundle,
    );
  if (forbiddenGlobal) throw new Error(`packed browser bundle contains ${forbiddenGlobal[0]}`);

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
