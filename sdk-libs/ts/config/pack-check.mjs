import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

import { browserEntryPoints, packageConfigurations, productionPackageNames } from "./packages.mjs";

function publishedName(packageName) {
  return packageConfigurations[packageName].publishedName ?? `@zolana/${packageName}`;
}

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const typescript = path.resolve(packagesRoot, "../../node_modules/typescript/bin/tsc");
const directory = await mkdtemp(path.join(tmpdir(), "zolana-pack-"));
const rootManifest = JSON.parse(
  await readFile(path.resolve(packagesRoot, "../../package.json"), "utf8"),
);
const nodeTypes = `@types/node@${rootManifest.devDependencies["@types/node"]}`;

/** Flatten an exports map entry (condition object or bare asset path) to file targets. */
function exportTargets(conditions) {
  if (typeof conditions === "string") return [conditions];
  return Object.values(conditions).flatMap((target) =>
    typeof target === "string" ? [target] : Object.values(target),
  );
}

function sideEffectImports(specifiers) {
  return specifiers.map((specifier) => `import ${JSON.stringify(specifier)};`).join("\n");
}

function commonJsRequires(specifiers, namePrefix) {
  return specifiers
    .map(
      (specifier, index) =>
        `import ${namePrefix}${String(index)} = require(${JSON.stringify(specifier)});\nvoid ${namePrefix}${String(index)};`,
    )
    .join("\n");
}

async function typecheck(files, types) {
  const configPath = path.join(
    directory,
    types.length === 0 ? "tsconfig.json" : "tsconfig.peer.json",
  );
  await writeFile(
    configPath,
    `${JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        noEmit: true,
        strict: true,
        target: "ES2022",
        types,
      },
      files,
    })}\n`,
  );
  execFileSync(process.execPath, [typescript, "--project", configPath], {
    cwd: directory,
    stdio: "inherit",
  });
}

try {
  const tarballs = [];
  // Optional peers are not installed by npm; this consumer installs them so
  // peer-backed entry points resolve.
  const peers = new Set();
  const peerPackageNames = new Set();
  for (const packageName of productionPackageNames) {
    const manifest = JSON.parse(
      await readFile(path.join(packagesRoot, packageName, "package.json"), "utf8"),
    );
    for (const [peer, range] of Object.entries(manifest.peerDependencies ?? {})) {
      peers.add(`${peer}@${range}`);
      peerPackageNames.add(packageName);
    }
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
    const name = publishedName(packageName);
    if (unexpectedFile) {
      throw new Error(`${name} tarball contains ${unexpectedFile.path}`);
    }
    const buildMetadata = files.find((file) => file.path.endsWith(".tsbuildinfo"));
    if (buildMetadata) {
      throw new Error(`${name} tarball contains ${buildMetadata.path}`);
    }
    for (const conditions of Object.values(manifest.exports)) {
      // A shipped asset is a bare path rather than a condition map, and it is
      // the one export whose absence from the tarball a consumer only finds out
      // about at run time.
      for (const target of new Set(exportTargets(conditions))) {
        if (!packedPaths.has(target.slice(2))) {
          throw new Error(`${name} tarball lacks ${target}`);
        }
      }
    }
    // Node reads the module format of a build from the manifest beside it, so
    // the tarball is broken without them however complete the exports map is.
    for (const marker of ["dist/es/package.json", "dist/cjs/package.json"]) {
      if (!packedPaths.has(marker)) {
        throw new Error(`${name} tarball lacks ${marker}`);
      }
    }
    tarballs.push(path.join(directory, filename));
  }

  execFileSync("npm", ["init", "--yes", "--scope", "zolana-consumer"], {
    cwd: directory,
    stdio: "ignore",
  });
  execFileSync(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs, ...peers],
    {
      cwd: directory,
      stdio: "inherit",
    },
  );

  const imports = [];
  // Packages with optional peers typecheck in a separate project below, so
  // ambient types those peers need do not weaken the main consumer check.
  const peerBackedImports = [];
  const strictImports = [];
  for (const [packageName, entryPoints] of Object.entries(browserEntryPoints)) {
    const peerBackedEntryPoints = new Set(
      packageConfigurations[packageName].peerBackedEntryPoints ?? [],
    );
    for (const entryPoint of entryPoints) {
      const suffix = entryPoint === "." ? "" : entryPoint.slice(1);
      const specifier = `${publishedName(packageName)}${suffix}`;
      imports.push(specifier);
      if (peerPackageNames.has(packageName) || peerBackedEntryPoints.has(entryPoint)) {
        peerBackedImports.push(specifier);
      } else {
        strictImports.push(specifier);
      }
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
  // The slim build against the artifact the tarball actually carries, in its
  // own process because the two entry points share one instance: initializing
  // the inlined one first would leave this proving nothing. The ESM inlined
  // build is a second module graph and so a second instance, which is what
  // makes the digest comparison real.
  const slimConsumer = path.join(directory, "slim-consumer.cjs");
  await writeFile(
    slimConsumer,
    `const { readFileSync } = require("node:fs");
const slim = require("@zolana/hasher/slim");
const artifact = readFileSync(require.resolve("@zolana/hasher/poseidon.wasm"));
const input = [Uint8Array.from([1]), Uint8Array.from([2])];
const hex = (bytes) => Buffer.from(bytes).toString("hex");
void (async () => {
  await slim.initializePoseidon(artifact);
  const fromFile = hex(slim.poseidon(input));
  const inlined = await import("@zolana/hasher");
  await inlined.initializePoseidon();
  if (artifact.byteLength !== inlined.POSEIDON_ARTIFACT_BYTES) {
    throw new Error(
      \`poseidon.wasm is \${artifact.byteLength} bytes where the inlined artifact is \${inlined.POSEIDON_ARTIFACT_BYTES}\`,
    );
  }
  const fromInline = hex(inlined.poseidon(input));
  if (fromFile !== fromInline) {
    throw new Error(\`the slim build gives \${fromFile} where the inlined one gives \${fromInline}\`);
  }
})();
`,
  );

  for (const major of ["20", "22"]) {
    for (const consumer of [nodeConsumer, commonJsConsumer, slimConsumer]) {
      execFileSync("npm", ["exec", "--yes", `--package=node@${major}`, "--", "node", consumer], {
        cwd: directory,
        stdio: "inherit",
      });
    }
  }

  await writeFile(
    path.join(directory, "type-consumer.mts"),
    `${sideEffectImports(strictImports)}
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
    `${commonJsRequires(strictImports, "required")}
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
  await typecheck(["type-consumer.mts", "type-consumer.cts"], []);

  if (peerBackedImports.length > 0) {
    // Kit's types pull in `undici-types` via Node ambient types. Install
    // `@types/node` only for this peer-backed project.
    execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", nodeTypes], {
      cwd: directory,
      stdio: "inherit",
    });
    await writeFile(
      path.join(directory, "peer-consumer.mts"),
      `${sideEffectImports(peerBackedImports)}\n`,
    );
    await writeFile(
      path.join(directory, "peer-consumer.cts"),
      `${commonJsRequires(peerBackedImports, "peer")}\n`,
    );
    await typecheck(["peer-consumer.mts", "peer-consumer.cts"], ["node"]);
  }

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
