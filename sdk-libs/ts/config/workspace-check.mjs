import { access, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageConfigurations, packageNames, productionPackageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY_URL = "git+https://github.com/helius-labs/zolana.git";
const BUGS_URL = "https://github.com/helius-labs/zolana/issues";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function manifest(packageName) {
  return JSON.parse(await readFile(path.join(packagesRoot, packageName, "package.json"), "utf8"));
}

/** Package name from an import specifier; relative and `node:` imports are ignored. */
function dependencyName(specifier) {
  if (specifier.startsWith(".") || specifier.startsWith("node:")) return undefined;
  if (specifier.startsWith("@")) {
    const segments = specifier.split("/");
    return segments.slice(0, 2).join("/");
  }
  return specifier.split("/")[0];
}

/**
 * Runtime imports from `src/**`, including bare `export … from` re-exports.
 * Comment text that mentions a package name is ignored: only statement forms
 * count, so an unused declaration cannot hide behind documentation.
 */
async function sourceDependencies(packageName) {
  const sourceRoot = path.join(packagesRoot, packageName, "src");
  let entries;
  try {
    entries = await readdir(sourceRoot, { recursive: true });
  } catch (error) {
    if (error.code === "ENOENT") return new Set();
    throw error;
  }
  const imported = new Set();
  for (const entry of entries.filter((name) => name.endsWith(".ts"))) {
    const source = await readFile(path.join(sourceRoot, entry), "utf8");
    for (const match of source.matchAll(
      /^\s*(?:import|export)\s+(?:type\s+)?(?:[^"'`]*?\sfrom\s+)?["']([^"']+)["']/gm,
    )) {
      const name = dependencyName(match[1]);
      if (name !== undefined) imported.add(name);
    }
    for (const match of source.matchAll(/import\s*\(\s*["']([^"']+)["']\s*\)/g)) {
      const name = dependencyName(match[1]);
      if (name !== undefined) imported.add(name);
    }
  }
  return imported;
}

function outputStem(exportPath) {
  return exportPath === "." ? "index" : `${exportPath.slice(2)}/index`;
}

async function checkExports() {
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    const configuration = packageConfigurations[packageName];
    const exportPaths = Object.keys(value.exports ?? {});
    const assets = configuration.assets ?? {};
    // Assets come last so a reader of the manifest meets the JavaScript the
    // package is for before the files it carries.
    const expectedExportPaths = [...configuration.entryPoints, ...Object.keys(assets)];
    // `test-kit` reads `import.meta.url` and is never published, so it is the
    // one package with no CommonJS half.
    const dual = productionPackageNames.includes(packageName);
    const expectedConditions = [
      ...(configuration.browser ? ["browser"] : []),
      "import",
      ...(dual ? ["require"] : []),
      "default",
    ];

    const publishedName = configuration.publishedName ?? `@zolana/${packageName}`;
    assert(value.name === publishedName, `${packageName} package name`);
    assert(value.type === "module", `${value.name} must be ESM`);
    assert(value.sideEffects === false, `${value.name} must declare sideEffects`);
    assert(
      value.engines?.node === ">=20.19.0 <23",
      `${value.name} must support maintained Node 20 and 22 releases`,
    );
    assert(
      value.files?.length === 1 && value.files[0] === "dist",
      `${value.name} files must be dist`,
    );
    assert(
      JSON.stringify(exportPaths) === JSON.stringify(expectedExportPaths),
      `${value.name} export paths`,
    );
    for (const [exportPath, conditions] of Object.entries(value.exports)) {
      const stem = outputStem(exportPath);
      assert(!exportPath.includes("*"), `${value.name} cannot use wildcard exports`);

      // An asset is one file for every consumer, so it carries no conditions
      // and no declarations. Resolving it has to actually reach something, or
      // the slim build has nothing to load.
      if (Object.hasOwn(assets, exportPath)) {
        assert(conditions === assets[exportPath], `${value.name} ${exportPath} asset target`);
        await access(path.join(packagesRoot, packageName, conditions));
        continue;
      }

      assert(
        JSON.stringify(Object.keys(conditions)) === JSON.stringify(expectedConditions),
        `${value.name} ${exportPath} export conditions`,
      );

      // Each format carries its own declarations. A CommonJS consumer resolving
      // the ESM ones is told the module has a default export it does not have,
      // which is the failure this arrangement exists to prevent, so the two
      // types entries must differ.
      for (const format of dual ? ["import", "require"] : ["import"]) {
        const target = conditions[format];
        const directory = format === "require" ? "cjs" : "es";
        assert(
          target?.types === `./dist/${directory}/${stem}.d.ts`,
          `${value.name} ${exportPath} ${format} declaration target`,
        );
        assert(
          target.default === `./dist/${directory}/${stem}.js`,
          `${value.name} ${exportPath} ${format} target`,
        );
        assert(
          JSON.stringify(Object.keys(target)) === JSON.stringify(["types", "default"]),
          `${value.name} ${exportPath} ${format} conditions`,
        );
        await access(path.join(packagesRoot, packageName, target.types));
        await access(path.join(packagesRoot, packageName, target.default));
      }

      assert(
        conditions.default === `./dist/es/${stem}.js`,
        `${value.name} ${exportPath} default must be the ESM build`,
      );
      if (configuration.browser) {
        assert(
          JSON.stringify(conditions.browser) === JSON.stringify(conditions.import),
          `${value.name} ${exportPath} browser must match import`,
        );
      }
    }

    // A manifest beside each build is what tells Node and TypeScript how to
    // read it, since the package itself declares `"type": "module"`.
    const formats = dual ? ["es", "cjs"] : ["es"];
    for (const format of formats) {
      const marker = JSON.parse(
        await readFile(
          path.join(packagesRoot, packageName, "dist", format, "package.json"),
          "utf8",
        ),
      );
      assert(
        marker.type === (format === "cjs" ? "commonjs" : "module"),
        `${value.name} dist/${format} must declare its module type`,
      );
    }

    assert(
      value.main === (dual ? "./dist/cjs/index.js" : "./dist/es/index.js"),
      `${value.name} main must reach the CommonJS build where there is one`,
    );
    assert(value.module === "./dist/es/index.js", `${value.name} module must reach the ESM build`);
    assert(value.types === "./dist/es/index.d.ts", `${value.name} types must reach the ESM build`);
  }
}

async function checkPublishMetadata() {
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    assert(value.license === "Apache-2.0", `${value.name} must declare Apache-2.0`);
    assert(value.repository?.type === "git", `${value.name} repository.type`);
    assert(value.repository?.url === REPOSITORY_URL, `${value.name} repository.url`);
    assert(
      value.repository?.directory === `sdk-libs/ts/${packageName}`,
      `${value.name} repository.directory`,
    );
    assert(
      value.homepage ===
        `https://github.com/helius-labs/zolana/tree/main/sdk-libs/ts/${packageName}`,
      `${value.name} homepage`,
    );
    assert(value.bugs?.url === BUGS_URL, `${value.name} bugs.url`);
    if (productionPackageNames.includes(packageName)) {
      assert(value.publishConfig?.access === "public", `${value.name} publishConfig.access`);
      assert(value.private !== true, `${value.name} must be publishable`);
    }
  }
}

function sortedKeys(value) {
  return Object.keys(value ?? {}).sort();
}

async function checkDependencies() {
  await checkPublishMetadata();
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    const configuration = packageConfigurations[packageName];
    const dependencies = sortedKeys(value.dependencies);
    const expected = [...configuration.dependencies].sort();
    assert(
      JSON.stringify(dependencies) === JSON.stringify(expected),
      `${value.name} dependency graph`,
    );
    const peers = sortedKeys(value.peerDependencies);
    const expectedPeers = [...(configuration.peerDependencies ?? [])].sort();
    assert(
      JSON.stringify(peers) === JSON.stringify(expectedPeers),
      `${value.name} peer dependency graph`,
    );
    for (const peer of peers) {
      // Peers must not also appear in dependencies.
      assert(
        !dependencies.includes(peer),
        `${value.name} declares ${peer} as both peer and dependency`,
      );
      // Non-optional peers install into every consumer; an opt-in adapter must
      // mark them optional.
      assert(
        value.peerDependenciesMeta?.[peer]?.optional === true,
        `${value.name} peer ${peer} must be optional`,
      );
    }
    // Sources may import peers; install is the consumer's choice.
    const resolvable = [...dependencies, ...peers].sort();
    const imported = [...(await sourceDependencies(packageName))].sort();
    assert(
      JSON.stringify(imported) === JSON.stringify(resolvable),
      `${value.name} source imports ${JSON.stringify(imported)} must match dependencies ${JSON.stringify(resolvable)}`,
    );
    for (const entryPoint of configuration.browserDependencies ?? []) {
      const segments = entryPoint.split("/");
      const dependency = entryPoint.startsWith("@") ? segments.slice(0, 2).join("/") : segments[0];
      assert(resolvable.includes(dependency), `${value.name} browser dependency ${entryPoint}`);
    }
    for (const [dependency, version] of Object.entries(value.dependencies ?? {})) {
      if (dependency.startsWith("@zolana/")) {
        assert(version === "0.1.0", `${value.name} internal versions must be coordinated`);
      }
    }
  }
  for (const packageName of productionPackageNames) {
    const value = await manifest(packageName);
    assert(
      !sortedKeys(value.dependencies).includes("@zolana/test-kit"),
      `${value.name} reaches test-kit`,
    );
  }
  const testKit = await manifest("test-kit");
  assert(testKit.private === true, "@zolana/test-kit must be private");
}

async function checkScaffold() {
  const vectorPackages = [
    "hasher",
    "interface",
    "keypair",
    "transaction",
    "indexer-api",
    "api",
    "client",
    "wallet",
    "merkle-tree",
    "smart-account-client",
    "kit",
  ];
  const propertyPackages = [
    "keypair",
    "transaction",
    "indexer-api",
    "api",
    "client",
    "wallet",
    "merkle-tree",
    "smart-account-client",
  ];
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    assert(value.scripts?.["api:check"], `${value.name} lacks api:check`);
    if (packageConfigurations[packageName].browser) {
      assert(
        value.scripts?.["test:browser"] === `node ../config/browser-check.mjs ${packageName}`,
        `${value.name} must run its isolated browser check`,
      );
    }
    if (vectorPackages.includes(packageName)) {
      const script = value.scripts?.["test:vectors"];
      assert(
        script && !script.includes("passWithNoTests"),
        `${value.name} must define non-vacuous vector tests`,
      );
    }
    if (propertyPackages.includes(packageName)) {
      const script = value.scripts?.["test:property"];
      assert(
        script && !script.includes("passWithNoTests"),
        `${value.name} must define non-vacuous property tests`,
      );
    }
    if (packageName === "api") {
      const script = value.scripts?.["test:cross"];
      assert(
        script && !script.includes("passWithNoTests") && !script.includes("test:unit"),
        `${value.name} must define non-vacuous cross-contract tests`,
      );
    }
  }
}

async function checkApiReports() {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(
    process.execPath,
    [path.join(path.dirname(fileURLToPath(import.meta.url)), "api-check.mjs")],
    {
      cwd: path.resolve(packagesRoot, "../.."),
      stdio: "inherit",
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const command = process.argv[2];
if (command === "exports") await checkExports();
else if (command === "dependencies") await checkDependencies();
else if (command === "api") {
  await checkScaffold();
  await checkApiReports();
} else if (command === "scaffold") await checkScaffold();
else {
  await checkExports();
  await checkDependencies();
  await checkScaffold();
  await checkApiReports();
}
