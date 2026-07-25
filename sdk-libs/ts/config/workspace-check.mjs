import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { packageConfigurations, packageNames, productionPackageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function manifest(packageName) {
  return JSON.parse(await readFile(path.join(packagesRoot, packageName, "package.json"), "utf8"));
}

function outputStem(exportPath) {
  return exportPath === "." ? "index" : `${exportPath.slice(2)}/index`;
}

async function checkExports() {
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    const configuration = packageConfigurations[packageName];
    const exportPaths = Object.keys(value.exports ?? {});
    const expectedExportPaths = configuration.entryPoints;
    // `test-kit` reads `import.meta.url` and is never published, so it is the
    // one package with no CommonJS half.
    const dual = productionPackageNames.includes(packageName);
    const expectedConditions = [
      ...(configuration.browser ? ["browser"] : []),
      "import",
      ...(dual ? ["require"] : []),
      "default",
    ];

    assert(value.name === `@zolana/${packageName}`, `${packageName} package name`);
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
        await readFile(path.join(packagesRoot, packageName, "dist", format, "package.json"), "utf8"),
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

async function checkDependencies() {
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    const dependencies = Object.keys(value.dependencies ?? {}).sort();
    const expected = [...packageConfigurations[packageName].dependencies].sort();
    assert(
      JSON.stringify(dependencies) === JSON.stringify(expected),
      `${value.name} dependency graph`,
    );
    for (const entryPoint of packageConfigurations[packageName].browserDependencies ?? []) {
      const segments = entryPoint.split("/");
      const dependency = entryPoint.startsWith("@") ? segments.slice(0, 2).join("/") : segments[0];
      assert(dependencies.includes(dependency), `${value.name} browser dependency ${entryPoint}`);
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
      !Object.keys(value.dependencies ?? {}).includes("@zolana/test-kit"),
      `${value.name} reaches test-kit`,
    );
  }
  const testKit = await manifest("test-kit");
  assert(testKit.private === true, "@zolana/test-kit must be private");
}

async function checkScaffold() {
  const vectorPackages = [
    "interface",
    "keypair",
    "transaction",
    "indexer-api",
    "api",
    "client",
    "wallet",
    "merkle-tree",
    "smart-account-client",
  ];
  const propertyPackages = [
    "keypair",
    "transaction",
    "indexer-api",
    "api",
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

const command = process.argv[2];
if (command === "exports") await checkExports();
else if (command === "dependencies") await checkDependencies();
else if (command === "api") await checkScaffold();
else {
  await checkExports();
  await checkDependencies();
  await checkScaffold();
}
