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
    const expectedConditions = configuration.browser
      ? ["types", "browser", "import", "default"]
      : ["types", "import", "default"];

    assert(value.name === `@zolana/${packageName}`, `${packageName} package name`);
    assert(value.type === "module", `${value.name} must be ESM`);
    assert(value.sideEffects === false, `${value.name} must declare sideEffects`);
    assert(value.engines?.node === ">=20 <23", `${value.name} must support Node 20 and 22`);
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
      assert(
        conditions.types === `./dist/${stem}.d.ts`,
        `${value.name} ${exportPath} declaration target`,
      );
      assert(conditions.import === `./dist/${stem}.js`, `${value.name} ${exportPath} ESM target`);
      assert(
        conditions.default === conditions.import,
        `${value.name} ${exportPath} default must match import`,
      );
      if (configuration.browser) {
        assert(
          conditions.browser === conditions.import,
          `${value.name} ${exportPath} browser must match import`,
        );
      }
      await access(path.join(packagesRoot, packageName, conditions.types));
      await access(path.join(packagesRoot, packageName, conditions.import));
    }
    assert(value.main === undefined, `${value.name} cannot expose a legacy main`);
    assert(value.module === undefined, `${value.name} cannot expose a legacy module`);
    assert(value.types === undefined, `${value.name} cannot bypass the export map`);
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
    for (const version of Object.values(value.dependencies ?? {})) {
      assert(version === "0.1.0", `${value.name} internal versions must be coordinated`);
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

async function checkApiScaffold() {
  for (const packageName of packageNames) {
    const value = await manifest(packageName);
    assert(value.scripts?.["api:check"], `${value.name} lacks api:check`);
  }
}

const command = process.argv[2];
if (command === "exports") await checkExports();
else if (command === "dependencies") await checkDependencies();
else if (command === "api") await checkApiScaffold();
else {
  await checkExports();
  await checkDependencies();
  await checkApiScaffold();
}
