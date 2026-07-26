// Extract the public export surface of every workspace package from its built
// declaration files and compare it to the committed reports under
// `sdk-libs/ts/api-reports/`. Fails on an undeclared addition or removal.
//
//   node sdk-libs/ts/config/api-check.mjs           # check
//   node sdk-libs/ts/config/api-check.mjs --update  # rewrite reports

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";

import { packageConfigurations, packageNames } from "./packages.mjs";

const packagesRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reportsRoot = path.join(packagesRoot, "api-reports");
const update = process.argv.includes("--update");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function outputStem(exportPath) {
  return exportPath === "." ? "index" : `${exportPath.slice(2)}/index`;
}

/**
 * Walk a declaration file and collect named exports. Relative `export *`
 * re-exports are followed so annex entry points that star-export helpers still
 * produce a flat, comparable surface.
 */
function declarationExports(absolutePath, seen = new Set()) {
  if (seen.has(absolutePath)) return [];
  seen.add(absolutePath);
  const source = ts.sys.readFile(absolutePath);
  assert(source !== undefined, `missing declaration ${absolutePath}`);
  const file = ts.createSourceFile(absolutePath, source, ts.ScriptTarget.Latest, true);
  const exports = [];

  for (const statement of file.statements) {
    if (ts.isExportDeclaration(statement)) {
      const moduleSpecifier = statement.moduleSpecifier;
      if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        const typeOnly = statement.isTypeOnly;
        for (const element of statement.exportClause.elements) {
          exports.push({
            name: element.name.text,
            kind: typeOnly || element.isTypeOnly ? "type" : "value",
          });
        }
      } else if (
        statement.exportClause === undefined &&
        moduleSpecifier &&
        ts.isStringLiteral(moduleSpecifier)
      ) {
        const specifier = moduleSpecifier.text;
        if (specifier.startsWith(".")) {
          const resolved = path.resolve(
            path.dirname(absolutePath),
            specifier.endsWith(".js") ? specifier.replace(/\.js$/u, ".d.ts") : `${specifier}.d.ts`,
          );
          exports.push(...declarationExports(resolved, seen));
        }
      }
      continue;
    }

    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    if (!modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) continue;

    if (
      ts.isInterfaceDeclaration(statement) ||
      ts.isTypeAliasDeclaration(statement) ||
      (ts.isModuleDeclaration(statement) &&
        statement.flags & ts.NodeFlags.Namespace &&
        statement.name &&
        ts.isIdentifier(statement.name))
    ) {
      if (statement.name && ts.isIdentifier(statement.name)) {
        exports.push({ name: statement.name.text, kind: "type" });
      }
      continue;
    }

    if (
      ts.isClassDeclaration(statement) ||
      ts.isFunctionDeclaration(statement) ||
      ts.isEnumDeclaration(statement)
    ) {
      if (statement.name) exports.push({ name: statement.name.text, kind: "value" });
      continue;
    }

    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) {
          exports.push({ name: declaration.name.text, kind: "value" });
        }
      }
    }
  }

  return exports;
}

function normalize(exports) {
  const byName = new Map();
  for (const entry of exports) {
    const existing = byName.get(entry.name);
    // A symbol that appears as both value and type is a value export for the
    // report (classes, enums, const enums with type side). Prefer value.
    if (existing === undefined || (existing === "type" && entry.kind === "value")) {
      byName.set(entry.name, entry.kind);
    }
  }
  return [...byName.entries()]
    .map(([name, kind]) => ({ name, kind }))
    .sort(
      (left, right) => left.name.localeCompare(right.name) || left.kind.localeCompare(right.kind),
    );
}

async function runtimeKeys(packageName, exportPath) {
  const stem = outputStem(exportPath);
  const moduleUrl = pathToFileURL(
    path.join(packagesRoot, packageName, "dist", "es", `${stem}.js`),
  ).href;
  const module = await import(moduleUrl);
  return Object.keys(module).sort();
}

async function packageReport(packageName) {
  const configuration = packageConfigurations[packageName];
  const entryPoints = {};
  for (const exportPath of configuration.entryPoints) {
    const stem = outputStem(exportPath);
    const declarationPath = path.join(packagesRoot, packageName, "dist", "es", `${stem}.d.ts`);
    const fromDeclarations = normalize(declarationExports(declarationPath));
    const runtime = await runtimeKeys(packageName, exportPath);
    const runtimeSet = new Set(runtime);
    for (const name of runtime) {
      const existing = fromDeclarations.find((entry) => entry.name === name);
      if (existing === undefined) {
        fromDeclarations.push({ name, kind: "value" });
      } else if (existing.kind === "type") {
        existing.kind = "value";
      }
    }
    // Declaration extraction can mark a re-exported value as type-only when the
    // exporting file uses `export type`. Prefer the runtime module.
    for (const entry of fromDeclarations) {
      if (runtimeSet.has(entry.name)) entry.kind = "value";
    }
    entryPoints[exportPath] = normalize(fromDeclarations);
  }
  return {
    package: `@zolana/${packageName}`,
    entryPoints,
  };
}

function diffExports(expected, actual) {
  const key = (entry) => `${entry.name}:${entry.kind}`;
  const expectedKeys = new Set(expected.map(key));
  const actualKeys = new Set(actual.map(key));
  return {
    added: actual.filter((entry) => !expectedKeys.has(key(entry))),
    removed: expected.filter((entry) => !actualKeys.has(key(entry))),
  };
}

async function main() {
  await mkdir(reportsRoot, { recursive: true });
  const problems = [];

  for (const packageName of packageNames) {
    const report = await packageReport(packageName);
    const reportPath = path.join(reportsRoot, `${packageName}.json`);
    const serialized = `${JSON.stringify(report, null, 2)}\n`;

    if (update) {
      await writeFile(reportPath, serialized);
      console.log(`wrote ${path.relative(packagesRoot, reportPath)}`);
      continue;
    }

    let committed;
    try {
      committed = JSON.parse(await readFile(reportPath, "utf8"));
    } catch (error) {
      problems.push(`${packageName}: missing committed API report (${error.message})`);
      continue;
    }

    assert(committed.package === report.package, `${packageName}: report package name drifted`);
    const expectedPaths = Object.keys(committed.entryPoints ?? {}).sort();
    const actualPaths = Object.keys(report.entryPoints).sort();
    if (JSON.stringify(expectedPaths) !== JSON.stringify(actualPaths)) {
      problems.push(
        `${packageName}: entry points ${JSON.stringify(actualPaths)} != committed ${JSON.stringify(expectedPaths)}`,
      );
      continue;
    }

    for (const exportPath of actualPaths) {
      const { added, removed } = diffExports(
        committed.entryPoints[exportPath],
        report.entryPoints[exportPath],
      );
      if (added.length > 0) {
        problems.push(
          `${packageName} ${exportPath}: undeclared addition(s) ${added.map((e) => e.name).join(", ")}`,
        );
      }
      if (removed.length > 0) {
        problems.push(
          `${packageName} ${exportPath}: undeclared removal(s) ${removed.map((e) => e.name).join(", ")}`,
        );
      }
    }
  }

  if (update) return;
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    throw new Error(`${problems.length} API report difference(s)`);
  }
  console.log(`api reports match for ${packageNames.length} packages`);
}

await main();
