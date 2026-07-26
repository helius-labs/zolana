import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const reports = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../reports");
const inventory = JSON.parse(await readFile(path.join(reports, "inventory.json"), "utf8"));
const live = JSON.parse(await readFile(path.join(reports, "inventory-live.json"), "utf8"));
const manifest = JSON.parse(
  await readFile(path.join(root, "sdk-libs/ts/fixtures/manifest.json"), "utf8"),
);

// Baseline lives in the fixture manifest; inventory must quote the same pin.
if (inventory.frozenCommit !== manifest.frozenCommit) {
  throw new Error("inventory frozen commit diverges from fixture manifest");
}
if (inventory.rows?.length !== 182) throw new Error("inventory must contain 182 rows");

const paths = new Set();
for (const row of inventory.rows) {
  if (paths.has(row.path)) throw new Error(`duplicate inventory path: ${row.path}`);
  paths.add(row.path);
  if (!row.packet || !row.marker || !row.testResponsibility || !row.fixtureResponsibility) {
    throw new Error(`incomplete inventory row: ${row.path}`);
  }
  try {
    await access(path.join(root, row.path));
  } catch {
    throw new Error(`inventory source path missing: ${row.path}`);
  }
}

// Post-baseline packages (hasher-wasm, test-kit annex) cannot sit in the frozen
// 182-path inventory. They are checked here against inventory-live.json.
if (!Array.isArray(live.rows) || live.rows.length === 0) {
  throw new Error("inventory-live.json must list at least one live row");
}
for (const row of live.rows) {
  if (paths.has(row.path)) throw new Error(`live inventory path duplicates frozen row: ${row.path}`);
  if (paths.has(`live:${row.path}`)) throw new Error(`duplicate live inventory path: ${row.path}`);
  paths.add(`live:${row.path}`);
  if (
    row.marker !== "live" ||
    !row.packet ||
    !row.testResponsibility ||
    !row.fixtureResponsibility ||
    !row.target ||
    !row.responsibility
  ) {
    throw new Error(`incomplete live inventory row: ${row.path}`);
  }
  try {
    await access(path.join(root, row.path));
  } catch {
    throw new Error(`live inventory source path missing: ${row.path}`);
  }
}

console.log(
  `inventory ok: ${inventory.rows.length} frozen rows, ${live.rows.length} live rows`,
);
