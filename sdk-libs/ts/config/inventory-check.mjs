import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const reports = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../reports");
const inventory = JSON.parse(await readFile(path.join(reports, "inventory.json"), "utf8"));

if (inventory.frozenCommit !== "43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f") {
  throw new Error("inventory frozen commit changed");
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
