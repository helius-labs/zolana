// Writes the manifest the browser validates downloaded proving keys against, from proving-keys.lock.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const out = process.argv[2];
if (out === undefined) throw new Error("usage: key-manifest.mjs <out-file>");

const lock = JSON.parse(
  readFileSync(
    new URL("../../../prover/server/prover/provingkeys/proving-keys.lock", import.meta.url),
    "utf8",
  ),
);
const manifest = {};
for (const [name, entry] of Object.entries(lock.keys)) {
  if (!/^transfer_confidential_|^merge_8_1/.test(name)) continue;
  manifest[name] = { size: entry.size, sha256: entry.sha256 };
}
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(manifest, null, 2));
console.log(`manifest pins ${Object.keys(manifest).length} key(s) from ${lock.prefix}`);
