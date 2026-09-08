// Prints each proving key's circuit size, so a "witness size, got N, expected M"
// error can be attributed to a specific key. Needs no localnet.
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import nodeFs from "node:fs";
import nodePath from "node:path";

globalThis.require = createRequire(import.meta.url);
globalThis.fs = nodeFs;
globalThis.path = nodePath;
await import("../../core/src/vendor/wasm_exec.js");

const ready = new Promise((resolve) => {
  globalThis.__zolanaProverReady = resolve;
});
const go = new globalThis.Go();
const wasm = await readFile(new URL("../public/prover/zolana-prover.wasm", import.meta.url));
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
void go.run(instance);
await ready;
const api = globalThis.__zolanaProver;

const shapes = ["1_1", "1_2", "2_2", "2_3", "3_3", "4_3", "4_4", "5_3", "5_4", "1_8"];
console.log("shape   witness  nbPublic  nbSecret");
for (const shape of shapes) {
  const file = `transfer_confidential_${shape}.key`;
  const bytes = await readFile(
    new URL(`../../../prover/server/proving-keys/${file}`, import.meta.url),
  );
  const loaded = api.loadKey(file, new Uint8Array(bytes));
  if (loaded.error !== undefined) {
    console.log(`${shape.padEnd(7)} ERROR ${loaded.error}`);
    continue;
  }
  const witness = loaded.nbPublic + loaded.nbSecret - 1;
  console.log(
    `${shape.padEnd(7)} ${String(witness).padStart(7)}  ${String(loaded.nbPublic).padStart(8)}  ${String(loaded.nbSecret).padStart(8)}`,
  );
}
process.exit(0);
