// Consume an explicitly pinned test bundle; this never downloads or builds GK.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const live = process.argv[3] === "--live";
assert.equal(
  process.argv.length,
  live ? 6 : 4,
  "usage: run-gk.mjs <bundle> <sdk-tools> | <bundle> --live <manifest> <new-output-directory>",
);
const directory = resolve(process.argv[2]);
const sdkTools = live ? undefined : resolve(process.argv[3]);
if (live) assert.ok(process.env.ZOLANA_TEE_PROOF_VERIFIER, "set ZOLANA_TEE_PROOF_VERIFIER");
const expected = (await readFile(new URL("gk-revision.txt", import.meta.url), "utf8")).trim();
assert.match(expected, /^[a-f0-9]{40}$/u, "expected an exact reviewed GK commit");
const manifest = JSON.parse(await readFile(resolve(directory, "manifest.json"), "utf8"));
assert.equal(
  manifest.source_revision,
  expected,
  "GK test bundle source differs from the reviewed pin",
);
for (const name of ["tee_integration", "gk-health-check"]) {
  const executable = resolve(directory, name);
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(executable)) hash.update(chunk);
  assert.equal(hash.digest("hex"), manifest.files[name], `${name}: test bundle hash mismatch`);
  await chmod(executable, 0o700); // GitHub artifact downloads do not preserve executable modes.
}
if (!live)
  for (const name of ["prover", "rust-sdk-test"]) await chmod(resolve(sdkTools, name), 0o700);
const child = spawn(resolve(directory, "tee_integration"), ["--ignored", "--nocapture"], {
  stdio: "inherit",
  env: {
    ...process.env,
    GK_HEALTH_CHECK_BINARY: resolve(directory, "gk-health-check"),
    GK_SDK_TEST_DRIVER: new URL(live ? "live.mjs" : "gk-sdk-driver.mjs", import.meta.url).pathname,
    NODE_BINARY: process.execPath,
    ...(live
      ? {
          GK_TEST_TIMEOUT_SECONDS: "3600",
          ZOLANA_TEE_LIVE_MANIFEST: resolve(process.argv[4]),
          ZOLANA_TEE_LIVE_OUTPUT: resolve(process.argv[5]),
        }
      : {
          ZOLANA_TEE_LOCAL_PROVER_BINARY: resolve(sdkTools, "prover"),
          ZOLANA_TEE_RUST_TEST_BINARY: resolve(sdkTools, "rust-sdk-test"),
          ZOLANA_TEE_PROVING_KEYS: resolve(sdkTools, "keys"),
        }),
  },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
process.exitCode = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code) => resolve(code ?? 1));
});
