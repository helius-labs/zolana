// Regenerate every Rust-side TypeScript fixture and fail when a committed file
// has drifted. Each generator lives in `xtask/src/bin/` and supports `--check`.
// After generators, revision-compatibility, driftReview, and verifying-key
// provenance run. Body freshness is the generator --check; frozenCommit is the
// historical pin and is not advanced by a quiet regeneration.
//
//   node sdk-libs/ts/config/fixtures-check.mjs

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const here = path.dirname(fileURLToPath(import.meta.url));

// Order matches the binary names under xtask/src/bin/, minus the non-fixture
// `xtask` dispatch binary. A generator added there without a row here leaves
// committed fixtures ungated.
const generators = [
  "merkle-semantics",
  "poseidon-parity",
  "program-libs-parity",
  "proof-response-parity",
  "prover-request",
  "public-input-assembly",
  "retry-schedule",
  "solana-rpc-groups",
  "solana-rpc-reads",
  "solana-rpc-send",
  "ts-fixtures",
  "ts-interface-oracle",
  "wallet-actions",
  "wallet-sync-tags",
];

for (const bin of generators) {
  console.log(`checking ${bin}`);
  const result = spawnSync(
    "rustup",
    ["run", "1.97.0", "cargo", "run", "-p", "xtask", "--bin", bin, "--", "--check"],
    { cwd: root, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

console.log("checking fixture provenance");
const provenance = spawnSync(process.execPath, [path.join(here, "fixtures-provenance.mjs")], {
  cwd: root,
  stdio: "inherit",
});
if (provenance.error) throw provenance.error;
if (provenance.status !== 0) {
  process.exit(provenance.status ?? 1);
}
