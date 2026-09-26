import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "../../..");
const NIGHTLY = "nightly-2026-05-18";

const args = new Set(process.argv.slice(2));
const threads = args.has("--threads");
const testExports = args.has("--test-exports");
const inputsOnly = args.has("--inputs-only");
if (inputsOnly && threads) {
  console.error("--inputs-only builds without the prover, so it takes no threads");
  process.exit(1);
}
const outDir = inputsOnly ? "web/pkg-inputs" : "web/pkg";

const targetFeatures = threads ? "+atomics,+bulk-memory,+simd128" : "+simd128";
const rustflags = [`-C target-feature=${targetFeatures}`];
if (threads) {
  rustflags.push(
    "-C link-arg=--shared-memory",
    "-C link-arg=--max-memory=1073741824",
    "-C link-arg=--import-memory",
    "-C link-arg=--export=__wasm_init_tls",
    "-C link-arg=--export=__tls_size",
    "-C link-arg=--export=__tls_align",
    "-C link-arg=--export=__tls_base",
  );
}

const env = {
  ...process.env,
  CARGO_PROFILE_RELEASE_OPT_LEVEL: "3",
  CARGO_PROFILE_RELEASE_LTO: "fat",
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS: "1",
  CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS: "false",
  CARGO_PROFILE_RELEASE_PANIC: "abort",
  CARGO_INCREMENTAL: "0",
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS: rustflags.join(" "),
  CARGO_TARGET_DIR: join(
    REPO_ROOT,
    "target",
    threads ? "wasm-threads" : inputsOnly ? "wasm-inputs" : "wasm-single",
  ),
};
if (threads) {
  env.RUSTUP_TOOLCHAIN = NIGHTLY;
}

const features = [threads ? "threads" : null, testExports ? "test-exports" : null].filter(Boolean);
const cargoArgs = [
  ...(inputsOnly ? ["--no-default-features"] : []),
  ...(features.length > 0 ? ["--features", features.join(",")] : []),
  ...(threads ? ["-Z", "build-std=panic_abort,std"] : []),
];

const result = spawnSync(
  "wasm-pack",
  ["build", "--release", "--target", "web", "--out-dir", outDir, "--", ...cargoArgs],
  { cwd: PACKAGE_ROOT, env, stdio: "inherit" },
);
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

if (threads) {
  const declarations = join(PACKAGE_ROOT, "web", "pkg", "timelock_escrow_wasm.d.ts");
  const untypedPool = "export function initThreadPool(num_threads: number): Promise<any>;";
  const text = readFileSync(declarations, "utf8");
  if (!text.includes(untypedPool)) {
    console.error("wasm-bindgen-rayon no longer declares initThreadPool as expected");
    process.exit(1);
  }
  writeFileSync(
    declarations,
    text.replace(untypedPool, "export function initThreadPool(threads: number): Promise<void>;"),
  );
}
