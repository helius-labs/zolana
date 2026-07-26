// Build the Rust groth16-verify oracle once per vitest run, before any test.
//
// Suites compare TypeScript proof/compression output against this binary. A
// stale on-disk binary would silently certify against the wrong reference, so
// every run asks cargo to rebuild-if-stale. Warm targets finish in well under a
// second; cold compiles stay outside individual test budgets.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

export default function setup() {
  const result = spawnSync("cargo", ["build", "-p", "xtask", "--bin", "groth16-verify"], {
    cwd: workspaceRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    env: process.env,
  });

  // Forward cargo's progress so a rebuild's `Compiling xtask` is visible in
  // the vitest run log (warm runs typically print only `Finished`).
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) {
    throw new Error(
      `failed to spawn cargo build -p xtask --bin groth16-verify: ${result.error.message}`,
    );
  }

  if (result.status !== 0) {
    const parts = [
      `cargo build -p xtask --bin groth16-verify failed with exit ${String(result.status)}`,
      result.stdout?.trim() ? `stdout:\n${result.stdout.trim()}` : undefined,
      result.stderr?.trim() ? `stderr:\n${result.stderr.trim()}` : undefined,
    ].filter((part) => part !== undefined);
    throw new Error(parts.join("\n\n"));
  }
}
