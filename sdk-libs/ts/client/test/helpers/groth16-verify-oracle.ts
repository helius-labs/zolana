import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");

/// Prefer `CARGO_TARGET_DIR` so a custom target layout still finds the binary CI
/// (and local warmup) built with `cargo build -p xtask --bin groth16-verify`.
function groth16VerifyBin(): string {
  const targetDir = process.env["CARGO_TARGET_DIR"] ?? path.join(workspaceRoot, "target");
  return path.join(targetDir, "debug", "groth16-verify");
}

/// Resolve the pre-built oracle. Compiling under vitest via `cargo run` is
/// forbidden: a cold compile under a parallel suite pool exceeds the test
/// budget and surfaces only as a timeout.
function resolveGroth16VerifyBin(): string {
  const bin = groth16VerifyBin();
  if (!existsSync(bin)) {
    throw new Error(
      [
        `missing groth16-verify oracle binary: ${bin}`,
        "TypeScript suites require it pre-built; they do not compile xtask under vitest.",
        "Build with: cargo build -p xtask --bin groth16-verify",
      ].join("\n"),
    );
  }
  return bin;
}

function runGroth16Verify(args: readonly string[], input?: string) {
  const result = spawnSync(resolveGroth16VerifyBin(), [...args], {
    cwd: workspaceRoot,
    input,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return result;
}

export type VerifyFamily =
  | "confidential"
  | "zone"
  | "zone_authority"
  | "merge"
  | "merge_zone";

export type VerifyRail = "eddsa" | "p256";

export type FailCode =
  | "encoding"
  | "rail_mismatch"
  | "verification_failure"
  | "unknown_vk";

export interface VerifyProof {
  readonly a: string;
  readonly b: string;
  readonly c: string;
  readonly commitment?: string;
  readonly commitmentPok?: string;
}

export interface VerifyRequest {
  readonly family: VerifyFamily;
  readonly rail?: VerifyRail;
  readonly shape: Readonly<{ inputs: number; outputs: number }>;
  readonly publicInputHashBytes: string;
  readonly proof: VerifyProof;
  readonly encoding?: "compressed" | "uncompressed";
  readonly op?: "verify" | "compress";
}

export type VerifyResult =
  | Readonly<{ ok: true; proof?: VerifyProof }>
  | Readonly<{ ok: false; code: FailCode }>;

/// Call the test-only Rust oracle that decompresses with `groth16_solana` and
/// verifies against the embedded release verifying keys. Network is unused.
export function callGroth16Verify(request: VerifyRequest): VerifyResult {
  const result = runGroth16Verify([], JSON.stringify(request));
  if (result.status !== 0) {
    throw new Error(`groth16-verify exited ${String(result.status)}: ${result.stderr}`);
  }
  const lines = result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const last = lines.at(-1);
  if (last === undefined) throw new Error("groth16-verify produced no JSON");
  return JSON.parse(last) as VerifyResult;
}

export function groth16VerifySelfCheck(): void {
  const result = runGroth16Verify(["--check"]);
  if (result.status !== 0) {
    throw new Error(`groth16-verify --check failed: ${result.stderr}`);
  }
}

export function hexBytes(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function flipBit(bytes: Uint8Array, byteIndex: number, bit = 0): Uint8Array {
  const next = new Uint8Array(bytes);
  next[byteIndex] = (next[byteIndex] ?? 0) ^ (1 << bit);
  return next;
}

export function proofWire(
  proof: Readonly<{
    a: Uint8Array;
    b: Uint8Array;
    c: Uint8Array;
    commitment?: Readonly<{ commitment: Uint8Array; commitmentPok: Uint8Array }>;
  }>,
): VerifyProof {
  return {
    a: hexBytes(proof.a),
    b: hexBytes(proof.b),
    c: hexBytes(proof.c),
    ...(proof.commitment === undefined
      ? {}
      : {
          commitment: hexBytes(proof.commitment.commitment),
          commitmentPok: hexBytes(proof.commitment.commitmentPok),
        }),
  };
}

/// Compress through `solana_bn254::alt_bn128_*_compress_be` (parity oracle).
export function rustCompressProof(proof: VerifyProof): VerifyProof {
  const result = runGroth16Verify([], JSON.stringify({ op: "compress", proof }));
  if (result.status !== 0) {
    throw new Error(`groth16-verify compress exited ${String(result.status)}: ${result.stderr}`);
  }
  const lines = result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const last = lines.at(-1);
  if (last === undefined) throw new Error("groth16-verify compress produced no JSON");
  const parsed = JSON.parse(last) as VerifyResult;
  if (!parsed.ok || parsed.proof === undefined) {
    throw new Error(`rust compress failed: ${last}`);
  }
  return parsed.proof;
}
