import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");

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
}

export type VerifyResult =
  | Readonly<{ ok: true }>
  | Readonly<{ ok: false; code: FailCode }>;

/// Call the test-only Rust oracle that decompresses with `groth16_solana` and
/// verifies against the embedded release verifying keys. Network is unused.
export function callGroth16Verify(request: VerifyRequest): VerifyResult {
  const result = spawnSync(
    "rustup",
    ["run", "1.97.0", "cargo", "run", "-q", "-p", "xtask", "--bin", "groth16-verify"],
    {
      cwd: workspaceRoot,
      input: JSON.stringify(request),
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (result.error) throw result.error;
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
  const result = spawnSync(
    "rustup",
    ["run", "1.97.0", "cargo", "run", "-q", "-p", "xtask", "--bin", "groth16-verify", "--", "--check"],
    {
      cwd: workspaceRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (result.error) throw result.error;
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
  compressed: Readonly<{
    a: Uint8Array;
    b: Uint8Array;
    c: Uint8Array;
    commitment?: Readonly<{ commitment: Uint8Array; commitmentPok: Uint8Array }>;
  }>,
): VerifyProof {
  return {
    a: hexBytes(compressed.a),
    b: hexBytes(compressed.b),
    c: hexBytes(compressed.c),
    ...(compressed.commitment === undefined
      ? {}
      : {
          commitment: hexBytes(compressed.commitment.commitment),
          commitmentPok: hexBytes(compressed.commitment.commitmentPok),
        }),
  };
}
