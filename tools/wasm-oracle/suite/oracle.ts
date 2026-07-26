import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

/**
 * The canonical Rust compiled to WebAssembly. Each export takes one JSON request
 * string and returns one JSON outcome string.
 */
export interface Oracle {
  hash_field(valueHex: string): string;
  split_be_128(valueHex: string): string;
  sha256_be(preimageHex: string): string;
  pk_field_compressed(compressedHex: string): string;
  owner_pk_field_compressed(compressedHex: string): string;
  pack33(bytesHex: string): string;
  ciphertext_hash(ciphertextHex: string): string;
  asset_field(addressHex: string): string;
  signed_to_field(valueDec: string): string;
  merkle_root(request: string): string;
  merkle_proof(request: string): string;
  merkle_path(request: string): string;
  merkle_leaf(request: string): string;
  merkle_verify(request: string): string;
  merkle_subtrees(request: string): string;
  merkle_canopy(request: string): string;
  merkle_history_root_index(request: string): string;
  merkle_history_root_index_v2(request: string): string;
  indexed_root(request: string): string;
  indexed_non_inclusion_proof(request: string): string;
  indexed_non_inclusion_proof_round_trip(request: string): string;
}

export const oracle = require("../pkg/zolana_wasm_oracle.js") as Oracle;

export type Outcome =
  | { readonly arm: "ok"; readonly value: unknown }
  | { readonly arm: "err"; readonly code: string; readonly details: string };

export function parseOutcome(json: string): Outcome {
  const parsed = JSON.parse(json) as
    | { ok: unknown }
    | { err: { code: string; details: string } };
  if ("ok" in parsed) return { arm: "ok", value: parsed.ok };
  return { arm: "err", code: parsed.err.code, details: parsed.err.details };
}

/**
 * Runs a native TypeScript call and reports which arm it took. A thrown value is
 * a rejection; its `code` is read when the error carries one, so a Rust variant
 * name and a TypeScript error code sit side by side in the report.
 */
export function outcomeOf(call: () => unknown): Outcome {
  try {
    return { arm: "ok", value: call() };
  } catch (thrown) {
    const code =
      thrown !== null &&
      typeof thrown === "object" &&
      "code" in thrown &&
      typeof thrown.code === "string"
        ? thrown.code
        : thrown instanceof Error
          ? thrown.constructor.name
          : "NonError";
    const details = thrown instanceof Error ? thrown.message : String(thrown);
    return { arm: "err", code, details };
  }
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexList(values: readonly Uint8Array[]): readonly string[] {
  return values.map(hex);
}
