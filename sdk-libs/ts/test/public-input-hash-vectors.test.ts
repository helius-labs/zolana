import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/public_input_hash.json" with { type: "json" };
import { resolvedPublicInputHash, transferPublicInputHash } from "../src/client/prover/assembly.js";
import { mergePublicInputs } from "../src/client/prover/merge.js";
import type { Bytes32 } from "../src/keypair/index.js";
import type { TreeSlot } from "../src/interface/tree-slot.js";

function field(value: string): bigint {
  return BigInt(`0x${value}`);
}

function hex(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function treeSlots(
  slots: readonly { id: number; utxo_root: string; nullifier_root: string }[],
): readonly TreeSlot[] {
  return slots.map((slot) => ({
    id: slot.id,
    utxoRoot: bytes(slot.utxo_root),
    nullifierRoot: bytes(slot.nullifier_root),
  }));
}

// Produced by the Rust provers' hash (sdk-libs/client/tests/public_input_hash_vectors.rs).
// The wide and compact shapes are the ones a left fold would hash differently.
describe("public input hash known-answer vectors", () => {
  it("covers the shapes the contract pins", () => {
    expect(vectors.transfers.map((vector) => vector.name)).toEqual([
      "full_2x3",
      "compact_2x3",
      "full_36x2",
      "compact_36x2",
      "compact_5x4_without_owner_chain",
    ]);
    expect(vectors.merges.map((vector) => vector.name)).toEqual([
      "full_8",
      "compact_8",
      "full_36",
      "compact_36",
    ]);
  });

  it.each(vectors.transfers)("transfer $name hashes to the committed value", (vector) => {
    const [cacheTreeId, cacheReadHashChain] = vector.cached_inputs.map(field);
    const hash = transferPublicInputHash({
      nullifiers: vector.nullifiers.map(field),
      outputHashes: vector.output_hashes.map(field),
      outputTreeId: vector.output_tree_id,
      privateTxHash: field(vector.private_tx_hash),
      externalDataHash: field(vector.external_data_hash),
      publicSlots: vector.public_assets.flatMap((asset, index) => [
        field(asset),
        field(vector.public_amounts[index] ?? ""),
      ]),
      ringProgramId: field(vector.ring_program_id),
      signerPublicKeyHashes: vector.signer_pk_hashes.map(field),
      inputFlags: field(vector.input_flags),
      publishedOutputOwnerPublicKeyHashes: vector.output_owner_pk_hashes?.map(field),
      cacheTreeId: cacheTreeId ?? 0n,
      cacheReadHashChain: cacheReadHashChain ?? 0n,
      cacheReadHashes: [],
      cacheIsCached: [],
      cacheReadIndex: [],
      treeSlots: treeSlots(vector.tree_slots),
    });
    expect(hex(hash)).toBe(vector.public_input_hash);
  });

  it.each(vectors.merges)("merge $name hashes to the committed value", (vector) => {
    const publicInputs = mergePublicInputs({
      nullifiers: vector.nullifiers.map(field),
      outputHash: field(vector.output_hash),
      outputTreeId: vector.output_tree_id,
      privateTxHash: field(vector.private_tx_hash),
      externalDataHash: field(vector.external_data_hash),
      owner: [field(vector.owner_pk_hash), field(vector.nullifier_pk)],
    });
    expect(hex(resolvedPublicInputHash(publicInputs, treeSlots(vector.tree_slots)))).toBe(
      vector.public_input_hash,
    );
  });
});
