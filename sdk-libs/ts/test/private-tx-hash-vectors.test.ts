import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/private_tx_hash.json" with { type: "json" };
import { privateTxHash, transactMessageHash } from "../src/transaction/instructions/transact.js";
import type { Bytes32 } from "../src/keypair/index.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function committed(name: string): string {
  const vector = vectors.vectors.find((entry) => entry.name === name);
  if (vector === undefined) {
    throw new Error(`missing vector ${name}`);
  }
  return vector.private_tx_hash;
}

describe("privateTxHash known-answer vectors", () => {
  it("covers every case the contract pins", () => {
    expect(vectors.vectors.map((vector) => vector.name)).toEqual([
      "compact",
      "padded",
      "padding_moved",
      "address_nullifier",
      "two_inputs",
      "reordered_inputs",
      "single_slot_spend",
      "single_slot_address",
      "field_modulus_minus_one",
    ]);
  });

  it.each(vectors.vectors)("$name hashes to the committed private tx hash", (vector) => {
    expect(
      hex(
        privateTxHash({
          inputHashes: vector.input_hashes.map(bytes),
          outputHashes: vector.output_hashes.map(bytes),
          addressNullifiers: vector.address_nullifiers.map(bytes),
          blinding: bytes(vector.blinding),
        }),
      ),
    ).toBe(vector.private_tx_hash);
  });

  it.each(vectors.vectors)("$name signs the committed message hash", (vector) => {
    expect(
      hex(transactMessageHash(bytes(vector.private_tx_hash), bytes(vector.external_data_hash))),
    ).toBe(vector.message_hash);
  });

  it.each(
    vectors.vectors.filter((vector) =>
      vector.address_nullifiers.every((value) => /^0+$/u.test(value)),
    ),
  )("$name hashes the same with the address nullifiers omitted", (vector) => {
    expect(
      hex(
        privateTxHash({
          inputHashes: vector.input_hashes.map(bytes),
          outputHashes: vector.output_hashes.map(bytes),
          blinding: bytes(vector.blinding),
        }),
      ),
    ).toBe(vector.private_tx_hash);
  });

  it("skips padding and keeps the order of nonzero entries", () => {
    expect(committed("padded")).toBe(committed("compact"));
    expect(committed("padding_moved")).toBe(committed("compact"));
    expect(committed("address_nullifier")).not.toBe(committed("padding_moved"));
    expect(committed("reordered_inputs")).not.toBe(committed("two_inputs"));
  });
});
