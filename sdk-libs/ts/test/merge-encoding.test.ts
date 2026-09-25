import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";
import vector from "../../../test-vectors/merge_encoding.json" with { type: "json" };
import {
  encodeMergeTransactInstructionData,
  mergeExternalDataHash,
} from "../src/interface/codecs/index.js";
import { copyBytes, sha256 } from "../src/interface/internal.js";
import type { Bytes32, Bytes128, MergeTransactInstructionData } from "../src/interface/types.js";

function field(value: number): Bytes32 {
  return copyBytes(new Uint8Array(32).fill(value), 32) as Bytes32;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const data: MergeTransactInstructionData = {
  expiryUnixTs: 42n,
  proof: {
    a: field(1),
    b: copyBytes(new Uint8Array(128).fill(2), 128) as Bytes128,
    c: field(3),
  },
  outputUtxoHash: field(9),
  eddsaOwner: false,
  privateTxHash: field(3),
  nullifiers: Array.from({ length: 8 }, (_, index) => field(index)),
  utxoTreeRootIndex: 4,
  nullifierTreeRootIndex: 10,
};

describe("shared merge encoding", () => {
  it("matches the Rust cached-merge encoding and external hash", () => {
    const address = getAddressDecoder().decode(Buffer.from(vector.cached.cache_address, "hex"));
    const encoded = encodeMergeTransactInstructionData({
      ...data,
      cacheSlot: vector.cached.cache_slot,
    });
    expect(encoded).toHaveLength(528);
    expect(Array.from(encoded.slice(-2))).toEqual([1, vector.cached.cache_slot]);
    expect(hex(sha256(encoded))).toBe(vector.cached.instruction_sha256);
    expect(
      hex(
        mergeExternalDataHash({
          instructionTag: 17,
          expiryUnixTs: data.expiryUnixTs,
          outputUtxoHash: data.outputUtxoHash,
          cache: { address, slot: vector.cached.cache_slot },
        }),
      ),
    ).toBe(vector.cached.external_data_hash);
  });

  it("matches the Rust plain-merge encoding and external hash", () => {
    const encoded = encodeMergeTransactInstructionData(data);
    expect(encoded).toHaveLength(527);
    expect(encoded.at(-1)).toBe(0);
    expect(hex(sha256(encoded))).toBe(vector.instruction_sha256);
    expect(
      hex(
        mergeExternalDataHash({
          instructionTag: 17,
          expiryUnixTs: data.expiryUnixTs,
          outputUtxoHash: data.outputUtxoHash,
        }),
      ),
    ).toBe(vector.external_data_hash);
  });
});
