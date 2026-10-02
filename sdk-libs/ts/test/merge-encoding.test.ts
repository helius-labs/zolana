import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";
import vector from "../../../test-vectors/merge_encoding.json" with { type: "json" };
import {
  decodeMergeOutputDerivation,
  encodeMergeTransactInstructionData,
  mergeExternalDataHash,
} from "../src/interface/codecs/index.js";
import { BN254_SCALAR_ORDER } from "../src/hasher/index.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { mergeMaskedAmount, mergeUnmaskedAmount } from "../src/keypair/merge/index.js";
import { MAX_MERGE_INPUTS } from "../src/interface/constants.js";
import { copyBytes, sha256 } from "../src/interface/internal.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  MergeTransactInstructionData,
} from "../src/interface/types.js";

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
  maskedAmount: new Uint8Array(32) as Bytes32,
  txViewingPk: new Uint8Array(33) as Bytes33,
  salt: new Uint8Array(16) as Bytes16,
  outputData: new Uint8Array(),
};

/** The masked amount, key, salt and empty ciphertext after the cache option. */
const MERGE_TAIL = 32 + 33 + 16 + 2;

describe("shared merge encoding", () => {
  it("matches the Rust cached-merge encoding and external hash", () => {
    const address = getAddressDecoder().decode(Buffer.from(vector.cached.cache_address, "hex"));
    const encoded = encodeMergeTransactInstructionData({
      ...data,
      cacheSlot: vector.cached.cache_slot,
    });
    expect(encoded).toHaveLength(528 + MERGE_TAIL);
    expect(Array.from(encoded.slice(-2 - MERGE_TAIL, -MERGE_TAIL))).toEqual([
      1,
      vector.cached.cache_slot,
    ]);
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

  it("matches the Rust wide-merge encoding and refuses empty and oversized lists", () => {
    expect(MAX_MERGE_INPUTS).toBe(vector.wide.input_count);
    const nullifiers = (count: number) => Array.from({ length: count }, (_, index) => field(index));
    const wide = encodeMergeTransactInstructionData({
      ...data,
      nullifiers: nullifiers(vector.wide.input_count),
    });
    expect(hex(sha256(wide))).toBe(vector.wide.instruction_sha256);
    for (const count of [0, MAX_MERGE_INPUTS + 1]) {
      expect(() =>
        encodeMergeTransactInstructionData({ ...data, nullifiers: nullifiers(count) }),
      ).toThrow("INTERFACE_INVALID_LENGTH");
    }
    expect(() =>
      encodeMergeTransactInstructionData({ ...data, nullifiers: nullifiers(9) }),
    ).not.toThrow();
  });

  it("matches the Rust plain-merge encoding and external hash", () => {
    const encoded = encodeMergeTransactInstructionData(data);
    expect(encoded).toHaveLength(527 + MERGE_TAIL);
    expect(encoded.at(-1 - MERGE_TAIL)).toBe(0);
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

describe("merge output derivation", () => {
  it("reads the masked amount and a ring merge's ring-data hash", () => {
    expect(decodeMergeOutputDerivation(field(1))).toEqual({
      maskedAmount: field(1),
    });
    expect(decodeMergeOutputDerivation(new Uint8Array([...field(1), ...field(2)]))).toEqual({
      maskedAmount: field(1),
      outputRingDataHash: field(2),
    });
    for (const length of [0, 31, 33, 63, 65]) {
      expect(decodeMergeOutputDerivation(new Uint8Array(length))).toBeUndefined();
    }
  });

  it("recovers exactly the u64 amounts it masked", () => {
    const mask = bigIntToBytes(BN254_SCALAR_ORDER - 5n) as Bytes32;
    for (const amount of [0n, 4n, 5n, 0xffff_ffff_ffff_ffffn]) {
      expect(mergeUnmaskedAmount(mergeMaskedAmount(amount, mask), mask)).toBe(amount);
    }
    expect(mergeUnmaskedAmount(mergeMaskedAmount(1n << 64n, mask), mask)).toBeUndefined();
    expect(
      mergeUnmaskedAmount(bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32, field(0)),
    ).toBeUndefined();
  });
});
