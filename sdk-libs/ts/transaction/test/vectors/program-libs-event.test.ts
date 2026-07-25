import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { hashChain } from "../../src/internal.js";
import {
  EncryptedScheme,
  decodeOutputData,
  decodeProofless,
  encodeOutputData,
  encodeProofless,
  outputDataEncoding,
} from "../../src/serialization/codecs.js";
import type { Bytes32 } from "../../src/internal.js";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("program-libs/event/src/proofless.rs against the transaction codecs", () => {
  const proofless = fixture.event.proofless;

  // Ten option combinations, because the six borsh `Option`s sit in a fixed
  // order after four fixed fields and a reader that slid by one byte would
  // still decode most of them.
  for (const vector of proofless.vectors) {
    it(`decodes the Rust borsh bytes for ${vector.name}`, () => {
      const decoded = decodeProofless(hexToBytes(vector.borsh));
      expect(bytesToHex(decoded.owner)).toBe(vector.value.owner);
      expect(bytesToHex(decoded.blinding)).toBe(vector.value.blinding);
      expect(decoded.amount).toBe(BigInt(vector.value.amount));
      expect(decoded.dataHash === undefined ? null : bytesToHex(decoded.dataHash)).toBe(
        vector.value.dataHash,
      );
      expect(decoded.utxoData === undefined ? null : bytesToHex(decoded.utxoData)).toBe(
        vector.value.utxoData,
      );
      expect(decoded.zoneDataHash === undefined ? null : bytesToHex(decoded.zoneDataHash)).toBe(
        vector.value.zoneDataHash,
      );
      expect(decoded.zoneData === undefined ? null : bytesToHex(decoded.zoneData)).toBe(
        vector.value.zoneData,
      );
      expect(decoded.memo === undefined ? null : bytesToHex(decoded.memo)).toBe(vector.value.memo);
    });

    it(`re-encodes ${vector.name} to the same bytes Rust wrote`, () => {
      const bytes = hexToBytes(vector.borsh);
      expect(bytesToHex(encodeProofless(decodeProofless(bytes)))).toBe(vector.borsh);
    });

    it(`wraps ${vector.name} into the same output-data envelope as encode_output_data`, () => {
      // Rust prepends a single zero byte to the borsh body before wrapping it in
      // `OutputDataEncoding::Plaintext`. That byte is the proofless scheme tag,
      // which is what the TypeScript encoder writes from `EncryptedScheme`.
      const body = encodeProofless(decodeProofless(hexToBytes(vector.borsh)));
      const wrapped = encodeOutputData(EncryptedScheme.proofless, body);
      expect(bytesToHex(wrapped)).toBe(vector.encodeOutputData);
    });
  }

  it("preserves the memo the spec does not list", () => {
    const withMemo = proofless.vectors.find((entry) => entry.name === "memo-only");
    expect(withMemo?.value.memo).toBeTruthy();
    if (withMemo === undefined) return;
    const decoded = decodeProofless(hexToBytes(withMemo.borsh));
    expect(decoded.memo).toBeDefined();
    expect(new TextDecoder().decode(decoded.memo)).toBe("memo");
  });

  it("distinguishes an absent byte vector from a present empty one", () => {
    const empties = proofless.vectors.find((entry) => entry.name === "empty-vec-options");
    const nones = proofless.vectors.find((entry) => entry.name === "all-none");
    expect(empties && nones).toBeTruthy();
    if (empties === undefined || nones === undefined) return;
    expect(decodeProofless(hexToBytes(empties.borsh)).memo).toEqual(new Uint8Array(0));
    expect(decodeProofless(hexToBytes(nones.borsh)).memo).toBeUndefined();
    expect(empties.borsh).not.toBe(nones.borsh);
  });

  it("agrees with the Rust field order", () => {
    expect(proofless.fieldOrder).toEqual([
      "owner",
      "blinding",
      "asset",
      "amount",
      "dataHash",
      "utxoData",
      "zoneProgramId",
      "zoneDataHash",
      "zoneData",
      "memo",
    ]);
  });

  it("maps the three OutputDataEncoding tags onto the Rust discriminants", () => {
    const tags = Object.fromEntries(
      proofless.outputDataEncoding.map((entry) => [entry.name, entry.tag]),
    );
    expect(tags).toEqual({ plaintext: 0, encrypted: 1, verifiable: 2 });
    expect(outputDataEncoding(EncryptedScheme.proofless)).toBe("plaintext");
    expect(outputDataEncoding(EncryptedScheme.merge)).toBe("verifiable");
    expect(outputDataEncoding(EncryptedScheme.confidential)).toBe("encrypted");
  });

  it("round trips the output-data envelope", () => {
    const vector = proofless.vectors[0];
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    const decoded = decodeOutputData(hexToBytes(vector.encodeOutputData));
    expect(decoded.encoding).toBe("plaintext");
    expect(decoded.scheme).toBe(EncryptedScheme.proofless);
    expect(bytesToHex(decoded.body)).toBe(vector.borsh);
  });
});

describe("program-libs/hasher/src/hash_chain.rs against transaction hashChain", () => {
  for (const vector of fixture.hasher.hashChain.createHashChainFromSlice) {
    it(`matches create_hash_chain_from_slice for ${vector.name}`, () => {
      const inputs = vector.inputs.map((input) => hexToBytes(input) as Bytes32);
      expect(bytesToHex(hashChain(inputs))).toBe(vector.output);
    });
  }

  it("returns 32 zero bytes for an empty chain rather than throwing", () => {
    expect(fixture.hasher.hashChain.emptyReturnsZero).toBe(true);
    expect(bytesToHex(hashChain([]))).toBe("0".repeat(64));
  });

  it("returns a single element unhashed", () => {
    const single = fixture.hasher.hashChain.createHashChainFromSlice.find(
      (entry) => entry.name === "single",
    );
    expect(single).toBeDefined();
    if (single === undefined) return;
    expect(single.output).toBe(single.inputs[0]);
  });

  it("is order sensitive", () => {
    const pair = fixture.hasher.hashChain.createHashChainFromSlice.find(
      (entry) => entry.name === "pair",
    );
    const reversed = fixture.hasher.hashChain.createHashChainFromSlice.find(
      (entry) => entry.name === "pair-reversed",
    );
    expect(pair?.output).not.toBe(reversed?.output);
  });
});
