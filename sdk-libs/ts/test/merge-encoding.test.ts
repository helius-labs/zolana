import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";
import vector from "../../../test-vectors/merge_encoding.json" with { type: "json" };
import {
  encodeMergeBody,
  encodeMergeTransactInstructionData,
  mergeExternalDataHash,
} from "../src/interface/codecs/index.js";
import {
  MAX_MERGE_INPUTS,
  MERGE_CIPHERTEXT_LENGTH,
  MERGE_INPUT_COUNT,
} from "../src/interface/constants.js";
import { copyBytes, sha256 } from "../src/interface/internal.js";
import type {
  Bytes32,
  Bytes33,
  Bytes128,
  MergeBody,
  MergeEnvelope,
  MergeProofCommitment,
  MergeTransactInstructionData,
} from "../src/interface/types.js";

function field(value: number): Bytes32 {
  return copyBytes(new Uint8Array(32).fill(value), 32) as Bytes32;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string, length: number): Uint8Array {
  return copyBytes(Uint8Array.from(Buffer.from(value, "hex")), length);
}

const proofCommitment: MergeProofCommitment = {
  commitment: fromHex(vector.proof_commitment.commitment, 32) as Bytes32,
  commitmentPok: fromHex(vector.proof_commitment.commitment_pok, 32) as Bytes32,
};

const envelope: MergeEnvelope = {
  ephemeralPk: fromHex(vector.envelope.ephemeral_pk, 33) as Bytes33,
  ciphertext: fromHex(vector.envelope.ciphertext, MERGE_CIPHERTEXT_LENGTH),
};

const ENVELOPE_LENGTH = 32 + 32 + 33 + MERGE_CIPHERTEXT_LENGTH;

const body: MergeBody = {
  expiryUnixTs: 42n,
  proof: {
    a: field(1),
    b: copyBytes(new Uint8Array(128).fill(2), 128) as Bytes128,
    c: field(3),
  },
  outputUtxoHash: field(9),
  eddsaOwner: false,
  privateTxHash: field(3),
  nullifiers: Array.from({ length: MERGE_INPUT_COUNT }, (_, index) => field(index)),
  utxoTreeRootIndex: 4,
  nullifierTreeRootIndex: 10,
};

const data: MergeTransactInstructionData = { ...body, proofCommitment, envelope };

function envelopeBytes(): number[] {
  return [
    ...proofCommitment.commitment,
    ...proofCommitment.commitmentPok,
    ...envelope.ephemeralPk,
    ...envelope.ciphertext,
  ];
}

describe("shared merge encoding", () => {
  it("matches the Rust cached-merge encoding and external hash", () => {
    const address = getAddressDecoder().decode(Buffer.from(vector.cached.cache_address, "hex"));
    const encoded = encodeMergeTransactInstructionData({
      ...data,
      cacheSlot: vector.cached.cache_slot,
    });
    expect(encoded).toHaveLength(1177);
    expect(Array.from(encoded.slice(-(ENVELOPE_LENGTH + 2)))).toEqual([
      1,
      vector.cached.cache_slot,
      ...envelopeBytes(),
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
    expect(wide).toHaveLength(408 + 32 * vector.wide.input_count);
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
    expect(encoded).toHaveLength(1176);
    expect(Array.from(encoded.slice(-(ENVELOPE_LENGTH + 1)))).toEqual([0, ...envelopeBytes()]);
    expect(Array.from(encoded.slice(0, -ENVELOPE_LENGTH))).toEqual(
      Array.from(encodeMergeBody(body)),
    );
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

  it("matches the Rust ring-merge encoding: the ring data hash and the body alone", () => {
    const ringBody = encodeMergeBody(body);
    expect(ringBody).toHaveLength(271 + 32 * MERGE_INPUT_COUNT);
    const encoded = Uint8Array.from([
      ...fromHex(vector.ring.output_ring_data_hash, 32),
      ...ringBody,
    ]);
    expect(hex(sha256(encoded))).toBe(vector.ring.instruction_sha256);
    const cached = encodeMergeBody({ ...body, cacheSlot: 5 });
    expect(cached).toHaveLength(ringBody.length + 1);
    expect(Array.from(cached.slice(-2))).toEqual([1, 5]);
  });

  it.each([
    ["commitment", { commitment: new Uint8Array(31) as Bytes32 }],
    ["commitmentPok", { commitmentPok: new Uint8Array(33) as Bytes32 }],
  ] as const)("refuses a proof commitment whose %s has the wrong length", (name, override) => {
    expect(() =>
      encodeMergeTransactInstructionData({
        ...data,
        proofCommitment: { ...proofCommitment, ...override },
      }),
    ).toThrow(
      expect.objectContaining({
        code: "INTERFACE_INVALID_LENGTH",
        details: expect.objectContaining({ name: `proofCommitment.${name}` }),
      }),
    );
  });

  it.each([
    ["ephemeralPk", { ephemeralPk: new Uint8Array(32) as Bytes33 }],
    ["ciphertext", { ciphertext: new Uint8Array(MERGE_CIPHERTEXT_LENGTH + 1) }],
    ["ciphertext", { ciphertext: new Uint8Array(MERGE_CIPHERTEXT_LENGTH - 1) }],
  ] as const)("refuses an envelope whose %s has the wrong length", (name, override) => {
    expect(() =>
      encodeMergeTransactInstructionData({ ...data, envelope: { ...envelope, ...override } }),
    ).toThrow(
      expect.objectContaining({
        code: "INTERFACE_INVALID_LENGTH",
        details: expect.objectContaining({ name: `envelope.${name}` }),
      }),
    );
  });
});
