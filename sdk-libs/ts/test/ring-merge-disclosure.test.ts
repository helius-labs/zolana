import { describe, expect, it, vi } from "vitest";

import vector from "../../../test-vectors/ring-merge-anonymous.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import { Reader, Writer, addressBytes, encodeBase58 } from "../src/interface/internal.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import { ringProofRequestBody } from "../src/client/prover/ring.js";
import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  sealRingMergeDisclosureWith,
  readRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
  type RingMergeOpening,
} from "../src/ring/merge-disclosure.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value.replace(/^0x/, ""), "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function disclosure(): RingMergeDisclosure {
  return {
    proof: new Uint8Array(192).fill(7),
    ephemeralPublicKey: bytes<Bytes33>(vector.eph_pk, 33),
    ciphertext: bytes<Bytes32>(vector.envelope_ciphertext, 32),
    fields: vector.fields.map((field) => bytes<Bytes32>(field, 32)),
  };
}

function opening(): RingMergeOpening {
  return {
    ownerKey: encodeBase58(bytes(vector.request.ownerKey, 32)),
    nullifierPublicKey: bytes(vector.nullifier_pk, 32),
    mint: encodeBase58(bytes(vector.mint, 32)),
    amount: BigInt(vector.amount),
    outputBlinding: bytes(vector.output_blinding, 32),
    inputCommitments: vector.input_commitments.map((value) => bytes<Bytes32>(value, 32)),
  };
}

describe("anonymous ring merge disclosure (test-vectors/ring-merge-anonymous.json)", () => {
  it("opens the Go disclosure and hashes the Go statement", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const salt = bytes<Bytes16>(vector.salt, 16);
    const opening = openRingMergeDisclosure(auditor, disclosure(), salt);
    expect(Buffer.from(addressBytes(opening.ownerKey)).toString("hex")).toBe(
      vector.request.ownerKey.slice(2),
    );
    expect(Buffer.from(opening.nullifierPublicKey).toString("hex")).toBe(
      vector.nullifier_pk.slice(2),
    );
    expect(Buffer.from(addressBytes(opening.mint)).toString("hex")).toBe(vector.mint.slice(2));
    expect(opening.amount).toBe(BigInt(vector.amount));
    expect(Buffer.from(opening.outputBlinding).toString("hex")).toBe(
      vector.output_blinding.slice(2),
    );
    expect(
      opening.inputCommitments.map((value) => `0x${Buffer.from(value).toString("hex")}`),
    ).toEqual(vector.input_commitments);
    const otherSalt = salt.slice() as Bytes16;
    otherSalt[0] = (otherSalt[0] ?? 0) ^ 1;
    expect(() => openRingMergeDisclosure(auditor, disclosure(), otherSalt)).toThrow();

    const hash = ringMergeAnonymousPublicInputHash({
      privateTxHash: bytes(vector.request.privateTxHash, 32),
      outputUtxoHash: bytes(vector.request.outputUtxoHash, 32),
      firstNullifier: bytes(vector.request.firstNullifier, 32),
      ringId: bytes(vector.request.ringProgramId, 32),
      auditorPublicKey: X25519PublicKey.fromBytes(bytes(vector.auditor_pk, 33)),
      disclosure: disclosure(),
      salt,
    });
    expect(`0x${Buffer.from(hash).toString("hex")}`).toBe(vector.public_input_hash);
  });

  it("seals the Go disclosure under the vector keys", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    try {
      const sealed = sealRingMergeDisclosureWith({
        opening: opening(),
        salt: bytes(vector.salt, 16),
        auditor: auditor.publicKey(),
        ephemeral,
        disclosureKey: bytes(vector.request.disclosureKey, 32),
      });
      expect(sealed.disclosure).toEqual({
        ephemeralPublicKey: bytes(vector.eph_pk, 33),
        ciphertext: bytes(vector.envelope_ciphertext, 32),
        fields: vector.fields.map((field) => bytes(field, 32)),
      });
      expect(sealed.ephemeralSecret).toEqual(bytes(vector.request.ephSk, 32));
    } finally {
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("wipes the opening when the auditor key exchange throws", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    vi.spyOn(ephemeral, "ecdh").mockImplementation(() => {
      throw new RangeError("small order");
    });
    const fill = vi.spyOn(Uint8Array.prototype, "fill");
    try {
      expect(() =>
        sealRingMergeDisclosureWith({
          opening: opening(),
          salt: bytes(vector.salt, 16),
          auditor: auditor.publicKey(),
          ephemeral,
          disclosureKey: bytes(vector.request.disclosureKey, 32),
        }),
      ).toThrow("small order");
      const length = mergeDisclosureFieldCount(vector.width) * 31;
      const wiped = fill.mock.contexts.filter(
        (buffer): buffer is Uint8Array => buffer instanceof Uint8Array && buffer.length === length,
      );
      expect(wiped).not.toHaveLength(0);
      for (const buffer of wiped) expect(buffer.every((byte) => byte === 0)).toBe(true);
    } finally {
      fill.mockRestore();
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("copies no secret out of a refused seal", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    const secretBytes = vi.spyOn(ephemeral, "secretBytes");
    try {
      expect(() =>
        sealRingMergeDisclosureWith({
          opening: opening(),
          salt: new Uint8Array(15) as Bytes16,
          auditor: auditor.publicKey(),
          ephemeral,
          disclosureKey: bytes(vector.request.disclosureKey, 32),
        }),
      ).toThrow();
      expect(secretBytes).not.toHaveBeenCalled();
    } finally {
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("writes the Go prover body of custom-ring-merge-anonymous-8", () => {
    const request = vector.request;
    const field = (value: string) => bytes<Bytes32>(value, 32);
    const body = ringProofRequestBody({
      kind: "anonymousMerge",
      publicInputHash: field(request.publicInputHash),
      privateTxHash: field(request.privateTxHash),
      outputUtxoHash: field(request.outputUtxoHash),
      firstNullifier: field(request.firstNullifier),
      ringProgramId: field(request.ringProgramId),
      auditorPk: field(request.auditorPk),
      salt: field(request.salt),
      ephSk: field(request.ephSk),
      disclosureKey: field(request.disclosureKey),
      ownerKey: field(request.ownerKey),
      nullifierSecret: field(request.nullifierSecret),
      mintChunks: request.mintChunks.map(field),
      inputs: request.inputs.map((slot) => ({
        domain: field(slot.domain),
        treeId: field(slot.treeId),
        amount: field(slot.amount),
        blinding: field(slot.blinding),
        ringDataHash: field(slot.ringDataHash),
      })),
      outputTreeId: field(request.outputTreeId),
      outputRingDataHash: field(request.outputRingDataHash),
    });
    expect(JSON.parse(JSON.stringify(body))).toEqual(request);
  });

  it("writes the option ahead of the SPP body and reads back its own layout", () => {
    expect([8, 24, 52].map(mergeDisclosureFieldCount)).toEqual([13, 30, 59]);
    const absent = writeRingMergeDisclosure(new Writer(), undefined).finish();
    expect(absent).toEqual(Uint8Array.of(0));
    const present = writeRingMergeDisclosure(new Writer(), disclosure()).finish();
    expect(present.length).toBe(1 + 192 + 33 + 32 + 1 + 32 * vector.fields.length);
    expect(readRingMergeDisclosure(new Reader(present))).toEqual(disclosure());
    const tagged = present.slice();
    tagged[0] = 2;
    expect(() => readRingMergeDisclosure(new Reader(tagged))).toThrow();
  });
});
