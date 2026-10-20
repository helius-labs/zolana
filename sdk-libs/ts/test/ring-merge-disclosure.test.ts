import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/ring-merge-anonymous.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import { Reader, Writer, addressBytes } from "../src/interface/internal.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  readRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
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
      memberRegistryRoot: bytes(vector.request.memberRegistryRoot, 32),
      auditorPublicKey: X25519PublicKey.fromBytes(bytes(vector.auditor_pk, 33)),
      disclosure: disclosure(),
      salt,
    });
    expect(`0x${Buffer.from(hash).toString("hex")}`).toBe(vector.public_input_hash);
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
