import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/audit-disclosure.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import {
  AUDIT_DISCLOSURE_FIELD_COUNT,
  AUDIT_OUTPUT_FIELD_COUNT,
  AUDIT_OUTPUT_SLOTS,
  encryptTransactionViewingSecret,
  openAuditOutputDisclosure,
  type AuditOutputOpening,
} from "../src/keypair/audit.js";
import type { Bytes16, Bytes32 } from "../src/keypair/bytes.js";
import { X25519Secret } from "../src/keypair/x25519.js";
import { hashChain4 } from "../src/transaction/internal.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function fields(values: readonly string[]): Bytes32[] {
  if (values.length !== AUDIT_DISCLOSURE_FIELD_COUNT) {
    throw new RangeError(`expected ${String(AUDIT_DISCLOSURE_FIELD_COUNT)} fields`);
  }
  return values.map((value) => bytes<Bytes32>(value, 32));
}

function openings(values: readonly Bytes32[]): AuditOutputOpening[] {
  return Array.from({ length: AUDIT_OUTPUT_SLOTS }, (_, slot) => {
    const at = (index: number): Bytes32 => {
      const field = values[slot * AUDIT_OUTPUT_FIELD_COUNT + index];
      if (field === undefined) throw new RangeError("missing disclosure field");
      return field;
    };
    return {
      domain: at(0),
      treeId: at(1),
      ownerHash: at(2),
      asset: at(3),
      amount: at(4),
      blinding: at(5),
      dataHash: at(6),
      ringDataHash: at(7),
      ringProgramId: at(8),
    };
  });
}

await initializePoseidon();

/** Written by the Go circuit tests from the circuit's own gadgets. */
describe("shared audit disclosure vector (test-vectors/audit-disclosure.json)", () => {
  const key = bytes<Bytes32>(vector.key, 32);
  const salt = bytes<Bytes16>(vector.salt, 16);
  const plaintext = fields(vector.fields);
  const pad = fields(vector.pad);
  const ciphertext = fields(vector.ciphertext);
  const disclosureHash = bytes<Bytes32>(vector.disclosure_hash, 32);
  const seal = (outputs: readonly AuditOutputOpening[]) =>
    encryptTransactionViewingSecret(key, X25519Secret.generate().publicKey(), { salt, outputs })
      .message.disclosure;

  it("derives the pad, the ciphertext of all-zero fields", () => {
    const zero = new Uint8Array(32) as Bytes32;
    expect(
      seal(openings(Array.from({ length: AUDIT_DISCLOSURE_FIELD_COUNT }, () => zero))),
    ).toEqual(pad);
  });

  it("seals the fields to the pinned ciphertext", () => {
    expect(seal(openings(plaintext))).toEqual(ciphertext);
  });

  it("opens the pinned ciphertext to the fields", () => {
    expect(openAuditOutputDisclosure(key, salt, ciphertext)).toEqual(openings(plaintext));
  });

  it("hashes the ciphertext with the 4-ary chain", () => {
    expect(hashChain4(ciphertext)).toEqual(disclosureHash);
  });
});
