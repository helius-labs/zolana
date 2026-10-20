import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/audit-disclosure-anonymous.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import {
  auditDisclosureLength,
  decodeAnonymousAuditDisclosure,
  encodeAnonymousAuditDisclosure,
  encryptTransactionViewingSecret,
  isDummyAnonymousOutput,
  openAnonymousAuditDisclosure,
} from "../src/keypair/audit.js";
import type { Bytes16, Bytes32 } from "../src/keypair/bytes.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { hashChain4 } from "../src/transaction/internal.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function fields(values: readonly string[]): Bytes32[] {
  return values.map((value) => bytes<Bytes32>(value, 32));
}

await initializePoseidon();

/** Written by the Go circuit tests from the circuit's own gadgets. */
describe("shared anonymous audit disclosure vector", () => {
  const key = bytes<Bytes32>(vector.key, 32);
  const salt = bytes<Bytes16>(vector.salt, 16);
  const shape = { anonymous: true, inputs: vector.n_in, outputs: vector.n_out };
  const length = 62 + 93 * vector.n_in + 124 * vector.n_out;
  const plaintext = bytes<Uint8Array>(vector.plaintext, length);
  const disclosure = decodeAnonymousAuditDisclosure(plaintext, shape);
  const ciphertext = fields(vector.ciphertext);

  it("reads four chunks per output, the recipient address only", () => {
    expect(auditDisclosureLength(shape)).toBe(vector.fields.length);
    expect(disclosure.inputs).toHaveLength(vector.n_in);
    expect(disclosure.outputs).toHaveLength(vector.n_out);
    expect(disclosure.outputs.map(isDummyAnonymousOutput)).toEqual([false, true, false, false]);
    const first = disclosure.outputs[0]!;
    expect(first.identityTag).toBe(0x53);
    expect(first.nullifierPublicKey).toEqual(
      bytes<Bytes32>("06abb007f62900df5b600765dcc662923fd1e683e2161e45f2a53b6960fa6cf5", 32),
    );
    expect(first.viewingPublicKey[0]).toBe(4);
    expect(encodeAnonymousAuditDisclosure(disclosure)).toEqual(plaintext);
  });

  it("seals the slots to the pinned ciphertext under the shared pad", () => {
    const sealed = encryptTransactionViewingSecret(key, X25519Keypair.generate().publicKey(), {
      salt,
      anonymous: disclosure,
    }).message.disclosure;
    expect(sealed).toEqual(ciphertext);
  });

  it("opens the pinned ciphertext and hashes it with the 4-ary chain", () => {
    expect(openAnonymousAuditDisclosure(key, salt, ciphertext, shape)).toEqual(disclosure);
    expect(hashChain4(ciphertext)).toEqual(bytes<Bytes32>(vector.disclosure_hash, 32));
  });

  it("rejects nonzero slot padding", () => {
    for (const index of [33, 62 + 74, 62 + 3 * 93 + 98]) {
      const corrupted = plaintext.slice();
      corrupted[index] = 1;
      expect(() => decodeAnonymousAuditDisclosure(corrupted, shape)).toThrow(RangeError);
    }
  });
});
