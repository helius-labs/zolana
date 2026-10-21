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
import { hashChain4, rightAlign } from "../src/transaction/internal.js";

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
  const outputsAt = 62 + 93 * vector.n_in;
  const length = outputsAt + 155 * vector.n_out;
  const plaintext = bytes<Uint8Array>(vector.plaintext, length);
  const disclosure = decodeAnonymousAuditDisclosure(plaintext, shape);
  const ciphertext = fields(vector.ciphertext);

  it("reads five chunks per output, a ring note's address or an exit's opening", () => {
    expect(auditDisclosureLength(shape)).toBe(vector.fields.length);
    expect(disclosure.inputs).toHaveLength(vector.n_in);
    expect(disclosure.outputs.map((output) => output.kind)).toEqual([
      "ring",
      "padding",
      "exit",
      "ring",
    ]);
    expect(disclosure.outputs.map(isDummyAnonymousOutput)).toEqual([false, true, false, false]);
    const [ring, , exit] = disclosure.outputs;
    if (ring?.kind !== "ring" || exit?.kind !== "exit") throw new Error("vector slot kinds");
    expect(ring.identityTag).toBe(0x53);
    expect(ring.nullifierPublicKey).toEqual(
      bytes<Bytes32>("06abb007f62900df5b600765dcc662923fd1e683e2161e45f2a53b6960fa6cf5", 32),
    );
    expect(ring.viewingPublicKey[0]).toBe(4);
    expect(exit.identityTag).toBe(0x53);
    expect(exit.amount).toBe(100n);
    expect(exit.blinding).toEqual(rightAlign(Uint8Array.of(62)));
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

  it("rejects nonzero slot padding, an unknown output kind, a foreign owner tag and a non-canonical exit field", () => {
    const [ring, padding, exit] = [outputsAt, outputsAt + 155, outputsAt + 310];
    for (const [index, value] of [
      [33, 1],
      [62 + 74, 1],
      [ring + 99, 1],
      [padding + 70, 1],
      [exit + 138, 1],
      [exit + 106, 0xff],
      [ring, 3],
      [exit + 1, 0x50],
    ] as const) {
      const corrupted = plaintext.slice();
      corrupted[index] = value;
      expect(() => decodeAnonymousAuditDisclosure(corrupted, shape)).toThrow(RangeError);
    }
  });
});
