import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/anonymous_recipient_encryption.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import { encodeBase58 } from "../src/interface/internal.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyIndexedInputs,
  policyPublicInputHash,
  recipientStreamSecret,
  type CustomRingBasePublicInput,
} from "../src/keypair/audit.js";
import { hashChain } from "../src/transaction/internal.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import { TransactionError } from "../src/transaction/error.js";
import { hashChain4 } from "../src/transaction/internal.js";
import {
  RING_ANONYMOUS_BODY_LENGTH,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  decodeRingAnonymous,
  encodeRingAnonymous,
  ringAnonymousBodyHash,
} from "../src/transaction/serialization/codecs.js";

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
describe("shared anonymous recipient encryption vector", () => {
  const tx = ViewingKey.fromBytes(bytes<Bytes32>(vector.tx_sk, 32));
  const recipient = ViewingKey.fromBytes(bytes<Bytes32>(vector.recipient_viewing_sk, 32));
  const txPublicKey = X25519PublicKey.fromBytes(bytes<Bytes33>(vector.tx_pk, 33));
  const recipientPublicKey = X25519PublicKey.fromBytes(
    bytes<Bytes33>(vector.recipient_viewing_pk, 33),
  );
  const salt = bytes<Bytes16>(vector.salt, 16);
  const stream = {
    txViewingPublicKey: txPublicKey,
    recipientViewingPublicKey: recipientPublicKey,
    salt,
    slotIndex: vector.slot,
  };
  const plaintext = bytes<Uint8Array>(vector.plaintext, RING_ANONYMOUS_PLAINTEXT_LENGTH);
  const ciphertext = bytes<Uint8Array>(vector.ciphertext, RING_ANONYMOUS_PLAINTEXT_LENGTH);
  const opening = {
    assetAddress: encodeBase58(bytes<Bytes32>(vector.asset_address, 32)),
    amount: BigInt(vector.amount),
    blinding: bytes<Bytes32>(vector.blinding, 32),
    pairU: bytes<Bytes32>(vector.pair_u, 32),
  };

  it("derives the clamped keys, the shared point and the slot secret", () => {
    expect(tx.publicKey().equals(txPublicKey)).toBe(true);
    expect(recipient.publicKey().equals(recipientPublicKey)).toBe(true);
    const dh = bytes<Bytes32>(vector.dh, 32);
    expect(
      X25519Keypair.fromBytes(bytes<Bytes32>(vector.tx_sk, 32)).ecdh(recipientPublicKey),
    ).toEqual(dh);
    expect(recipient.ecdh(txPublicKey)).toEqual(dh);
    expect(recipientStreamSecret(dh, stream)).toEqual(bytes<Bytes32>(vector.secret, 32));
    expect(recipientStreamSecret(dh, { ...stream, slotIndex: vector.slot + 1 })).not.toEqual(
      bytes<Bytes32>(vector.secret, 32),
    );
  });

  it("lays the opening out as asset || amount || blinding || pair u", () => {
    expect(encodeRingAnonymous(opening)).toEqual(plaintext);
    expect(decodeRingAnonymous(plaintext)).toEqual(opening);
  });

  it("refuses a noncanonical blinding alias and any other length", () => {
    const alias = plaintext.slice();
    alias.fill(0xff, 40, 72);
    expect(() => decodeRingAnonymous(alias)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INVALID_BLINDING" }),
    );
    expect(() => decodeRingAnonymous(plaintext.subarray(1))).toThrow(TransactionError);
    expect(() =>
      encodeRingAnonymous({ ...opening, blinding: alias.slice(40, 72) as Bytes32 }),
    ).toThrow(TransactionError);
  });

  it("seals from the transaction key and opens from the recipient key", () => {
    expect(tx.sealAnonymousOutput(recipientPublicKey, plaintext, salt, vector.slot)).toEqual(
      ciphertext,
    );
    expect(recipient.openAnonymousOutput(ciphertext, txPublicKey, salt, vector.slot)).toEqual(
      plaintext,
    );
    expect(
      recipient.openAnonymousOutput(ciphertext, txPublicKey, salt, vector.slot + 1),
    ).not.toEqual(plaintext);
  });

  it("hashes the 105-byte published body", () => {
    const body = bytes<Uint8Array>(vector.body, RING_ANONYMOUS_BODY_LENGTH);
    expect(body[0]).toBe(9);
    expect(body.subarray(1)).toEqual(ciphertext);
    expect(ringAnonymousBodyHash(ciphertext)).toEqual(bytes<Bytes32>(vector.body_hash, 32));
  });

  function baseInput(): CustomRingBasePublicInput {
    const statement = vector.statement;
    return {
      privateTxHash: bytes<Bytes32>(statement.private_tx_hash, 32),
      txViewingPublicKey: X25519PublicKey.fromBytes(bytes<Bytes33>(statement.tx_viewing_pk, 33)),
      auditorPublicKey: X25519PublicKey.fromBytes(bytes<Bytes33>(statement.auditor_pk, 33)),
      message: {
        ephemeralPublicKey: X25519PublicKey.fromBytes(bytes<Bytes33>(statement.eph_pk, 33)),
        ciphertext: bytes<Bytes32>(statement.audit_ciphertext, 32),
        disclosure: fields(statement.disclosure),
      },
      outputHashes: fields(statement.output_hashes),
      outputBodyHashes: fields(statement.output_body_hashes),
      salt: bytes<Bytes16>(statement.salt, 16),
      anonymous: statement.anonymous,
    };
  }

  it("extends the base statement into the twenty-two-element policy statement", () => {
    const policy = vector.policy_statement;
    const input = {
      ...baseInput(),
      policyHash: bytes<Bytes32>(policy.policy_hash, 32),
      treeSlots: policy.tree_slots.map((slot) => ({
        id: slot.id,
        utxoRoot: bytes<Bytes32>(slot.utxo_root, 32),
        nullifierRoot: bytes<Bytes32>(slot.nullifier_root, 32),
      })),
      addressTreeId: policy.address_tree_id,
      ringId: bytes<Bytes32>(policy.ring_id, 32),
      namespaceOwnerHash: bytes<Bytes32>(policy.namespace_owner_hash, 32),
      approvalRequired: policy.approval_required,
      keyEscrow: policy.key_escrow,
      memberRegistryRoot: bytes<Bytes32>(policy.member_registry_root, 32),
      foreignRoot: bytes<Bytes32>(policy.foreign_root, 32),
    };
    const elements = fields(policy.elements);
    expect(elements).toHaveLength(22);
    expect(elements.slice(0, 13)).toEqual(fields(vector.statement.elements));
    expect(policyPublicInputHash(input)).toEqual(bytes<Bytes32>(policy.public_input_hash, 32));
    const indexed = policyIndexedInputs(input);
    expect(indexed[0]).toEqual(hashChain(elements.slice(0, 14)));
    expect(indexed.slice(1)).toEqual(elements.slice(15));
  });

  it("chains the body hashes into the thirteen-element base statement", () => {
    const statement = vector.statement;
    const outputBodyHashes = fields(statement.output_body_hashes);
    const padding = bytes<Uint8Array>(statement.padding_body, RING_ANONYMOUS_BODY_LENGTH);
    expect(outputBodyHashes).toEqual([
      bytes<Bytes32>(vector.body_hash, 32),
      ringAnonymousBodyHash(padding.subarray(1)),
    ]);
    const input = baseInput();
    const elements = fields(statement.elements);
    expect(elements).toHaveLength(13);
    expect(elements[8]).toEqual(hashChain4(outputBodyHashes));
    expect(auditPublicInputHash(input)).toEqual(bytes<Bytes32>(statement.public_input_hash, 32));
    const { outputBodyHashes: _, ...withoutBodies } = input;
    expect(auditPublicInputHash(withoutBodies)).not.toEqual(
      bytes<Bytes32>(statement.public_input_hash, 32),
    );
    expect(() =>
      auditPublicInputHash({ ...input, outputBodyHashes: [outputBodyHashes[0]!] }),
    ).toThrow(RangeError);
  });
});
