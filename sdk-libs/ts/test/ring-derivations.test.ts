import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import secrets from "../../../test-vectors/ring-secrets.json" with { type: "json" };
import tags from "../../../test-vectors/ring-tags.json" with { type: "json" };
import { BN254_SCALAR_ORDER, hashBytes, solanaOwnerIdentity } from "../src/hasher/index.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import {
  DOMAIN_PRIVATE_TX_BLINDING_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
  DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1,
} from "../src/keypair/derivation.js";
import {
  outputBlindingSeed,
  privateTxBlinding,
  ringOutputBlinding,
  transactOutputBlinding,
} from "../src/keypair/transact/index.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { createProofOutput, outputSlotBlinding } from "../src/transaction/utxo.js";
import { RingDomain, depositBlinding } from "../src/keypair/ring-domain.js";
import {
  BODY_LEN,
  EPOCH_SLOTS,
  J_INBOX,
  J_PAIR,
  K_PAIR_EPOCHS,
  TAG_LEN,
  anonymousRingSecret,
  confidentialRingSecret,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  packedSlotSecret,
  pairKey,
  pairTag,
  ringTag,
  senderCommitment,
  tagEpoch,
  tagIndex,
} from "../src/keypair/ring-stream.js";

/** The epoch ring-secrets.json tags its anonymous outputs in. */
const SECRETS_TAG_EPOCH = 6734n;

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function ascii(tag: string): number {
  return Buffer.from(tag, "ascii").readUInt32BE(0);
}

function ringId(): Bytes32 {
  return hashBytes(bytes<Bytes32>(tags.ring_program_id, 32)) as Bytes32;
}

describe("ring domains", () => {
  it("spells every domain from its ASCII tag, no two alike", () => {
    expect(RingDomain).toEqual({
      auditStatement: ascii("CRAU"),
      packedSlotSecret: ascii("CRAS"),
      deliveredSlotSecret: ascii("CRDS"),
      confidentialRingSecret: ascii("CRRC"),
      anonymousRingSecret: ascii("CRRA"),
      inboxKey: ascii("CRIK"),
      inboxTag: ascii("CRIT"),
      pairKey: ascii("CRPK"),
      pairTag: ascii("CRPT"),
      senderCommitment: ascii("CRSC"),
      disclosurePad: ascii("CROD"),
      policyStatement: ascii("CRPO"),
      policyTable: ascii("CRTB"),
      queueWrite: ascii("CRQW"),
      applyRecords: ascii("CRAP"),
      registerKey: ascii("CRRG"),
      depositBlinding: ascii("CRDB"),
    });
    expect(DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1).toBe(ascii("TXRB"));
    const values = [
      ...Object.values(RingDomain),
      DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1,
      DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
      DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
      DOMAIN_PRIVATE_TX_BLINDING_V1,
    ];
    expect(new Set(values).size).toBe(values.length);
  });
});

describe("ring-tags.json", () => {
  it("pins the stream constants", () => {
    expect({
      epoch_slots: Number(EPOCH_SLOTS),
      j_inbox: J_INBOX,
      j_pair: J_PAIR,
      k_pair_epochs: Number(K_PAIR_EPOCHS),
      tag_len: TAG_LEN,
      body_len: BODY_LEN,
    }).toEqual(tags.constants);
  });

  it("derives the inbox and pair streams", () => {
    expect(hex(ringId())).toBe(tags.ring_id);
    const inbox = inboxKey(
      ringId(),
      X25519PublicKey.fromBytes(bytes<Bytes33>(tags.viewing_pk, 33)),
    );
    expect(hex(inbox)).toBe(tags.inbox_key);
    for (const entry of tags.inbox_tags)
      expect(hex(inboxTag(inbox, BigInt(entry.epoch), tagIndex(entry.index)))).toBe(entry.tag);
    const pair = pairKey(bytes<Bytes32>(tags.first_contact_secret, 32));
    expect(hex(pair)).toBe(tags.pair_key);
    for (const entry of tags.pair_tags)
      expect(hex(pairTag(pair, BigInt(entry.epoch), tagIndex(entry.index)))).toBe(entry.tag);
  });

  it("takes low128 of canonical fields and maps slots to epochs", () => {
    for (const entry of tags.low128)
      expect(hex(ringTag(bytes<Bytes32>(entry.value, 32)))).toBe(entry.tag);
    for (const entry of tags.epochs) expect(tagEpoch(BigInt(entry.slot))).toBe(BigInt(entry.epoch));
  });

  it("refuses an index past the stream and a field at the modulus", () => {
    expect(() => tagIndex(J_INBOX)).toThrow("KEYPAIR_TAG_INDEX_OUT_OF_RANGE");
    expect(() => ringTag(bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32)).toThrow(
      "KEYPAIR_NONCANONICAL_FIELD",
    );
  });
});

describe("ring-secrets.json", () => {
  const txSecret = bytes<Bytes32>(secrets.tx_viewing_secret, 32);
  const txViewingKey = X25519PublicKey.fromBytes(bytes<Bytes33>(secrets.tx_viewing_pk, 33));
  const recipientViewingKey = X25519PublicKey.fromBytes(
    bytes<Bytes33>(secrets.recipient_viewing_pk, 33),
  );
  const salt = bytes<Bytes16>(secrets.salt, 16);
  const firstNullifier = bytes<Bytes32>(secrets.first_nullifier, 32);

  it("reaches one agreement from the sender and the recipient", () => {
    const sender = X25519Keypair.fromBytes(txSecret);
    const recipient = X25519Keypair.fromBytes(bytes<Bytes32>(secrets.recipient_viewing_secret, 32));
    try {
      expect(sender.publicKey().equals(txViewingKey)).toBe(true);
      expect(recipient.publicKey().equals(recipientViewingKey)).toBe(true);
      expect(hex(sender.ecdh(recipientViewingKey))).toBe(secrets.agreement);
      expect(hex(recipient.ecdh(txViewingKey))).toBe(secrets.agreement);
    } finally {
      sender.destroy();
      recipient.destroy();
    }
  });

  it("derives every slot secret, ring secret and output blinding", () => {
    const seed = outputBlindingSeed(firstNullifier, bytes<Bytes32>(secrets.blinding_seed, 32));
    expect(hex(seed)).toBe(secrets.output_blinding_seed);
    const inbox = inboxKey(ringId(), recipientViewingKey);
    for (const output of secrets.outputs) {
      const outputIndex = output.output_index;
      const packed = packedSlotSecret({
        txViewingSecret: txSecret,
        salt,
        outputIndex,
        firstNullifier,
      });
      expect(hex(packed)).toBe(output.packed_slot_secret);
      expect(hex(confidentialRingSecret(packed))).toBe(output.packed_ring_secret);
      const delivered = deliveredSlotSecret({
        agreement: bytes<Bytes32>(secrets.agreement, 32),
        txViewingKey,
        recipientViewingKey,
        salt,
        outputIndex,
        firstNullifier,
      });
      expect(hex(delivered)).toBe(output.delivered_slot_secret);
      expect(hex(confidentialRingSecret(delivered))).toBe(output.confidential_ring_secret);
      const tag = inboxTag(inbox, SECRETS_TAG_EPOCH, tagIndex(outputIndex));
      expect(hex(tag)).toBe(output.tag);
      const anonymous = anonymousRingSecret(delivered, bytes<Bytes16>(output.tag, 16));
      expect(hex(anonymous)).toBe(output.anonymous_ring_secret);
      const blinding = (ringSecret: Bytes32): string =>
        hex(ringOutputBlinding({ firstNullifier, ringSecret, outputIndex }));
      expect(blinding(confidentialRingSecret(packed))).toBe(output.packed_blinding);
      expect(blinding(confidentialRingSecret(delivered))).toBe(output.confidential_blinding);
      expect(blinding(anonymous)).toBe(output.anonymous_blinding);
      expect(hex(transactOutputBlinding(firstNullifier, seed, outputIndex))).toBe(
        output.exit_blinding,
      );
    }
    expect(hex(depositBlinding(bytes<Bytes32>(secrets.deposit_blinding_secret, 32)))).toBe(
      secrets.deposit_blinding,
    );
  });

  it("blinds a ring output from its ring secret and every other slot from the seed", () => {
    const outputBlindingSeed = bytes<Bytes32>(secrets.output_blinding_seed, 32);
    const [output] = secrets.outputs;
    if (output === undefined) throw new Error("ring-secrets.json has no output");
    const slotIndex = output.output_index;
    const ringSecret = anonymousRingSecret(
      bytes<Bytes32>(output.delivered_slot_secret, 32),
      bytes<Bytes16>(output.tag, 16),
    );
    const ringProgramId = address("Ring111111111111111111111111111111111111111");
    const ownerAddress = ShieldedKeypair.generate().shieldedAddress();
    const slot = (fields: Parameters<typeof createProofOutput>[0]) =>
      outputSlotBlinding({
        output: createProofOutput(fields),
        firstNullifier,
        outputBlindingSeed,
        slotIndex,
      });
    const asset = address("So11111111111111111111111111111111111111112");
    const ring = { ownerAddress, asset, amount: 1n, ringProgramId, ringSecret };
    expect(hex(slot(ring))).toBe(output.anonymous_blinding);
    expect(hex(slot({ ownerAddress, asset, amount: 1n }))).toBe(output.exit_blinding);
    expect(hex(slot({ asset, amount: 0n, ringProgramId }))).toBe(output.exit_blinding);
    const { ringSecret: _, ...missing } = ring;
    expect(() => slot(missing)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MISSING_RING_SECRET" }),
    );
    expect(() => slot({ ownerAddress, asset, amount: 1n, ringSecret })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNEXPECTED_RING_SECRET" }),
    );
  });

  it("commits the hidden sender of the same transaction", () => {
    const senderPkHash = solanaOwnerIdentity(bytes<Bytes32>(secrets.sender_key, 32)) as Bytes32;
    expect(hex(senderPkHash)).toBe(secrets.sender_pk_hash);
    const blinding = privateTxBlinding(firstNullifier, bytes<Bytes32>(secrets.blinding_seed, 32));
    expect(hex(blinding)).toBe(secrets.private_tx_blinding);
    expect(hex(senderCommitment({ senderPkHash, privateTxBlinding: blinding }))).toBe(
      secrets.sender_commitment,
    );
  });
});
