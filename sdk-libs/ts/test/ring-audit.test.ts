import { initializePoseidon } from "../src/hasher/index.js";
import { describe, expect, it } from "vitest";
import { address, type Signature } from "@solana/kit";

import { poseidon } from "../src/keypair/poseidon.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { treeIdField } from "../src/interface/tree-slot.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  auditSharedSecret,
  auditorMessageData,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  parseAuditorMessage,
} from "../src/keypair/audit.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import {
  encodeSpendRecord,
  encodeSpendCounters,
  spendCountersCommitment,
  memberOfIdentity,
  spendRecordMessageTag,
} from "../src/ring/policy.js";
import { AssetRegistry, SOL_ASSET_ID } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encryptConfidential,
} from "../src/transaction/serialization/codecs.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

// Vectors from custom-rings/sdk/tests/go_vectors.rs.
const TX_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e") as Bytes32;
const EPH_SK = hex("01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d") as Bytes32;
const AUDITOR_SK = hex(
  "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c",
) as Bytes32;
const EPH_PK = hex("038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a133c") as Bytes33;
const AUDITOR_PK = hex(
  "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec",
) as Bytes33;
const DH = hex("0adc4a9b4fc9112518acab2c346559372e9a5c2a9d8b93fb1b7650ea1edd4823") as Bytes32;
const SHARED_SECRET = hex(
  "009926f6e6fefd31699816632ef553197a3695424ddd9589e3d074518c40d605",
) as Bytes32;
const CIPHERTEXT = hex(
  "6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b",
) as Bytes32;

// Fixture from custom-rings/program/src/instructions/transact.rs.
const TX_PK = hex("0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5") as Bytes33;
const PRIVATE_TX_HASH = hex(
  "0000000000000000000000000000000000000000000000000000000000abcdef",
) as Bytes32;
const PUBLIC_INPUT_HASH = hex("18bf7563a64675c110ae7d408b973c98005afac6d06b8ae177f4435d7e6e020b");

describe("ring audit encryption", () => {
  it("matches the Go vectors", () => {
    const ephemeral = ViewingKey.fromBytes(EPH_SK);
    const auditor = P256PublicKey.fromBytes(AUDITOR_PK);
    expect(ephemeral.publicKey().toBytes()).toEqual(EPH_PK);
    expect(ViewingKey.fromBytes(AUDITOR_SK).publicKey().toBytes()).toEqual(AUDITOR_PK);
    const dh = ephemeral.ecdh(auditor);
    expect(dh).toEqual(DH);
    expect(auditSharedSecret(dh, ephemeral.publicKey(), auditor)).toEqual(SHARED_SECRET);
    const message = {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext: CIPHERTEXT,
    };
    expect(decryptTransactionViewingSecret(ViewingKey.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes a 65-byte message", () => {
    const auditor = ViewingKey.generate();
    const encrypted = encryptTransactionViewingSecret(TX_SK, auditor.publicKey());
    expect(decryptTransactionViewingSecret(auditor, encrypted.message)).toEqual(TX_SK);
    const data = auditorMessageData(encrypted.message, auditor.publicKey());
    expect(data.viewTag).toEqual(auditor.publicKey().x());
    expect(data.data).toHaveLength(65);
    const parsed = parseAuditorMessage(data.data);
    expect(parsed.ciphertext).toEqual(encrypted.message.ciphertext);
    expect(parsed.ephemeralPublicKey.toBytes()).toEqual(
      encrypted.message.ephemeralPublicKey.toBytes(),
    );
  });

  it("hashes the audit statement like Rust `CustomRingBasePublicInput::hash`", () => {
    expect(
      auditPublicInputHash({
        privateTxHash: PRIVATE_TX_HASH,
        txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
        auditorPublicKey: P256PublicKey.fromBytes(AUDITOR_PK),
        message: {
          ephemeralPublicKey: P256PublicKey.fromBytes(EPH_PK),
          ciphertext: CIPHERTEXT,
        },
      }),
    ).toEqual(PUBLIC_INPUT_HASH);
  });

  // The pinned Go fixture is the eight-element prefix and the policy tail folds onto it.
  it("extends the audit chain like Rust `the_public_input_chain_extends_the_audit_chain`", () => {
    const policyHash = new Uint8Array(32).fill(0x2a) as Bytes32;
    const stateRoot = new Uint8Array(32).fill(6) as Bytes32;
    const nullifierRoot = new Uint8Array(32).fill(7) as Bytes32;
    const ringId = new Uint8Array(32).fill(8) as Bytes32;
    const namespaceOwnerHash = new Uint8Array(32).fill(10) as Bytes32;
    const windowIndex = new Uint8Array(32) as Bytes32;
    windowIndex[31] = 3;
    const approval = new Uint8Array(32) as Bytes32;
    approval[31] = 1;
    const extended = [
      policyHash,
      stateRoot,
      nullifierRoot,
      treeIdField(9),
      ringId,
      namespaceOwnerHash,
      windowIndex,
      approval,
    ].reduce((chain, element) => poseidon([chain, element]), PUBLIC_INPUT_HASH);
    expect(
      policyPublicInputHash({
        privateTxHash: PRIVATE_TX_HASH,
        txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
        auditorPublicKey: P256PublicKey.fromBytes(AUDITOR_PK),
        message: {
          ephemeralPublicKey: P256PublicKey.fromBytes(EPH_PK),
          ciphertext: CIPHERTEXT,
        },
        policyHash,
        entriesTreeId: 9,
        stateRoot,
        nullifierRoot,
        ringId,
        namespaceOwnerHash,
        windowIndex: 3n,
        approvalRequired: true,
      }),
    ).toEqual(extended);
  });

  it("decompresses the auditor key to the 65-byte point the circuit witnesses", () => {
    const auditor = P256PublicKey.fromBytes(AUDITOR_PK);
    const uncompressed = auditor.toUncompressed();
    expect(uncompressed).toHaveLength(65);
    expect(uncompressed[0]).toBe(4);
    expect(uncompressed.subarray(1, 33)).toEqual(auditor.x());
    expect(P256PublicKey.fromUncompressed(uncompressed).equals(auditor)).toBe(true);
  });
});

await initializePoseidon();

describe("ring audit spend records", () => {
  const auditor = ViewingKey.generate();
  const tx = ViewingKey.generate();
  const viewTag = new Uint8Array(32).fill(0x77) as Bytes32;
  const member = memberOfIdentity(new Uint8Array(32).fill(0x11) as Bytes32);
  const counters = {
    salt: new Uint8Array(32) as Bytes32,
    assets: Array.from({ length: 8 }, () => new Uint8Array(32) as Bytes32),
    spent: Array<bigint>(8).fill(0n),
  };
  const record = {
    member,
    version: 3n,
    window: 4n,
    countersCommitment: spendCountersCommitment(counters),
    blinding: new Uint8Array(32).fill(6) as Bytes32,
  };

  function transaction(
    input: Readonly<{ amount: bigint; recordMessage: Uint8Array | undefined }>,
  ): IndexedShieldedTransaction {
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey());
    const message = auditorMessageData(encrypted.message, auditor.publicKey());
    return {
      slot: 1n,
      txSignature: "sig" as Signature,
      txViewingPublicKey: tx.publicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputSlots: [
        {
          viewTag,
          outputContext: {
            hash: new Uint8Array(32) as Bytes32,
            tree: address("11111111111111111111111111111111"),
            leafIndex: 0n,
          },
          payload: encodeOutputData(
            EncryptedScheme.confidential,
            encryptConfidential(
              tx,
              tx.publicKey(),
              {
                assetId: SOL_ASSET_ID,
                amount: input.amount,
                blinding: record.blinding,
                data: new Data(),
              },
              new Uint8Array(16) as Bytes16,
              0,
            ),
            "encrypted",
          ),
        },
      ],
      messages: [
        ...(input.recordMessage === undefined
          ? []
          : [{ viewTag: spendRecordMessageTag(viewTag), data: input.recordMessage }]),
        {
          viewTag,
          data: new Uint8Array([
            ...tx.publicKey().toBytes(),
            ...tx.encryptSlot(
              tx.publicKey(),
              encodeSpendCounters(counters),
              new Uint8Array(16) as Bytes16,
              0xffff_ffff,
            ),
          ]),
        },
        message,
      ],
      nullifiers: [],
      proofless: false,
    };
  }

  const audit = (transaction: IndexedShieldedTransaction) =>
    auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() });

  it("reports a record whose first member byte is not a scheme byte", () => {
    const audited = audit(transaction({ amount: 0n, recordMessage: encodeSpendRecord(record) }));
    expect(audited.spendRecords).toHaveLength(1);
    expect(audited.spendRecords[0]?.record.member).toEqual(member);
    expect(audited.undecryptableSlots).toHaveLength(0);
    expect(audited.invalidSpendRecordSlots).toHaveLength(0);
  });

  it("rejects missing, duplicate, truncated, foreign recipient and corrupted counters", () => {
    const valid = transaction({ amount: 0n, recordMessage: encodeSpendRecord(record) });
    const countersMessage = valid.messages[1];
    if (countersMessage === undefined) throw new Error("missing counter fixture");
    for (const messages of [
      valid.messages.filter((_, index) => index !== 1),
      [countersMessage, ...valid.messages],
      valid.messages.map((message, index) =>
        index === 1 ? { ...message, data: message.data.slice(1) } : message,
      ),
      valid.messages.map((message, index) =>
        index === 1
          ? {
              ...message,
              data: new Uint8Array([
                ...auditor.publicKey().toBytes(),
                ...message.data.subarray(33),
              ]),
            }
          : message,
      ),
      valid.messages.map((message, index) => {
        if (index !== 1) return message;
        const data = message.data.slice();
        data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 1;
        return { ...message, data };
      }),
    ])
      expect(() => audit({ ...valid, messages })).toThrow("RING_SPEND_COUNTERS_UNKNOWN");
  });

  it("reports a crafted record message and still counts the slot's money", () => {
    const malformed = audit(transaction({ amount: 5n, recordMessage: new Uint8Array(3) }));
    expect(malformed.invalidSpendRecordSlots).toEqual([0]);
    expect(malformed.spendRecords).toHaveLength(0);
    expect(malformed.outputs.map((output) => output.amount)).toEqual([5n]);
    const wrongCarrier = audit(
      transaction({ amount: 5n, recordMessage: encodeSpendRecord(record) }),
    );
    expect(wrongCarrier.invalidSpendRecordSlots).toEqual([0]);
    expect(wrongCarrier.spendRecords).toHaveLength(0);
    expect(wrongCarrier.outputs.map((output) => output.amount)).toEqual([5n]);
  });
});
