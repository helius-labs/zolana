import { hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { describe, expect, it } from "vitest";
import { address, type Signature } from "@solana/kit";

import { poseidon } from "../src/keypair/poseidon.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { inputTreeSlots, treeIdField, treeSlotsHashChain } from "../src/interface/tree-slot.js";
import { addressBytes } from "../src/interface/internal.js";
import { UTXO_DOMAIN } from "../src/interface/program.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  auditSharedSecret,
  AUDITOR_MESSAGE_LENGTH,
  auditorMessageData,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  parseAuditorMessage,
  type AuditOutputOpening,
} from "../src/keypair/audit.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import {
  encodeSpendRecord,
  encodeSpendCounters,
  spendCountersCommitment,
  memberOfIdentity,
  spendRecordMessageTag,
} from "../src/ring/policy.js";
import { AssetRegistry, SOL_ASSET_ID, SOL_MINT } from "../src/transaction/asset.js";
import { commitmentPoseidon, rightAlign, ZERO_32 } from "../src/transaction/internal.js";
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
const PUBLIC_INPUT_HASH = hex("25266a07f9480618e9ab495065e3d2a4530ab8e2cefe44d6b5e7324466bb0093");
const ZERO_DISCLOSURE = Array.from({ length: 36 }, () => new Uint8Array(32) as Bytes32);

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
      disclosure: ZERO_DISCLOSURE,
    };
    expect(decryptTransactionViewingSecret(ViewingKey.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes the complete audit message", () => {
    const auditor = ViewingKey.generate();
    const encrypted = encryptTransactionViewingSecret(TX_SK, auditor.publicKey());
    expect(decryptTransactionViewingSecret(auditor, encrypted.message)).toEqual(TX_SK);
    const data = auditorMessageData(encrypted.message, auditor.publicKey());
    expect(data.viewTag).toEqual(auditor.publicKey().x());
    expect(data.data).toHaveLength(AUDITOR_MESSAGE_LENGTH);
    const parsed = parseAuditorMessage(data.data);
    expect(parsed.ciphertext).toEqual(encrypted.message.ciphertext);
    expect(parsed.ephemeralPublicKey.toBytes()).toEqual(
      encrypted.message.ephemeralPublicKey.toBytes(),
    );
  });

  it("hashes the audit statement like Rust `CustomRingBasePublicInput::hash`", () => {
    expect(
      Buffer.from(
        auditPublicInputHash({
          privateTxHash: PRIVATE_TX_HASH,
          txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
          auditorPublicKey: P256PublicKey.fromBytes(AUDITOR_PK),
          message: {
            ephemeralPublicKey: P256PublicKey.fromBytes(EPH_PK),
            ciphertext: CIPHERTEXT,
            disclosure: ZERO_DISCLOSURE,
          },
          outputHashes: [new Uint8Array(32) as Bytes32],
          salt: new Uint8Array(16) as Bytes16,
        }),
      ).toString("hex"),
    ).toBe(Buffer.from(PUBLIC_INPUT_HASH).toString("hex"));
  });

  it("extends the audit chain like Go `TestNonzeroRevocationTailVector`", () => {
    const filled = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
    const field = (value: bigint): Bytes32 => bigIntToBytes(value, 32) as Bytes32;
    const revocationTargets = Array.from({ length: 10 }, () => new Uint8Array(32) as Bytes32);
    revocationTargets[0] = field(0x42n);
    revocationTargets[1] = filled(0x11);
    // Fact 1 reads slot 2, fact 0 slot 0.
    const revocationTreeIndexes = [0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
    const tail = (treeSlotsChain: Bytes32): Uint8Array =>
      [
        filled(0x2a),
        treeSlotsChain,
        treeIdField(9),
        filled(8),
        filled(10),
        field(3n),
        field(1n),
        field(1n),
        filled(0x0b),
        field(2n << 3n),
        ...revocationTargets,
      ].reduce((chain, element) => poseidon([chain, element]), PUBLIC_INPUT_HASH);
    expect(Buffer.from(tail(filled(6))).toString("hex")).toBe(
      "0fea02bf7a8cfb1a2b99d9d69f90008e278e9d6fb56e94a253fafba9880fe31e",
    );
    const treeSlots = [
      { id: 9, utxoRoot: filled(6), nullifierRoot: filled(7) },
      { id: 1, utxoRoot: filled(4), nullifierRoot: filled(5) },
      { id: 2, utxoRoot: filled(2), nullifierRoot: filled(3) },
    ];
    const input = {
      privateTxHash: PRIVATE_TX_HASH,
      txViewingPublicKey: P256PublicKey.fromBytes(TX_PK),
      auditorPublicKey: P256PublicKey.fromBytes(AUDITOR_PK),
      message: {
        ephemeralPublicKey: P256PublicKey.fromBytes(EPH_PK),
        ciphertext: CIPHERTEXT,
        disclosure: ZERO_DISCLOSURE,
      },
      outputHashes: [new Uint8Array(32) as Bytes32],
      salt: new Uint8Array(16) as Bytes16,
      policyHash: filled(0x2a),
      treeSlots,
      addressTreeId: 9,
      ringId: filled(8),
      namespaceOwnerHash: filled(10),
      windowIndex: 3n,
      approvalRequired: true,
      keyRegistryRoot: filled(0x0b),
      revocationTargets,
      revocationTreeIndexes,
    };
    expect(policyPublicInputHash(input)).toEqual(
      tail(treeSlotsHashChain(inputTreeSlots(treeSlots))),
    );
    expect(() =>
      policyPublicInputHash({ ...input, revocationTreeIndexes: [8, 0, 0, 0, 0, 0, 0, 0, 0, 0] }),
    ).toThrow(RangeError);
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
    input: Readonly<{
      amount: bigint;
      committedAmount?: bigint;
      recordMessage: Uint8Array | undefined;
    }>,
  ): IndexedShieldedTransaction {
    const salt = new Uint8Array(16) as Bytes16;
    const opening = auditOpening(input.committedAmount ?? input.amount, record.blinding);
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey(), {
      salt,
      outputs: [opening],
    });
    const message = auditorMessageData(encrypted.message, auditor.publicKey());
    return {
      slot: 1n,
      txSignature: "sig" as Signature,
      txViewingPublicKey: tx.publicKey(),
      salt,
      outputSlots: [
        {
          viewTag,
          outputContext: {
            hash: auditOpeningHash(opening),
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
              salt,
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
            ...tx.encryptSlot(tx.publicKey(), encodeSpendCounters(counters), salt, 0xffff_ffff),
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

  it("rejects recipient plaintext that disagrees with the proof-bound output", () => {
    expect(() =>
      audit(transaction({ amount: 5n, committedAmount: 0n, recordMessage: undefined })),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
  });
});

function auditOpening(amount: bigint, blinding: Bytes32): AuditOutputOpening {
  return Object.freeze({
    domain: rightAlign(Uint8Array.of(UTXO_DOMAIN)),
    treeId: treeIdField(0),
    ownerHash: ZERO_32,
    asset: hashBytes(addressBytes(SOL_MINT)) as Bytes32,
    amount: rightAlign(bigIntToBytes(amount, 8)),
    blinding,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    ringProgramId: ZERO_32,
  });
}

function auditOpeningHash(opening: AuditOutputOpening): Bytes32 {
  return commitmentPoseidon([
    opening.domain,
    opening.treeId,
    opening.asset,
    opening.amount,
    opening.dataHash,
    commitmentPoseidon([opening.ringDataHash, opening.ringProgramId]),
    commitmentPoseidon([opening.ownerHash, opening.blinding]),
  ]);
}
