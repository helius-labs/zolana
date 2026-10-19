import { X25519PublicKey, X25519Keypair } from "../src/keypair/x25519.js";
import { SOLANA_OWNER_TAG, hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { describe, expect, it } from "vitest";
import { address, type Signature } from "@solana/kit";

import { poseidon } from "../src/keypair/poseidon.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { inputTreeSlots, treeIdField, treeSlotsHashChain } from "../src/interface/tree-slot.js";
import { addressBytes, encodeBase58 } from "../src/interface/internal.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { UTXO_DOMAIN } from "../src/interface/program.js";
import type { Bytes16, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditPublicInputHash,
  policyPublicInputHash,
  auditSharedSecret,
  AUDITOR_MESSAGE_LENGTH,
  auditDisclosureLength,
  auditorMessageData,
  decodeAnonymousAuditDisclosure,
  decryptTransactionViewingSecret,
  encodeAnonymousAuditDisclosure,
  encryptTransactionViewingSecret,
  openAnonymousAuditDisclosure,
  parseAuditorMessage,
  type AnonymousAuditDisclosure,
  type AnonymousOutputOpening,
  type AuditOutputOpening,
} from "../src/keypair/audit.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import { Utxo } from "../src/transaction/utxo.js";
import { ringAuditReader, transactionsPage } from "./helpers/clients.js";
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
  encodeConfidential,
  encodeOutputData,
  encryptAnonymous,
  encryptConfidential,
} from "../src/transaction/serialization/codecs.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

// Vectors from custom-rings/sdk/tests/go_vectors.rs.
const TX_SK = hex("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e") as Bytes32;
const EPH_SK = hex("01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d") as Bytes32;
const AUDITOR_SK = hex(
  "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c",
) as Bytes32;
const EPH_PK = hex("048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966") as Bytes33;
const AUDITOR_PK = hex(
  "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a",
) as Bytes33;
const DH = hex("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c") as Bytes32;
const SHARED_SECRET = hex(
  "2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f",
) as Bytes32;
const CIPHERTEXT = hex(
  "03417a38002f02b2af3e7b938032a1d317e6350831c55a9d3a91e9520feb2354",
) as Bytes32;

// Shared base vector in custom-rings/sdk/tests/go_vectors.rs.
const TX_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63") as Bytes33;
const PRIVATE_TX_HASH = hex(
  "0000000000000000000000000000000000000000000000000000000000abcdef",
) as Bytes32;
const PUBLIC_INPUT_HASH = hex("1b4e1ba78684f111c74fabe984dcf6b70cd0bd6cbdcaf90a672986ce1a89b0e0");
const ZERO_DISCLOSURE = Array.from({ length: 36 }, () => new Uint8Array(32) as Bytes32);

describe("ring audit encryption", () => {
  it("matches the Go vectors", () => {
    const ephemeral = X25519Keypair.fromBytes(EPH_SK);
    const auditor = X25519PublicKey.fromBytes(AUDITOR_PK);
    expect(ephemeral.publicKey().toBytes()).toEqual(EPH_PK);
    expect(X25519Keypair.fromBytes(AUDITOR_SK).publicKey().toBytes()).toEqual(AUDITOR_PK);
    const dh = ephemeral.ecdh(auditor);
    expect(dh).toEqual(DH);
    expect(auditSharedSecret(dh, ephemeral.publicKey(), auditor)).toEqual(SHARED_SECRET);
    const message = {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext: CIPHERTEXT,
      disclosure: ZERO_DISCLOSURE,
    };
    expect(decryptTransactionViewingSecret(X25519Keypair.fromBytes(AUDITOR_SK), message)).toEqual(
      TX_SK,
    );
  });

  it("round-trips under a fresh ephemeral key and publishes the complete audit message", () => {
    const auditor = X25519Keypair.generate();
    const encrypted = encryptTransactionViewingSecret(TX_SK, auditor.publicKey());
    expect(decryptTransactionViewingSecret(auditor, encrypted.message)).toEqual(TX_SK);
    const data = auditorMessageData(encrypted.message, auditor.publicKey());
    expect(data.viewTag).toEqual(auditor.publicKey().u());
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
          txViewingPublicKey: X25519PublicKey.fromBytes(TX_PK),
          auditorPublicKey: X25519PublicKey.fromBytes(AUDITOR_PK),
          message: {
            ephemeralPublicKey: X25519PublicKey.fromBytes(EPH_PK),
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
      "2aa0c875d2823f551bc4c1f5e98cc18fb0dc6171079af204193067ec124f07e6",
    );
    const treeSlots = [
      { id: 9, utxoRoot: filled(6), nullifierRoot: filled(7) },
      { id: 1, utxoRoot: filled(4), nullifierRoot: filled(5) },
      { id: 2, utxoRoot: filled(2), nullifierRoot: filled(3) },
    ];
    const input = {
      privateTxHash: PRIVATE_TX_HASH,
      txViewingPublicKey: X25519PublicKey.fromBytes(TX_PK),
      auditorPublicKey: X25519PublicKey.fromBytes(AUDITOR_PK),
      message: {
        ephemeralPublicKey: X25519PublicKey.fromBytes(EPH_PK),
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

  it("witnesses the canonical 32-byte X25519 coordinate", () => {
    const auditor = X25519PublicKey.fromBytes(AUDITOR_PK);
    expect(auditor.u()).toHaveLength(32);
    expect(auditor.toBytes()[0]).toBe(4);
    expect(auditor.u()).toEqual(auditor.toBytes().subarray(1));
  });
});

await initializePoseidon();

describe("ring audit spend records", () => {
  const auditor = X25519Keypair.generate();
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

describe("anonymous ring audit", () => {
  const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
  const auditor = X25519Keypair.generate();
  const tx = ViewingKey.generate();
  const member = ShieldedKeypair.generate();
  const source = member.shieldedAddress();
  const salt = new Uint8Array(16).fill(5) as Bytes16;
  const blinding = filled(7, 0) as Bytes32;
  const solAsset = hashBytes(addressBytes(SOL_MINT)) as Bytes32;
  const utxo = new Utxo({
    owner: source.signingPublicKey,
    asset: SOL_MINT,
    amount: 42n,
    blinding,
    ringProgramId: RING,
  });
  const commitment = utxo.hash(source.nullifierPublicKey, 0);
  const recipient: AnonymousOutputOpening = Object.freeze({
    identityTag: SOLANA_OWNER_TAG,
    identityKey: source.confidentialViewTag() as Bytes32,
    viewingPublicKey: source.viewingPublicKey.toBytes(),
    nullifierPublicKey: source.nullifierPublicKey,
    amount: 42n,
    asset: solAsset,
    blinding,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    ringNote: true,
  });
  const dummy: AnonymousOutputOpening = Object.freeze({
    identityTag: 0,
    identityKey: ZERO_32,
    viewingPublicKey: new Uint8Array(33) as Bytes33,
    nullifierPublicKey: ZERO_32,
    amount: 0n,
    asset: ZERO_32,
    blinding: ZERO_32,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    ringNote: false,
  });
  const disclosure: AnonymousAuditDisclosure = Object.freeze({
    sender: filled(3) as Bytes32,
    inputs: [
      { treeId: 4, amount: 9n, asset: solAsset, blinding: filled(6, 0) as Bytes32 },
      { treeId: 0, amount: 0n, asset: ZERO_32, blinding: ZERO_32 },
    ],
    outputs: [recipient, dummy],
  });
  const shape = { anonymous: true, inputs: 2, outputs: 2 };

  function transaction(opening = disclosure): IndexedShieldedTransaction {
    const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), auditor.publicKey(), {
      salt,
      anonymous: opening,
    });
    const body = encryptAnonymous(
      tx,
      source.viewingPublicKey,
      encodeConfidential({
        assetId: SOL_ASSET_ID,
        amount: 42n,
        blinding,
        ringProgramId: RING,
        data: new Data(),
      }),
      salt,
      0,
    );
    return {
      slot: 1n,
      txSignature: "1".repeat(87) as Signature,
      eventIndex: 0,
      txViewingPublicKey: tx.publicKey(),
      salt,
      ringProgramId: RING,
      outputSlots: [
        {
          viewTag: ZERO_32,
          outputContext: { hash: commitment, tree: treeAddress(0), treeId: 0, leafIndex: 0n },
          payload: encodeOutputData(EncryptedScheme.ringAnonymous, body, "encrypted"),
        },
        {
          viewTag: ZERO_32,
          outputContext: {
            hash: filled(9) as Bytes32,
            tree: treeAddress(0),
            treeId: 0,
            leafIndex: 1n,
          },
          payload: new Uint8Array(0),
        },
      ],
      messages: [auditorMessageData(encrypted.message, auditor.publicKey())],
      nullifiers: [filled(1) as Bytes32, filled(2) as Bytes32],
      proofless: false,
    };
  }

  it("seals a 2x2 disclosure into 833 bytes and opens it with the same stream", () => {
    expect(auditDisclosureLength(shape)).toBe(24);
    expect(auditDisclosureLength({ anonymous: true, inputs: 3, outputs: 4 })).toBe(43);
    expect(auditDisclosureLength({ anonymous: false, inputs: 0, outputs: 1 })).toBe(36);
    expect(auditDisclosureLength({ anonymous: true, inputs: 0, outputs: 2 })).toBeUndefined();
    expect(auditDisclosureLength({ anonymous: true, inputs: 5, outputs: 2 })).toBeUndefined();
    const message = transaction().messages[0]!;
    expect(message.data).toHaveLength(65 + 32 * 24);
    const parsed = parseAuditorMessage(message.data, shape);
    expect(openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, shape)).toEqual(
      disclosure,
    );
    // The fixed non-anonymous length and a neighbouring shape are both refused.
    expect(() => parseAuditorMessage(message.data)).toThrow();
    expect(() =>
      parseAuditorMessage(message.data, { anonymous: true, inputs: 1, outputs: 2 }),
    ).toThrow();
    expect(() =>
      openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, {
        anonymous: true,
        inputs: 1,
        outputs: 2,
      }),
    ).toThrow(RangeError);
    expect(() =>
      openAnonymousAuditDisclosure(tx.secretBytes(), salt, parsed.disclosure, {
        ...shape,
        anonymous: false,
      }),
    ).toThrow(RangeError);
  });

  it("rejects nonzero slot padding, a foreign sender tag and a ring flag above one", () => {
    const plaintext = encodeAnonymousAuditDisclosure(disclosure);
    expect(plaintext).toHaveLength(62 + 2 * 93 + 2 * 248);
    expect(decodeAnonymousAuditDisclosure(plaintext, shape)).toEqual(disclosure);
    for (const [index, value] of [
      [33, 1],
      [0, 0x50],
      [62 + 74, 1],
      [62 + 2 * 93 + 234, 2],
      [62 + 2 * 93 + 235, 1],
    ] as const) {
      const corrupted = plaintext.slice();
      corrupted[index] = value;
      expect(() => decodeAnonymousAuditDisclosure(corrupted, shape)).toThrow(RangeError);
    }
    expect(() => decodeAnonymousAuditDisclosure(plaintext.subarray(1), shape)).toThrow(RangeError);
  });

  it("audits the hidden sender, inputs and recipients and rebuilds the real commitment", () => {
    const audited = auditRingTransaction({
      auditor,
      transaction: transaction(),
      assets: new AssetRegistry(),
      mode: "anonymous",
    });
    expect(audited.anonymous).toEqual({
      sender: encodeBase58(filled(3)),
      inputs: [{ treeId: 4, amount: 9n, asset: solAsset }],
      recipients: [
        {
          slotIndex: 0,
          identityTag: SOLANA_OWNER_TAG,
          identityKey: source.confidentialViewTag(),
          nullifierPk: source.nullifierPublicKey,
          amount: 42n,
          asset: solAsset,
        },
      ],
    });
    expect(audited.outputs).toHaveLength(1);
    expect(audited.outputs[0]?.amount).toBe(42n);
    expect(audited.outputs[0]?.ringProgramId).toBe(RING);
    expect(audited.outputs[0]?.ownerTag).toEqual(source.confidentialViewTag());
    expect(audited.outputs[0]?.recipientViewingPublicKey.equals(source.viewingPublicKey)).toBe(
      true,
    );
    expect(audited.outputOpenings[0]?.ownerHash).toEqual(source.ownerHash());
    expect(auditOpeningHash(audited.outputOpenings[0]!)).toEqual(commitment);
    expect(audited.outputOpenings[1]?.ownerHash).toEqual(ZERO_32);
    expect(audited.undecryptableSlots).toEqual([1]);
  });

  it("fails closed without the anonymous mode, on a wrong commitment and without a tree id", () => {
    const valid = transaction();
    const assets = new AssetRegistry();
    expect(() => auditRingTransaction({ auditor, transaction: valid, assets })).toThrow(
      "RING_AUDIT_MESSAGE",
    );
    const slot = valid.outputSlots[0]!;
    const flipped = filled(0) as Bytes32;
    flipped.set(commitment);
    flipped[31] = (flipped[31] ?? 0) ^ 1;
    expect(() =>
      auditRingTransaction({
        auditor,
        assets,
        mode: "anonymous",
        transaction: {
          ...valid,
          outputSlots: [
            { ...slot, outputContext: { ...slot.outputContext, hash: flipped } },
            valid.outputSlots[1]!,
          ],
        },
      }),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
    const { treeId: _, ...withoutTreeId } = slot.outputContext;
    expect(() =>
      auditRingTransaction({
        auditor,
        assets,
        mode: "anonymous",
        transaction: {
          ...valid,
          outputSlots: [{ ...slot, outputContext: withoutTreeId }, valid.outputSlots[1]!],
        },
      }),
    ).toThrow("RING_AUDIT_OUTPUT_MISMATCH");
  });

  it("retains a zero-value input whose blinding distinguishes it from padding", () => {
    const audited = auditRingTransaction({
      auditor,
      assets: new AssetRegistry(),
      mode: "anonymous",
      transaction: transaction({
        ...disclosure,
        inputs: [
          { treeId: 0, amount: 0n, asset: ZERO_32, blinding },
          { treeId: 0, amount: 0n, asset: ZERO_32, blinding: ZERO_32 },
        ],
      }),
    });
    expect(audited.anonymous?.inputs).toEqual([{ treeId: 0, amount: 0n, asset: ZERO_32 }]);
  });

  it("recovers the member's note from an anonymous transaction", async () => {
    const indexed = transaction();
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (input) =>
          transactionsPage(input.ringProgramId === undefined ? { transactions: [indexed] } : {}),
      }),
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };
    const recovered = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source,
      nullifierKey: member.nullifierKey(),
      assets: new AssetRegistry(),
      mode: "anonymous",
      resolveTreeId: () => 0,
      origin: { ringInvoked: async () => true },
    });
    expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([42n]);
    expect(recovered.notes[0]?.outputContext.hash).toEqual(commitment);
    expect(recovered.unopened).toEqual([]);
    // Another member sees the transaction but owns none of its notes.
    const other = ShieldedKeypair.generate();
    const none = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source: other.shieldedAddress(),
      nullifierKey: other.nullifierKey(),
      assets: new AssetRegistry(),
      mode: "anonymous",
      resolveTreeId: () => 0,
      origin: { ringInvoked: async () => true },
    });
    expect(none.notes).toEqual([]);
    expect(none.unopened).toEqual([]);
  });
});

function filled(byte: number, first = byte): Uint8Array {
  const bytes = new Uint8Array(32).fill(byte);
  bytes[0] = first;
  return bytes;
}
