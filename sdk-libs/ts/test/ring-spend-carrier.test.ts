import { beforeAll, describe, expect, it } from "vitest";
import { getAddressDecoder, type Signature } from "@solana/kit";
import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes31, Bytes32 } from "../src/interface/types.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ShieldedAddress } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { createProofOutput, ProofInputUtxo, Utxo } from "../src/transaction/utxo.js";
import { encryptCustomRingTransferWith } from "../src/transaction/wallet/encrypt-rails.js";
import { EncryptedScheme, readOutputData } from "../src/transaction/serialization/codecs.js";
import {
  createExternalData,
  SppProofInputs,
  type IndexedShieldedTransaction,
} from "../src/transaction/instructions/transact.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import { frameDummyOutputs } from "../src/ring/transfer.js";
import { sealedSpendCounters } from "../src/ring/counters.js";
import {
  RingListNamespace,
  currentRingSpendRecord,
  encodeSpendRecord,
  memberOfIdentity,
  memberOfAsset,
  spendCountersCommitment,
  spendRecordFromSlot,
  spendRecordMessageTag,
} from "../src/ring/policy.js";

const field = (value: number): Bytes32 => {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
};
const NAMESPACE = field(10);
const ADDRESS = getAddressDecoder().decode(NAMESPACE);
const TREE = getAddressDecoder().decode(field(11));
beforeAll(initializePoseidon);

function fixture() {
  const viewing = ViewingKey.fromBytes(field(12));
  const auditor = ViewingKey.fromBytes(field(13));
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
  const owner = RingListNamespace.of(ADDRESS, 4);
  const counters = {
    salt: field(14),
    assets: [memberOfAsset(SOL_MINT)],
    spent: [9n],
  };
  const record = {
    member: memberOfIdentity(field(1)),
    version: 1n,
    window: 7n,
    countersCommitment: spendCountersCommitment(counters),
    blinding: field(15),
  };
  const hashes = owner.spendRecordHashes(record);
  const output = createProofOutput({
    ownerAddress: ShieldedAddress.forPda(NAMESPACE, nullifier.publicKey(), viewing.publicKey()),
    asset: SOL_MINT,
    amount: 0n,
    dataHash: hashes.dataHash,
    blinding: record.blinding,
    ownerTag: NAMESPACE,
  });
  const encrypted = encryptCustomRingTransferWith(viewing, {
    firstNullifier: field(16),
    outputs: [output],
    assets: new AssetRegistry(),
    auditorPublicKey: auditor.publicKey(),
    recordOutputIndex: 0,
    counterMessage: sealedSpendCounters(counters, NAMESPACE),
  });
  const carrier = encrypted.payload[0];
  if (carrier === undefined) throw new Error("carrier");
  const transaction: IndexedShieldedTransaction = {
    txSignature: "1".repeat(88) as Signature,
    slot: 77n,
    proofless: false,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    nullifiers: [field(16)],
    outputSlots: [
      {
        viewTag: carrier.viewTag,
        payload: carrier.data,
        outputContext: { tree: TREE, hash: hashes.utxoHash, leafIndex: 4n },
      },
    ],
    messages: [
      {
        viewTag: spendRecordMessageTag(NAMESPACE),
        data: encodeSpendRecord(record),
      },
      ...encrypted.sealedMessages,
      encrypted.auditorMessage,
    ],
  };
  encrypted.audit.txViewingSecret.fill(0);
  encrypted.audit.ephemeralSecret.fill(0);
  nullifier.destroy();
  viewing.destroy();
  return { transaction, auditor, record, hashes, counters, output };
}

describe("compressed spend record carrier", () => {
  it("frames dummy-only money outputs from the final encrypted record", () => {
    const f = fixture();
    const nullifier = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    const owner = f.output.ownerAddress;
    const carrier = f.transaction.outputSlots[0];
    const txViewingPublicKey = f.transaction.txViewingPublicKey;
    const salt = f.transaction.salt;
    if (
      owner === undefined ||
      carrier === undefined ||
      txViewingPublicKey === undefined ||
      salt === undefined
    )
      throw new Error("fixture");
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: owner.signingPublicKey,
        asset: SOL_MINT,
        amount: 0n,
        blinding: field(21),
      }),
      nullifierKey: nullifier,
      treeId: 4,
    });
    try {
      const dummy = createProofOutput({
        asset: SOL_MINT,
        amount: 0n,
        blinding: field(22),
        ownerTag: NAMESPACE,
      });
      const proofInputs = new SppProofInputs({
        payer: ADDRESS,
        inputUtxos: [input],
        outputs: [dummy, f.output],
        blindingSeed: field(23),
        outputTreeId: 4,
        externalData: createExternalData({
          txViewingPublicKey,
          salt,
          messages: f.transaction.messages,
          resolvedOwnerTags: [NAMESPACE, NAMESPACE],
          outputs: [
            { utxoHash: dummy.hash(4), ownerTag: { kind: "inline", value: NAMESPACE } },
            {
              utxoHash: f.hashes.utxoHash,
              ownerTag: { kind: "inline", value: NAMESPACE },
              data: carrier.payload,
            },
          ],
        }),
      });
      const framed = frameDummyOutputs(proofInputs);
      expect(framed.externalData.outputs[0]?.data).toHaveLength(carrier.payload.length);
      expect(
        readOutputData(framed.externalData.outputs[0]?.data ?? new Uint8Array()),
      ).toMatchObject({ encoding: "encrypted", scheme: EncryptedScheme.confidential });
      expect(framed.externalData.outputs[1]).toEqual(proofInputs.externalData.outputs[1]);
      expect(framed.outputs.map((output) => output.hash(4))).toEqual(
        proofInputs.outputs.map((output) => output.hash(4)),
      );
      expect(framed.externalData.messages).toEqual(proofInputs.externalData.messages);
    } finally {
      input.destroy();
      nullifier.destroy();
      f.auditor.destroy();
    }
  });
  it("matches the Rust public-message tag vector", () => {
    expect(
      Buffer.from(spendRecordMessageTag(new Uint8Array(32).fill(7) as Bytes32)).toString("hex"),
    ).toBe("87337f4d5068808c2f105da6e07232361fa4683cfe4a17920d01f2542ba46bb2");
  });
  it("publishes a true Confidential namespace output and audits its separate counters", () => {
    const f = fixture();
    try {
      const slot = f.transaction.outputSlots[0];
      if (slot === undefined) throw new Error("slot");
      expect(slot.viewTag).toEqual(NAMESPACE);
      expect(readOutputData(slot.payload)).toMatchObject({
        encoding: "encrypted",
        scheme: EncryptedScheme.confidential,
      });
      expect(f.output.hash(4)).toEqual(f.hashes.utxoHash);
      expect(f.transaction.messages).toHaveLength(3);
      expect(f.transaction.messages[0]?.viewTag).not.toEqual(f.transaction.messages[1]?.viewTag);
      const audited = auditRingTransaction({
        transaction: f.transaction,
        auditor: f.auditor,
        assets: new AssetRegistry(),
      });
      expect(audited.outputs).toHaveLength(0);
      expect(audited.undecryptableSlots).toHaveLength(0);
      expect(audited.spendRecords[0]?.record).toEqual(f.record);
      expect(audited.spendRecords[0]?.counters?.spent[0]).toBe(9n);
    } finally {
      f.auditor.destroy();
    }
  });

  it("rebuilds the exact current leaf from its message, not the encrypted body", () => {
    const f = fixture();
    try {
      const proof = {
        context: { slot: 77n, blockTime: 0n },
        root: field(1),
        nextIndex: 2n,
        member: f.record.member,
        next: field(2),
        nullifier: f.hashes.nullifier,
        index: 1n,
        proof: Array.from({ length: 40 }, () => field(0)),
        record: { transaction: f.transaction, outputIndex: 0 },
      };
      const input = {
        proof,
        entriesTree: TREE,
        entriesTreeId: 4,
        namespace: ADDRESS,
        member: f.record.member,
      };
      expect(currentRingSpendRecord(input).record).toEqual(f.record);
      const altered = { ...f.record, window: 8n };
      expect(() =>
        currentRingSpendRecord({
          ...input,
          proof: {
            ...proof,
            record: {
              ...proof.record,
              transaction: {
                ...f.transaction,
                messages: [
                  {
                    viewTag: spendRecordMessageTag(NAMESPACE),
                    data: encodeSpendRecord(altered),
                  },
                ],
              },
            },
          },
        }),
      ).toThrow("RING_SPEND_RECORD_INVALID");
    } finally {
      f.auditor.destroy();
    }
  });

  it("refuses duplicate openings and plaintext successors, but accepts plaintext registration", () => {
    const f = fixture();
    try {
      const slot = f.transaction.outputSlots[0];
      const message = f.transaction.messages[0];
      if (slot === undefined || message === undefined) throw new Error("slot");
      expect(() => spendRecordFromSlot(slot, [message, message])).toThrow(
        "RING_SPEND_RECORD_INVALID",
      );
      expect(() =>
        spendRecordFromSlot({ ...slot, payload: encodeSpendRecord(f.record) }, [message]),
      ).toThrow("RING_SPEND_RECORD_INVALID");
      expect(
        spendRecordFromSlot({ ...slot, payload: encodeSpendRecord(f.record) }, []),
      ).toBeUndefined();
      const registered = { ...f.record, version: 0n };
      expect(spendRecordFromSlot({ ...slot, payload: encodeSpendRecord(registered) }, [])).toEqual(
        registered,
      );
    } finally {
      f.auditor.destroy();
    }
  });
});
