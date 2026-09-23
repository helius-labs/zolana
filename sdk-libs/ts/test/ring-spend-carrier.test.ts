import { beforeAll, describe, expect, it } from "vitest";
import { getAddressDecoder, type Address, type Signature } from "@solana/kit";
import { initializePoseidon } from "../src/hasher/index.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { nullifierPdaAddress } from "../src/interface/pda/index.js";
import type { Bytes31, Bytes32 } from "../src/interface/types.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ShieldedAddress } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { createProofOutput, ProofInputUtxo, Utxo } from "../src/transaction/utxo.js";
import { encryptCustomRingTransfer } from "../src/transaction/wallet/encrypt-rails.js";
import { EncryptedScheme, readOutputData } from "../src/transaction/serialization/codecs.js";
import {
  createExternalData,
  SppProofInputs,
  type IndexedShieldedTransaction,
} from "../src/transaction/instructions/transact.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import { frameDummyOutputs } from "../src/ring/transfer.js";
import { sealedSpendCounters } from "../src/ring/counters.js";
import { findCurrentSpendRecord, readCurrentSpendRecord } from "../src/ring/spend-record-reader.js";
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

/** `leafTreeId` is the tree the record lands in, its address hashes under tree 4. */
function fixture(leafTreeId = 4) {
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
  const hashes = owner.spendRecordHashes(record, leafTreeId);
  const output = createProofOutput({
    ownerAddress: ShieldedAddress.forPda({
      pda: NAMESPACE,
      nullifierPublicKey: nullifier.publicKey(),
      viewingPublicKey: viewing.publicKey(),
    }),
    asset: SOL_MINT,
    amount: 0n,
    dataHash: hashes.dataHash,
    blinding: record.blinding,
    ownerTag: NAMESPACE,
  });
  const tx = viewing.transactionViewingKey(field(16));
  const encrypted = encryptCustomRingTransfer(tx, {
    outputs: [output],
    assets: new AssetRegistry(),
    auditorPublicKey: auditor.publicKey(),
    outputTreeId: leafTreeId,
    recordOutputIndex: 0,
    counterMessage: sealedSpendCounters(counters, NAMESPACE),
  });
  tx.destroy();
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
    const input = ProofInputUtxo.fromNullifierKey(
      new Utxo({
        owner: owner.signingPublicKey,
        asset: SOL_MINT,
        amount: 0n,
        blinding: field(21),
      }),
      nullifier,
      {},
      4,
    );
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

  it("rebuilds the exact current leaf from its message, not the encrypted body", async () => {
    const f = fixture();
    try {
      const record = { transaction: f.transaction, outputIndex: 0 };
      const input = {
        record,
        addressTreeId: 4,
        resolveTreeId: (tree: typeof TREE) => (tree === TREE ? 4 : 9),
        namespace: ADDRESS,
        member: f.record.member,
      };
      expect((await currentRingSpendRecord(input)).record).toEqual(f.record);
      const altered = { ...f.record, window: 8n };
      await expect(
        currentRingSpendRecord({
          ...input,
          record: {
            ...record,
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
        }),
      ).rejects.toThrow("RING_SPEND_RECORD_INVALID");
      for (const changed of [
        { member: memberOfIdentity(field(3)) },
        { resolveTreeId: () => 5 },
        { addressTreeId: 5 },
      ])
        await expect(currentRingSpendRecord({ ...input, ...changed })).rejects.toThrow(
          "RING_SPEND_RECORD_INVALID",
        );
    } finally {
      f.auditor.destroy();
    }
  });

  it("hashes a record's address under the address tree and its leaf under the tree it landed in", async () => {
    const f = fixture(6);
    try {
      const live = await currentRingSpendRecord({
        record: { transaction: f.transaction, outputIndex: 0 },
        addressTreeId: 4,
        resolveTreeId: () => 6,
        namespace: ADDRESS,
        member: f.record.member,
      });
      expect(live).toMatchObject({ record: f.record, tree: TREE, treeId: 6 });
      expect(live.utxoHash).toEqual(f.hashes.utxoHash);
      expect(f.hashes.address).toEqual(
        RingListNamespace.of(ADDRESS, 4).spendAddress(f.record.member),
      );
    } finally {
      f.auditor.destroy();
    }
  });

  it("waits while the served record is spent in the tree it landed in", async () => {
    const f = fixture(6);
    try {
      let spentReads = 1;
      const queried: Address[] = [];
      const live = await readCurrentSpendRecord({
        client: {
          getRingSpendRecord: async () => ({
            context: { slot: 1n, blockTime: 0n },
            record: { transaction: f.transaction, outputIndex: 0 },
          }),
          getAccount: async (address: Address) => {
            queried.push(address);
            return spentReads-- > 0 ? ({} as RpcAccount) : undefined;
          },
        },
        ringProgramId: ADDRESS,
        namespace: ADDRESS,
        addressTreeId: 4,
        resolveTreeId: () => 6,
        sender: f.record.member,
      });
      expect(live.record).toEqual(f.record);
      expect(spentReads).toBe(-1);
      const pda = await nullifierPdaAddress(TREE, live.nullifier);
      expect(queried).toEqual([pda, pda]);
    } finally {
      f.auditor.destroy();
    }
  });

  it("reads the indexed record for the requested member only", async () => {
    const f = fixture();
    try {
      const requests: unknown[] = [];
      const reader = (found: boolean) => ({
        client: {
          getRingSpendRecord: async (request: unknown) => {
            requests.push(request);
            return {
              context: { slot: 1n, blockTime: 0n },
              record: found ? { transaction: f.transaction, outputIndex: 0 } : null,
            };
          },
          getAccount: async () => undefined,
        },
        ringProgramId: ADDRESS,
        namespace: ADDRESS,
        addressTreeId: 4,
        resolveTreeId: () => 4,
        sender: f.record.member,
      });
      expect((await readCurrentSpendRecord(reader(true))).record).toEqual(f.record);
      expect(requests).toEqual([{ ringProgramId: ADDRESS, member: f.record.member }]);
      expect(await findCurrentSpendRecord(reader(false))).toBeUndefined();
      await expect(readCurrentSpendRecord(reader(false))).rejects.toMatchObject({
        code: "RING_SPEND_RECORD_MISSING",
      });
      await expect(
        readCurrentSpendRecord({ ...reader(true), sender: memberOfIdentity(field(3)) }),
      ).rejects.toMatchObject({ code: "RING_SPEND_RECORD_INVALID" });
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
