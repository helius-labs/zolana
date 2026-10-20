import { address, type Signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair, SigningKey, ViewingKey } from "../src/keypair/index.js";
import { RingAddress } from "../src/keypair/ring-address.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { decodeAddress, equal, hashBytes } from "../src/transaction/internal.js";
import {
  RING_ANONYMOUS_BODY_LENGTH,
  decodeRingAnonymous,
  readOutputData,
  ringAnonymousBodyHash,
} from "../src/transaction/serialization/codecs.js";
import { createProofOutput, type ProofOutputUtxo } from "../src/transaction/utxo.js";
import { encryptAnonymousRingTransfer } from "../src/transaction/wallet/anonymous-ring.js";
import { AnonymousTagRoutes } from "../src/transaction/wallet/anonymous.js";
import { LocalShieldedKeys } from "../src/transaction/wallet/keys.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { decryptTransactions } from "../src/transaction/wallet/sync.js";
import { auditRingTransaction } from "../src/ring/audit.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { AnonymousTagAllocator, TagStream } from "../src/wallet/tag-stream.js";
import { syncReads } from "./helpers/clients.js";

const RING = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
const CONTEXT = { blockTime: 1_700_000_000n, slot: 0n };
const FIRST_NULLIFIER = new Uint8Array(32).fill(0x11) as Bytes32;

await initializePoseidon();

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes(seed)));
}

function ringAddress(owner: ShieldedKeypair, index = 0): RingAddress {
  return new RingAddress({
    recipient: owner.shieldedAddress(),
    ringProgramId: RING,
    inboxSecret: owner.viewingKey().inboxSecret(index),
  });
}

function payment(owner: ShieldedKeypair, amount: bigint, nonce: number): ProofOutputUtxo {
  const blinding = new Uint8Array(32) as Bytes32;
  blinding[31] = nonce;
  return createProofOutput({
    ownerAddress: owner.shieldedAddress(),
    asset: SOL_MINT,
    amount,
    blinding,
    ringProgramId: RING,
  });
}

function padding(): ProofOutputUtxo {
  return createProofOutput({ asset: SOL_MINT, amount: 0n, ringProgramId: RING });
}

/** Serves rows under the tags they carry, so an index with a row is occupied. */
function stream(occupied: readonly Bytes32[]): TagStream {
  const rows: IndexedShieldedTransaction[] = occupied.map((tag, nonce) => ({
    slot: BigInt(nonce),
    txSignature: "1".repeat(64) as Signature,
    outputSlots: [
      {
        viewTag: tag,
        outputContext: { hash: bytes(nonce + 1), tree: TREE, leafIndex: BigInt(nonce) },
        payload: new Uint8Array(8),
      },
    ],
    messages: [],
    nullifiers: [],
    proofless: false,
  }));
  return new TagStream(
    syncReads({
      getShieldedTransactionsByTags: async (request) => ({
        context: CONTEXT,
        transactions: rows.filter((row) =>
          row.outputSlots.some((slot) => request.tags.some((tag) => equal(tag, slot.viewTag))),
        ),
      }),
    }),
  );
}

describe("anonymous tag allocation", () => {
  const sender = keypair(1);
  const recipient = keypair(2);

  it("gives two payments to one address the two lowest free indices and skips occupied ones", async () => {
    const target = ringAddress(recipient);
    const allocator = new AnonymousTagAllocator({
      stream: stream([target.inboxSecret.viewTag(1n)]),
      sender: sender.viewingKey(),
      firstNullifier: FIRST_NULLIFIER,
    });
    const slots = await allocator.assign([
      { kind: "inbox", address: target },
      undefined,
      { kind: "inbox", address: target },
      { kind: "change", address: ringAddress(sender) },
    ]);
    expect(slots[0]?.tag).toEqual(target.inboxSecret.viewTag(0n));
    expect(slots[1]).toBeUndefined();
    expect(slots[2]?.tag).toEqual(target.inboxSecret.viewTag(2n));
    expect(slots[3]?.tag).toEqual(sender.viewingKey().ringChangeViewTag(FIRST_NULLIFIER, 3));
  });

  it("never publishes one pair tag twice for two addresses sharing a viewing key", async () => {
    const first = ringAddress(recipient, 0);
    const second = ringAddress(recipient, 1);
    const counterparty = recipient.viewingPublicKey();
    const allocator = new AnonymousTagAllocator({
      stream: stream([]),
      sender: sender.viewingKey(),
      firstNullifier: FIRST_NULLIFIER,
    });
    const slots = await allocator.assign([
      { kind: "pair", address: first, counterparty },
      { kind: "pair", address: second, counterparty },
    ]);
    expect(slots[0]?.tag).toEqual(sender.viewingKey().pairSendViewTag(counterparty, 0n));
    expect(slots[1]?.tag).toEqual(sender.viewingKey().pairSendViewTag(counterparty, 1n));
    expect(
      recipient
        .viewingKey()
        .recipientSharedViewTag(sender.viewingKey().pairKey(counterparty).publicKey(), 1n),
    ).toEqual(slots[1]?.tag);
  });

  it("refuses a paired destination whose address names another viewing key", async () => {
    const allocator = new AnonymousTagAllocator({
      stream: stream([]),
      sender: sender.viewingKey(),
      firstNullifier: FIRST_NULLIFIER,
    });
    await expect(
      allocator.assign([
        {
          kind: "pair",
          address: ringAddress(recipient),
          counterparty: keypair(3).viewingPublicKey(),
        },
      ]),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_RING_DESTINATION" });
  });
});

describe("anonymous ring sealing", () => {
  const sender = keypair(1);
  const recipient = keypair(2);
  const auditor = X25519Keypair.generate();
  const target = ringAddress(recipient);
  const tx = ViewingKey.generate();
  const paid = payment(recipient, 10n, 1);
  const change = payment(sender, 5n, 2);
  const outputs = [paid, padding(), change, padding()];
  const slots = [
    { address: target, tag: target.inboxSecret.viewTag(0n) },
    undefined,
    {
      address: ringAddress(sender),
      tag: sender.viewingKey().ringChangeViewTag(FIRST_NULLIFIER, 2),
    },
    undefined,
  ];
  const input = {
    sender: sender.viewingKey(),
    senderIdentity: sender.shieldedAddress().confidentialViewTag(),
    ringProgramId: RING,
    auditorPublicKey: auditor.publicKey(),
    outputs,
    slots,
    inputs: [
      {
        treeId: 0,
        amount: 15n,
        asset: hashBytes(decodeAddress(SOL_MINT)) as Bytes32,
        blinding: bytes(3),
      },
    ],
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function indexed(
    encrypted: ReturnType<typeof encryptAnonymousRingTransfer>,
  ): IndexedShieldedTransaction {
    return {
      slot: 1n,
      txSignature: "1".repeat(87) as Signature,
      eventIndex: 0,
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      ringProgramId: RING,
      outputSlots: outputs.map((output, slotIndex) => ({
        viewTag: encrypted.payload[slotIndex]!.viewTag,
        outputContext: {
          hash: output.hash(TREE_ID),
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: BigInt(slotIndex),
        },
        payload: encrypted.payload[slotIndex]!.data,
      })),
      messages: [encrypted.auditorMessage],
      nullifiers: [FIRST_NULLIFIER],
      proofless: false,
    };
  }

  it("publishes every slot in one framing with a zero-led distinct tag", () => {
    const encrypted = encryptAnonymousRingTransfer(tx, input);
    expect(encrypted.payload).toHaveLength(4);
    const tags = new Set<string>();
    encrypted.payload.forEach((slot, slotIndex) => {
      const frame = readOutputData(slot.data);
      expect(frame.encoding).toBe("encrypted");
      expect(frame.scheme).toBe(9);
      expect(slot.data.length).toBe(encrypted.payload[0]!.data.length);
      expect(frame.body.length + 1).toBe(RING_ANONYMOUS_BODY_LENGTH);
      expect(slot.viewTag[0]).toBe(0);
      expect(slot.viewTag.some((byte) => byte !== 0)).toBe(true);
      tags.add(Buffer.from(slot.viewTag).toString("hex"));
      expect(encrypted.outputBodyHashes[slotIndex]).toEqual(ringAnonymousBodyHash(frame.body));
      expect(encrypted.delivery[slotIndex]?.ciphertext).toEqual(frame.body);
    });
    expect(tags.size).toBe(4);
    expect(encrypted.delivery[1]?.assetAddress).toEqual(new Uint8Array(32));
    expect(encrypted.delivery[0]?.pairU).toEqual(
      sender.viewingKey().pairKey(recipient.viewingPublicKey()).publicKey().u(),
    );
  });

  it("resamples a padding tag that collides with a tag of the transaction", () => {
    const real = slots[0]!.tag;
    const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    let collided = false;
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(
      <T extends ArrayBufferView<ArrayBuffer>>(buffer: T): T => {
        if (buffer.byteLength === 32 && !collided) {
          collided = true;
          new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).set(real);
          return buffer;
        }
        return original(buffer);
      },
    );
    const encrypted = encryptAnonymousRingTransfer(tx, input);
    expect(collided).toBe(true);
    const tags = encrypted.payload.map((slot) => Buffer.from(slot.viewTag).toString("hex"));
    expect(new Set(tags).size).toBe(4);
  });

  it("refuses records, compact padding, a foreign owner and a malformed tag", () => {
    const memo = [paid.withMemo(Uint8Array.of(1)), padding(), change, padding()];
    expect(() => encryptAnonymousRingTransfer(tx, { ...input, outputs: memo })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ANONYMOUS_OUTPUT_DATA" }),
    );
    const compact = [
      paid,
      createProofOutput({ asset: SOL_MINT, amount: 0n, compact: true }),
      change,
      padding(),
    ];
    expect(() => encryptAnonymousRingTransfer(tx, { ...input, outputs: compact })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ANONYMOUS_COMPACT_PADDING" }),
    );
    const foreign = [{ address: ringAddress(keypair(3)), tag: slots[0]!.tag }, ...slots.slice(1)];
    expect(() => encryptAnonymousRingTransfer(tx, { ...input, slots: foreign })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ANONYMOUS_SLOT_MISMATCH" }),
    );
    const unpadded = [{ address: target, tag: bytes(7) }, ...slots.slice(1)];
    expect(() => encryptAnonymousRingTransfer(tx, { ...input, slots: unpadded })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ANONYMOUS_TAG" }),
    );
    const missing = [undefined, ...slots.slice(1)];
    expect(() => encryptAnonymousRingTransfer(tx, { ...input, slots: missing })).toThrow(
      expect.objectContaining({ code: "TRANSACTION_ANONYMOUS_SLOT_MISMATCH" }),
    );
  });

  it("seals a slot sharing the sender's signing and nullifier keys to its address's viewing key", () => {
    const twin = ShieldedKeypair.withViewingKey(
      SigningKey.fromEd25519Bytes(bytes(1)),
      keypair(3).viewingKey(),
    );
    const address = ringAddress(twin);
    const encrypted = encryptAnonymousRingTransfer(tx, {
      ...input,
      outputs: [payment(twin, 10n, 1), ...outputs.slice(1)],
      slots: [{ address, tag: address.inboxSecret.viewTag(0n) }, ...slots.slice(1)],
    });
    const opened = decodeRingAnonymous(
      twin
        .viewingKey()
        .openAnonymousOutput(
          encrypted.delivery[0]!.ciphertext,
          encrypted.txViewingPublicKey,
          encrypted.salt,
          0,
        ),
    );
    expect(opened.amount).toBe(10n);
    expect(opened.pairU).toEqual(
      sender.viewingKey().pairKey(twin.viewingPublicKey()).publicKey().u(),
    );
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  });

  it("opens for the recipient under its inbox tag and for the auditor from the disclosed address", async () => {
    const encrypted = encryptAnonymousRingTransfer(tx, input);
    const transaction = indexed(encrypted);
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const routes = new AnonymousTagRoutes();
    routes.route(slots[0]!.tag, [recipient.viewingPublicKey()], { kind: "inbox", addressIndex: 0 });
    const report = await decryptTransactions({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      transactions: [transaction],
      anonymous: routes,
    });
    expect(report.storedUtxos).toBe(1);
    expect(wallet.utxos()[0]?.utxo.amount).toBe(10n);
    expect(
      routes
        .notes()[0]
        ?.pairPublicKey?.equals(
          sender.viewingKey().pairKey(recipient.viewingPublicKey()).publicKey(),
        ),
    ).toBe(true);

    const audited = auditRingTransaction({
      auditor,
      transaction,
      assets: new AssetRegistry(),
      mode: "anonymous",
    });
    expect(audited.outputs.map((output) => [output.slotIndex, output.amount])).toEqual([
      [0, 10n],
      [2, 5n],
    ]);
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.anonymous?.recipients.map((entry) => entry.slotIndex)).toEqual([0, 2]);
    expect(audited.outputOpenings[1]?.ownerHash).toEqual(new Uint8Array(32));
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  });
});
