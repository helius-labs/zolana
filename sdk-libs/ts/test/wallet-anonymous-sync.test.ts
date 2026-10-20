import { address, type Address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { DEFAULT_TREE_ID, type Bytes16, type Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type X25519PublicKey,
} from "../src/keypair/index.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { equal } from "../src/transaction/internal.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
  encodeRingAnonymous,
} from "../src/transaction/serialization/codecs.js";
import { Utxo } from "../src/transaction/utxo.js";
import { AnonymousTagRoutes } from "../src/transaction/wallet/anonymous.js";
import {
  LocalShieldedKeys,
  type DecryptRequest,
  type RingTagKeys,
} from "../src/transaction/wallet/keys.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { decryptTransactions } from "../src/transaction/wallet/sync.js";
import { recoverAnonymousRing } from "../src/wallet/anonymous-recovery.js";
import { ADDRESS_GAP, DECRYPTIONS_PER_INDEX } from "../src/wallet/anonymous-sync.js";
import { syncWallet } from "../src/wallet/sync.js";
import { DEFAULT_TAG_WINDOW, TagStream } from "../src/wallet/tag-stream.js";
import { syncReads } from "./helpers/clients.js";

const RING = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const TREE = treeAddress(DEFAULT_TREE_ID);
const SIGNATURE = "1".repeat(64) as Signature;
const SALT = new Uint8Array(16).fill(7) as Bytes16;
const CONTEXT = { blockTime: 1_700_000_000n, slot: 0n };

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes(seed)));
}

/** A ring note of `owner` with its commitment and nullifier. */
function note(owner: ShieldedKeypair, amount: bigint, nonce: number, asset: Address = SOL_MINT) {
  const blinding = new Uint8Array(32) as Bytes32;
  blinding[31] = nonce;
  const utxo = new Utxo({
    owner: owner.signingPublicKey(),
    asset,
    amount,
    blinding,
    ringProgramId: RING,
    data: new Data(),
  });
  const hash = utxo.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID);
  return { utxo, hash, nullifier: owner.nullifier(hash, blinding) };
}

/** `payer` pays `paid` to `recipient` in `slotIndex` under `tag`. */
function anonymousSlot(
  payer: ViewingKey,
  tx: ViewingKey,
  recipient: X25519PublicKey,
  paid: ReturnType<typeof note>,
  tag: Bytes32,
  slotIndex: number,
) {
  const pair = payer.pairKey(recipient);
  const pairU = pair.publicKey().u();
  pair.destroy();
  return anonymousSlotWithHint(tx, recipient, paid, tag, slotIndex, pairU);
}

function anonymousSlotWithHint(
  tx: ViewingKey,
  recipient: X25519PublicKey,
  paid: ReturnType<typeof note>,
  tag: Bytes32,
  slotIndex: number,
  pairU: Bytes32,
) {
  const body = tx.sealAnonymousOutput(
    recipient,
    encodeRingAnonymous({
      assetAddress: paid.utxo.asset,
      amount: paid.utxo.amount,
      blinding: paid.utxo.blinding,
      pairU,
    }),
    SALT,
    slotIndex,
  );
  return {
    viewTag: tag,
    outputContext: { hash: paid.hash, tree: TREE, leafIndex: BigInt(slotIndex) },
    payload: encodeOutputData(EncryptedScheme.ringAnonymous, body, "encrypted"),
  };
}

function transaction(
  tx: ViewingKey,
  nonce: number,
  nullifiers: readonly Bytes32[],
  outputSlots: IndexedShieldedTransaction["outputSlots"],
): IndexedShieldedTransaction {
  return {
    slot: BigInt(nonce),
    txSignature: SIGNATURE,
    txViewingPublicKey: tx.publicKey(),
    salt: SALT,
    outputSlots,
    messages: [],
    nullifiers,
    proofless: false,
    ringProgramId: RING,
  };
}

function inboxTag(recipient: ShieldedKeypair, i: number, j: bigint): Bytes32 {
  return recipient.viewingKey().inboxSecret(i).viewTag(j);
}

/** A first payment of `amount` from `payer` to `recipient`'s address `i` at inbox index `j`. */
function inboxPayment(
  payer: ShieldedKeypair,
  recipient: ShieldedKeypair,
  i: number,
  j: bigint,
  amount: bigint,
  nonce: number,
) {
  const paid = note(recipient, amount, nonce);
  const txKey = keypair(nonce).viewingKey();
  const tx = transaction(
    txKey,
    nonce,
    [bytes(nonce)],
    [
      anonymousSlot(
        payer.viewingKey(),
        txKey,
        recipient.viewingPublicKey(),
        paid,
        inboxTag(recipient, i, j),
        0,
      ),
    ],
  );
  return { tx, paid };
}

function pairPublicKeyOf(payer: ShieldedKeypair, recipient: ShieldedKeypair): X25519PublicKey {
  const pair = payer.viewingKey().pairKey(recipient.viewingPublicKey());
  try {
    return pair.publicKey();
  } finally {
    pair.destroy();
  }
}

interface Fixture {
  tagged?: readonly IndexedShieldedTransaction[];
  deposits?: readonly Readonly<{
    txSignature: Signature;
    slot: bigint;
    outputSlot: IndexedShieldedTransaction["outputSlots"][number];
  }>[];
  spends?: readonly IndexedShieldedTransaction[];
}

/** Serves rows by exact tag and nullifier, in one page, and records every tag asked for. */
function indexer(fixture: Fixture) {
  const queried: Bytes32[][] = [];
  const asked = (tag: Bytes32) => queried.some((tags) => tags.some((other) => equal(other, tag)));
  const client = syncReads({
    getShieldedTransactionsByTags: async (request) => {
      queried.push([...request.tags]);
      return {
        context: CONTEXT,
        transactions: (fixture.tagged ?? []).filter((tx) =>
          tx.outputSlots.some((slot) => request.tags.some((tag) => equal(tag, slot.viewTag))),
        ),
      };
    },
    getEncryptedUtxosByTags: async (request) => ({
      context: CONTEXT,
      matches: (fixture.deposits ?? []).filter((deposit) =>
        request.tags.some((tag) => equal(tag, deposit.outputSlot.viewTag)),
      ),
    }),
    getShieldedTransactionsByNullifiers: async (request) => ({
      context: CONTEXT,
      transactions: (fixture.spends ?? []).filter((tx) =>
        tx.nullifiers.some((nullifier) => request.nullifiers.some((n) => equal(n, nullifier))),
      ),
    }),
  });
  return { client, queried, asked };
}

/** Records which viewing keys each decryption named. */
function countingKeys(owner: ShieldedKeypair) {
  const local = LocalShieldedKeys.fromKeypair(owner);
  const decryptedUnder: X25519PublicKey[] = [];
  const keys: RingTagKeys = {
    address: () => local.address(),
    viewingPublicKeys: () => local.viewingPublicKeys(),
    decrypt: async (requests: readonly DecryptRequest[]) => {
      decryptedUnder.push(...requests.map((request) => request.viewingPublicKey));
      return local.decrypt(requests);
    },
    derive: (requests) => local.derive(requests),
    transactionKeys: (requests) => local.transactionKeys(requests),
    ringViewTags: (requests) => local.ringViewTags(requests),
  };
  return { keys, decryptedUnder };
}

function unspentHashes(wallet: Wallet): string[] {
  return wallet
    .utxos()
    .filter((entry) => !entry.spent)
    .map((entry) => Buffer.from(entry.outputContext.hash).toString("hex"))
    .sort();
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

const freshState = { issuedAddresses: 0, knownCounterparties: [] } as const;

describe("tag stream occupancy", () => {
  it("counts an undecryptable or colliding output as occupied and finds the first free index", async () => {
    const owner = keypair(1);
    const tagAt = (index: bigint) => owner.viewingKey().senderViewTag(index);
    const rows = [0n, 1n, 1n, 2n, 5n].map((index, nonce) => ({
      slot: BigInt(nonce),
      txSignature: SIGNATURE,
      outputSlots: [
        {
          viewTag: tagAt(index),
          outputContext: { hash: bytes(nonce + 1), tree: TREE, leafIndex: BigInt(nonce) },
          payload: new Uint8Array(8).fill(0xff),
        },
      ],
      messages: [],
      nullifiers: [],
      proofless: false,
    }));
    const { client } = indexer({ tagged: rows });
    const stream = new TagStream(client);
    expect([...(await stream.occupiedIndices(0n, tagAt))].sort()).toEqual([0n, 1n, 2n, 5n]);
    expect(await stream.firstFreeIndex(0n, tagAt)).toBe(3n);
    expect(await stream.firstFreeIndex(5n, tagAt)).toBe(6n);
    expect(await stream.firstFreeIndex(DEFAULT_TAG_WINDOW, tagAt)).toBe(DEFAULT_TAG_WINDOW);
  });
});

describe("anonymous ring sync", () => {
  it("finds both payers on one inbox index and opens their pair streams", async () => {
    const recipient = keypair(1);
    const first = inboxPayment(keypair(2), recipient, 0, 0n, 10n, 11);
    const second = inboxPayment(keypair(3), recipient, 0, 0n, 20n, 12);
    const { client, asked } = indexer({ tagged: [first.tx, second.tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(first.paid.hash), hex(second.paid.hash)].sort());
    const ring = report.anonymousRing!;
    const pairKeys = [keypair(2), keypair(3)].map((payer) => pairPublicKeyOf(payer, recipient));
    expect(ring.newCounterparties.map((key) => hex(key.toBytes())).sort()).toEqual(
      pairKeys.map((key) => hex(key.toBytes())).sort(),
    );
    expect(ring.usedAddresses).toBe(1);
    expect(ring.inboxNext.get(0)).toBe(1n);
    expect(ring.addressesUnderAttack).toEqual([]);
    expect(ring.notes.every((entry) => entry.stream.kind === "inbox")).toBe(true);
    for (const pairKey of pairKeys) {
      expect(asked(recipient.viewingKey().recipientSharedViewTag(pairKey, 0n))).toBe(true);
    }
    const rows = wallet.privateTransactions();
    expect(rows.map((row) => [row.direction, row.amount])).toEqual([
      ["inbound", 10n],
      ["inbound", 20n],
    ]);
  });

  it("opens every hit under a spammed inbox index and flags the address", async () => {
    const recipient = keypair(1);
    const spammer = keypair(4);
    const tagged: IndexedShieldedTransaction[] = [];
    for (let nonce = 0; nonce <= DECRYPTIONS_PER_INDEX; nonce++) {
      // Sealed to the spammer's own key under the recipient's tag, nothing opens.
      const { tx } = inboxPayment(spammer, spammer, 0, 0n, 1n, 20 + nonce);
      tagged.push({
        ...tx,
        outputSlots: tx.outputSlots.map((slot) => ({
          ...slot,
          viewTag: inboxTag(recipient, 0, 0n),
        })),
      });
    }
    // The real payment sits past the cap under the same index and still opens.
    const real = inboxPayment(keypair(2), recipient, 0, 0n, 10n, 50);
    tagged.push(real.tx);
    const { client } = indexer({ tagged });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(real.paid.hash)]);
    expect(report.anonymousRing?.addressesUnderAttack).toEqual([0]);
    expect(report.anonymousRing?.inboxNext.get(0)).toBe(1n);
    expect(report.anonymousRing?.usedAddresses).toBe(1);
  });

  it("stores a note whose pair hint is no X25519 key and reports the hint", async () => {
    const recipient = keypair(1);
    const paid = note(recipient, 10n, 11);
    const txKey = keypair(11).viewingKey();
    const tx = transaction(
      txKey,
      11,
      [bytes(11)],
      [
        anonymousSlotWithHint(
          txKey,
          recipient.viewingPublicKey(),
          paid,
          inboxTag(recipient, 0, 0n),
          0,
          new Uint8Array(32).fill(0xff) as Bytes32,
        ),
      ],
    );
    const { client } = indexer({ tagged: [tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(paid.hash)]);
    const ring = report.anonymousRing!;
    expect(ring.badPairHints.map(hex)).toEqual([hex(paid.hash)]);
    expect(ring.newCounterparties).toEqual([]);
    expect(ring.notes[0]?.pairPublicKey).toBeUndefined();
    expect(wallet.privateTransactions().map((row) => row.direction)).toEqual(["inbound"]);
  });

  it("holds a verified note with an unknown mint until the mint is registered", async () => {
    const recipient = keypair(1);
    const mint = address("So11111111111111111111111111111111111111112");
    const paid = note(recipient, 10n, 12, mint);
    const { tx } = inboxPayment(keypair(2), recipient, 0, 0n, 10n, 12);
    const payment = {
      ...tx,
      outputSlots: [
        anonymousSlotWithHint(
          keypair(12).viewingKey(),
          recipient.viewingPublicKey(),
          paid,
          inboxTag(recipient, 0, 0n),
          0,
          pairPublicKeyOf(keypair(2), recipient).u(),
        ),
      ],
    };
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(recipient);
    const routes = new AnonymousTagRoutes();
    routes.route(inboxTag(recipient, 0, 0n), recipient.viewingPublicKey(), {
      kind: "inbox",
      addressIndex: 0,
    });

    const held = await decryptTransactions({
      wallet,
      keys,
      transactions: [payment],
      anonymous: routes,
    });
    expect(wallet.utxos()).toEqual([]);
    expect(held.pendingAssets).toHaveLength(1);
    const pending = held.pendingAssets[0]!;
    expect(pending.utxo.asset).toBe(mint);
    expect(pending.utxo.amount).toBe(10n);
    expect(pending.outputContext.hash).toEqual(paid.hash);
    expect(pending.txSignature).toBe(SIGNATURE);
    expect(pending.slotIndex).toBe(0);

    wallet.registerAsset(7n, mint);
    const stored = await decryptTransactions({
      wallet,
      keys,
      transactions: [payment],
      anonymous: routes,
    });
    expect(stored.pendingAssets).toEqual([]);
    expect(unspentHashes(wallet)).toEqual([hex(paid.hash)]);
  });

  it("finds change from the nullifiers of a fresh wallet", async () => {
    const owner = keypair(1);
    const other = keypair(5);
    const blinding = bytes(30);
    const funded = new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount: 50n,
      blinding,
    });
    const fundedHash = funded.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID);
    const fundedNullifier = owner.nullifier(fundedHash, blinding);
    const deposit = {
      slot: 9n,
      txSignature: SIGNATURE,
      outputSlot: {
        viewTag: owner.viewingKey().senderViewTag(0n),
        outputContext: { hash: fundedHash, tree: TREE, leafIndex: 4n },
        payload: encodeOutputData(
          EncryptedScheme.proofless,
          encodeProofless({
            owner: owner.signingPublicKey().ownerProofInputHash(),
            blinding,
            asset: SOL_MINT,
            amount: 50n,
          }),
          "plaintext",
        ),
      },
    };
    const paid = note(other, 30n, 31);
    const change = note(owner, 20n, 32);
    const txKey = owner.viewingKey().transactionViewingKey(fundedNullifier);
    const changeTag = owner.viewingKey().ringChangeViewTag(fundedNullifier, 1);
    const spend = transaction(
      txKey,
      33,
      [fundedNullifier],
      [
        anonymousSlot(
          owner.viewingKey(),
          txKey,
          other.viewingPublicKey(),
          paid,
          inboxTag(other, 0, 0n),
          0,
        ),
        anonymousSlot(owner.viewingKey(), txKey, owner.viewingPublicKey(), change, changeTag, 1),
      ],
    );
    const { client, asked } = indexer({ deposits: [deposit], spends: [spend] });
    const wallet = new Wallet({ identity: owner.shieldedAddress() });
    const { keys, decryptedUnder } = countingKeys(owner);

    const report = await syncWallet({ wallet, keys, client, anonymousRing: freshState });

    expect(unspentHashes(wallet)).toEqual([hex(change.hash)]);
    expect(
      wallet
        .utxos()
        .map((entry) => entry.spent)
        .sort(),
    ).toEqual([false, true]);
    const ring = report.anonymousRing!;
    expect(ring.depositNext).toBe(1n);
    expect(ring.notes.map((entry) => [hex(entry.utxoHash), entry.stream.kind])).toEqual([
      [hex(change.hash), "change"],
    ]);
    expect(ring.newCounterparties).toEqual([]);
    // The recipient slot carries a tag this wallet never derived, only the
    // change slot was opened.
    expect(asked(inboxTag(other, 0, 0n))).toBe(false);
    expect(decryptedUnder).toHaveLength(1);
    expect(wallet.privateTransactions().filter((row) => row.direction === "inbound")).toHaveLength(
      1,
    );
  });

  it("treats a scheme-9 slot whose opening misses the commitment as a failed match", async () => {
    const recipient = keypair(1);
    const payer = keypair(2);
    const spam = inboxPayment(payer, recipient, 0, 0n, 1n, 21);
    const txKey = keypair(21).viewingKey();
    const garbage = encodeOutputData(
      EncryptedScheme.ringAnonymous,
      txKey.sealAnonymousOutput(
        recipient.viewingPublicKey(),
        encodeRingAnonymous({
          assetAddress: address("So11111111111111111111111111111111111111112"),
          amount: 1n,
          blinding: bytes(21),
          pairU: pairPublicKeyOf(payer, recipient).u(),
        }),
        SALT,
        0,
      ),
      "encrypted",
    );
    const spamTx: IndexedShieldedTransaction = {
      ...spam.tx,
      outputSlots: spam.tx.outputSlots.map((slot) => ({ ...slot, payload: garbage })),
    };
    const real = inboxPayment(keypair(3), recipient, 0, 1n, 10n, 11);
    const { client } = indexer({ tagged: [spamTx, real.tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(real.paid.hash)]);
    expect(report.unknownAssetIds).toEqual([]);
    expect(report.pendingAssets).toEqual([]);
    expect(report.anonymousRing?.inboxNext.get(0)).toBe(2n);
  });

  it("stops address discovery a gap past the last used address", async () => {
    const recipient = keypair(1);
    const far = ADDRESS_GAP - 5;
    const near = inboxPayment(keypair(2), recipient, 0, 0n, 10n, 11);
    const farPayment = inboxPayment(keypair(3), recipient, far, 0n, 20n, 12);
    const { client, asked } = indexer({ tagged: [near.tx, farPayment.tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(near.paid.hash), hex(farPayment.paid.hash)].sort());
    expect(report.anonymousRing?.usedAddresses).toBe(far + 1);
    expect(asked(inboxTag(recipient, far + ADDRESS_GAP, 0n))).toBe(true);
    expect(asked(inboxTag(recipient, far + ADDRESS_GAP + 1, 0n))).toBe(false);
  });

  it("scans the issued count whole and a known counterparty from the start", async () => {
    const recipient = keypair(1);
    const payer = keypair(2);
    const far = 2 * ADDRESS_GAP;
    const farPayment = inboxPayment(payer, recipient, far, 0n, 20n, 12);
    const pairPublicKey = pairPublicKeyOf(payer, recipient);
    const paired = note(recipient, 5n, 13);
    const txKey = keypair(13).viewingKey();
    const pairTx = transaction(
      txKey,
      13,
      [bytes(13)],
      [
        anonymousSlot(
          payer.viewingKey(),
          txKey,
          recipient.viewingPublicKey(),
          paired,
          payer.viewingKey().pairSendViewTag(recipient.viewingPublicKey(), 0n),
          0,
        ),
      ],
    );
    const { client } = indexer({ tagged: [farPayment.tx, pairTx] });

    const fresh = new Wallet({ identity: recipient.shieldedAddress() });
    await syncWallet({
      wallet: fresh,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });
    expect(unspentHashes(fresh)).toEqual([]);

    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: { issuedAddresses: far + 1, knownCounterparties: [pairPublicKey] },
    });
    expect(unspentHashes(wallet)).toEqual([hex(farPayment.paid.hash), hex(paired.hash)].sort());
    const ring = report.anonymousRing!;
    expect(ring.newCounterparties).toEqual([]);
    expect(ring.pairNext.map((entry) => [hex(entry.counterparty.toBytes()), entry.next])).toEqual([
      [hex(pairPublicKey.toBytes()), 1n],
    ]);
    expect(ring.usedAddresses).toBe(far + 1);
  });

  it("opens the pair stream of a first contact in the same sync", async () => {
    const recipient = keypair(1);
    const payer = keypair(2);
    const first = inboxPayment(payer, recipient, 0, 0n, 10n, 11);
    const later = note(recipient, 7n, 14);
    const txKey = keypair(14).viewingKey();
    const pairTx = transaction(
      txKey,
      14,
      [bytes(14)],
      [
        anonymousSlot(
          payer.viewingKey(),
          txKey,
          recipient.viewingPublicKey(),
          later,
          payer.viewingKey().pairSendViewTag(recipient.viewingPublicKey(), 0n),
          0,
        ),
      ],
    );
    const { client } = indexer({ tagged: [first.tx, pairTx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(recipient),
      client,
      anonymousRing: freshState,
    });

    expect(unspentHashes(wallet)).toEqual([hex(first.paid.hash), hex(later.hash)].sort());
    const ring = report.anonymousRing!;
    const pairPublicKey = pairPublicKeyOf(payer, recipient);
    expect(ring.newCounterparties.map((key) => hex(key.toBytes()))).toEqual([
      hex(pairPublicKey.toBytes()),
    ]);
    expect(ring.pairNext.map((entry) => entry.next)).toEqual([1n]);
    expect(ring.notes.map((entry) => entry.stream.kind).sort()).toEqual(["inbox", "pair"]);
  });

  it("never decrypts a slot under a tag the wallet did not derive", async () => {
    const recipient = keypair(1);
    const payer = keypair(2);
    const first = inboxPayment(payer, recipient, 0, 0n, 10n, 11);
    const foreign = note(recipient, 99n, 15);
    const txKey = keypair(11).viewingKey();
    const tx: IndexedShieldedTransaction = {
      ...first.tx,
      outputSlots: [
        ...first.tx.outputSlots,
        anonymousSlot(
          payer.viewingKey(),
          txKey,
          recipient.viewingPublicKey(),
          foreign,
          bytes(9),
          1,
        ),
      ],
    };
    const { client, asked } = indexer({ tagged: [tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const { keys, decryptedUnder } = countingKeys(recipient);

    await syncWallet({ wallet, keys, client, anonymousRing: freshState });

    expect(unspentHashes(wallet)).toEqual([hex(first.paid.hash)]);
    expect(decryptedUnder.map((key) => hex(key.toBytes()))).toEqual([
      hex(recipient.viewingPublicKey().toBytes()),
    ]);
    expect(asked(bytes(9))).toBe(false);
  });

  it("recovers a note under a tag the wallet never derived from ring history through a head", async () => {
    const recipient = keypair(1);
    const payer = keypair(2);
    const lost = note(recipient, 99n, 15);
    const txKey = keypair(15).viewingKey();
    const lostTx = transaction(
      txKey,
      15,
      [bytes(15)],
      [anonymousSlot(payer.viewingKey(), txKey, recipient.viewingPublicKey(), lost, bytes(9), 0)],
    );
    const later = inboxPayment(payer, recipient, 0, 0n, 5n, 40);
    const history = [lostTx, later.tx];
    let pages = 0;
    const client = syncReads({
      getShieldedTransactionsByTags: async (request) => {
        pages++;
        expect(request.ringProgramId).toBe(RING);
        expect(request.tags).toEqual([]);
        return { context: CONTEXT, transactions: history, scannedThrough: Uint8Array.of(1) };
      },
    });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(recipient);

    const partial = await recoverAnonymousRing({
      wallet,
      keys,
      client,
      ringProgramId: RING,
      head: 20n,
    });
    expect(partial.scannedTransactions).toBe(1);
    expect(unspentHashes(wallet)).toEqual([hex(lost.hash)]);

    const full = await recoverAnonymousRing({
      wallet,
      keys,
      client,
      ringProgramId: RING,
      head: 40n,
    });
    expect(full.scannedTransactions).toBe(2);
    expect(full.head).toBe(40n);
    expect(unspentHashes(wallet)).toEqual([hex(lost.hash), hex(later.paid.hash)].sort());
    expect(pages).toBe(2);
  });

  it("fails recovery on a page limit and on a cursor that does not advance", async () => {
    const recipient = keypair(1);
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(recipient);
    const endless = syncReads({
      getShieldedTransactionsByTags: async () => ({
        context: CONTEXT,
        transactions: [],
        nextCursor: Uint8Array.of(1),
      }),
    });
    await expect(
      recoverAnonymousRing({
        wallet,
        keys,
        client: endless,
        ringProgramId: RING,
        head: 1n,
        maxPages: 1,
      }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC", causeCode: "WALLET_RECOVERY_INCOMPLETE" });
    let cursor = 0;
    const stuck = syncReads({
      getShieldedTransactionsByTags: async () => ({
        context: CONTEXT,
        transactions: [],
        nextCursor: Uint8Array.of(cursor++ === 0 ? 1 : 1),
      }),
    });
    await expect(
      recoverAnonymousRing({ wallet, keys, client: stuck, ringProgramId: RING, head: 1n }),
    ).rejects.toMatchObject({ causeCode: "WALLET_RECOVERY_INCOMPLETE" });
    const unframed = syncReads({
      getShieldedTransactionsByTags: async () => ({ context: CONTEXT, transactions: [] }),
    });
    await expect(
      recoverAnonymousRing({ wallet, keys, client: unframed, ringProgramId: RING, head: 1n }),
    ).rejects.toMatchObject({ causeCode: "WALLET_RECOVERY_INCOMPLETE" });
    expect(wallet.utxos()).toEqual([]);
  });

  it("leaves scheme-9 slots closed without routes and without a state", async () => {
    const recipient = keypair(1);
    const first = inboxPayment(keypair(2), recipient, 0, 0n, 10n, 11);
    const { client, queried } = indexer({ tagged: [first.tx] });
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(recipient);

    const report = await syncWallet({ wallet, keys, client });
    expect(report.anonymousRing).toBeUndefined();
    expect(wallet.utxos()).toEqual([]);
    expect(queried).toHaveLength(1);

    const direct = await decryptTransactions({ wallet, keys, transactions: [first.tx] });
    expect(direct.storedUtxos).toBe(0);
    expect(wallet.utxos()).toEqual([]);

    const routes = new AnonymousTagRoutes();
    routes.route(inboxTag(recipient, 0, 0n), recipient.viewingPublicKey(), {
      kind: "inbox",
      addressIndex: 0,
    });
    const routed = await decryptTransactions({
      wallet,
      keys,
      transactions: [first.tx],
      anonymous: routes,
    });
    expect(routed.storedUtxos).toBe(1);
    expect(routes.notes().map((entry) => hex(entry.utxoHash))).toEqual([hex(first.paid.hash)]);
  });
});
