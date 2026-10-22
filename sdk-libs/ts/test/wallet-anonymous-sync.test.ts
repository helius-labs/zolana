import {
  address,
  getAddressEncoder,
  getBase58Decoder,
  signature,
  type Address,
  type Signature,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type {
  GetByNullifiersRequest,
  GetByTagsRequest,
  GetEncryptedUtxosByTagsResponse,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsByTagsResponse,
} from "../src/client/rpc.js";
import {
  DEFAULT_TREE_ID,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes96,
} from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { encodeRingDepositCapsule } from "../src/interface/ring-deposit-capsule.js";
import { ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey } from "../src/keypair/index.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { Pairing, type RingAddress } from "../src/keypair/ring-address.js";
import {
  EPOCH_SLOTS,
  J_INBOX,
  K_PAIR_EPOCHS,
  TAG_LEN,
  anonymousRingSecret,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  ringTagField,
  sealDeliveredBody,
  tagIndex,
} from "../src/keypair/ring-stream.js";
import type * as RingStream from "../src/keypair/ring-stream.js";
import type * as WalletInternal from "../src/wallet/internal.js";
import { mergeOutputBlinding, mergeOutputKey } from "../src/keypair/merge/index.js";
import { ringOutputBlinding } from "../src/keypair/transact/index.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import type {
  IndexedShieldedTransaction,
  OutputSlot,
} from "../src/transaction/instructions/transact.js";
import { EncryptedScheme, encodeOutputData } from "../src/transaction/serialization/codecs.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { encodeRingDepositPlaintext } from "../src/transaction/serialization/ring-deposit.js";
import { Utxo, ownerUtxoHash } from "../src/transaction/utxo.js";
import {
  ADDRESS_GAP,
  ANCHOR_DECOYS,
  AnonymousRingState,
  DECOYS_PER_TREE,
  MAX_FETCH_EPOCHS,
  MAX_ISSUED_ADDRESSES,
  PAIR_IDLE_EPOCHS,
  type SentFirstContact,
} from "../src/transaction/wallet/anonymous-state.js";
import { LocalShieldedKeys, type RingKeys } from "../src/transaction/wallet/keys.js";
import { Wallet, hex } from "../src/transaction/wallet/state.js";
import { resolvePendingNotes } from "../src/transaction/wallet/sync.js";
import { deserializeWallet, serializeWallet } from "../src/transaction/wallet/persistence.js";
import {
  TagAllocation,
  issueRingAddress,
  recordFirstContacts,
  retireFirstContact,
  ringAddressOf,
  scanAnonymousRing,
  type AnonymousIndexer,
  type PaymentTag,
} from "../src/wallet/anonymous-sync.js";
import { DEFAULT_INDEXER_RPC_CONFIG } from "../src/client/retry.js";
import { PAGE_LIMIT } from "../src/interface/indexer-limits.js";
import { syncWallet, type SyncClient, type SyncWalletConfig } from "../src/wallet/sync.js";
import { decodeRingProgramConfig } from "../src/ring/codecs.js";

import pinVector from "../../../test-vectors/anonymous-ring-state.json" with { type: "json" };
import { ringProgramConfigData } from "./helpers/ring-accounts.js";

const derivedPairKeys = vi.hoisted((): Bytes32[] => []);
vi.mock("../src/keypair/ring-stream.js", async (importOriginal) => {
  const actual = await importOriginal<typeof RingStream>();
  return {
    ...actual,
    pairKey: (secret: Bytes32) => {
      const key = actual.pairKey(secret);
      derivedPairKeys.push(key);
      return key;
    },
  };
});

const keyedBytes = vi.hoisted((): { values: Uint8Array[] | undefined } => ({ values: undefined }));
vi.mock("../src/wallet/internal.js", async (importOriginal) => {
  const actual = await importOriginal<typeof WalletInternal>();
  return {
    ...actual,
    bytesKey: (value: Uint8Array) => {
      keyedBytes.values?.push(value);
      return actual.bytesKey(value);
    },
  };
});

const RING = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const FOREIGN_RING = address("SysvarRent111111111111111111111111111111111");
const UNKNOWN_MINT = address("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
const SECOND_TREE_ID = 1;
const BLOCK_TIME = 1_700_000_000n;
const addressEncoder = getAddressEncoder();
const base58 = getBase58Decoder();
const SOL_ADDRESS = new Uint8Array(addressEncoder.encode(SOL_MINT)) as Bytes32;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** Below the field modulus, a first nullifier no wallet here derives. */
function field(value: number): Bytes32 {
  const out = bytes(value);
  out[0] = 0;
  return out;
}

function freeTag(value: number): Bytes16 {
  return new Uint8Array(TAG_LEN).fill(value) as Bytes16;
}

function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes(seed)));
}

const RECIPIENT = keypair(1);
const SENDER = keypair(2);
const OTHER = keypair(3);

function slotOf(epoch: bigint, offset = 0n): bigint {
  return epoch * EPOCH_SLOTS + 1_000n + offset;
}

/** The last slot of epoch 3. */
const INDEXED = 4n * EPOCH_SLOTS - 1n;

function signatureOf(left: Bytes32, right: Bytes32): Signature {
  return signature(base58.decode(Uint8Array.from([...left, ...right])));
}

function position(at: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, at);
  return out;
}

function offsetOf(cursor: Uint8Array | undefined): number {
  return cursor === undefined
    ? 0
    : new DataView(cursor.buffer, cursor.byteOffset, cursor.byteLength).getUint32(0);
}

/** Photon over one log, a row above the persisted slot is not served yet. */
class Indexer implements SyncClient {
  persisted: bigint;
  readonly #log: IndexedShieldedTransaction[] = [];

  constructor(persisted: bigint) {
    this.persisted = persisted;
  }

  publish(...rows: readonly IndexedShieldedTransaction[]): void {
    this.#log.push(...rows);
    this.#log.sort((left, right) => (left.slot < right.slot ? -1 : left.slot > right.slot ? 1 : 0));
  }

  async getShieldedTransactionsByTags(
    request: GetByTagsRequest,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    const tags = new Set(request.tags.map(hex));
    const page = this.#page(
      request,
      (tx) => !tx.proofless && tx.outputSlots.some((slot) => tags.has(hex(slot.viewTag))),
    );
    return { context: this.#context(), transactions: page.rows, ...page.position };
  }

  async getShieldedTransactionsByNullifiers(
    request: GetByNullifiersRequest,
  ): Promise<GetShieldedTransactionsByNullifiersResponse> {
    const nullifiers = new Set(request.nullifiers.map(hex));
    const page = this.#page(
      request,
      (tx) => !tx.proofless && tx.nullifiers.some((nullifier) => nullifiers.has(hex(nullifier))),
    );
    return { context: this.#context(), transactions: page.rows, ...page.position };
  }

  async getEncryptedUtxosByTags(
    request: GetByTagsRequest,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    const tags = new Set(request.tags.map(hex));
    const tagged = (slot: OutputSlot): boolean => tags.has(hex(slot.viewTag));
    const page = this.#page(request, (tx) => tx.proofless && tx.outputSlots.some(tagged));
    return {
      context: this.#context(),
      matches: page.rows.flatMap((tx) =>
        tx.outputSlots
          .filter(tagged)
          .map((outputSlot) => ({ slot: tx.slot, txSignature: tx.txSignature, outputSlot })),
      ),
      ...page.position,
    };
  }

  #context(): Readonly<{ blockTime: bigint; slot: bigint }> {
    return { blockTime: BLOCK_TIME, slot: this.persisted };
  }

  #page(
    request: Readonly<{ cursor?: Uint8Array; limit?: number }>,
    matches: (tx: IndexedShieldedTransaction) => boolean,
  ): Readonly<{
    rows: IndexedShieldedTransaction[];
    position: Readonly<{ nextCursor: Uint8Array }> | Readonly<{ scannedThrough: Uint8Array }>;
  }> {
    const visible = this.#log.filter((tx) => tx.slot <= this.persisted);
    const limit = request.limit ?? 1_000;
    const rows: IndexedShieldedTransaction[] = [];
    let next = offsetOf(request.cursor);
    for (; next < visible.length && rows.length < limit; next++) {
      const tx = visible[next];
      // Every answer decodes to fresh objects, as a wire client's does.
      if (tx !== undefined && matches(tx)) rows.push({ ...tx });
    }
    return {
      rows,
      position: visible.slice(next).some(matches)
        ? { nextCursor: position(next) }
        : { scannedThrough: position(visible.length) },
    };
  }
}

interface Output {
  readonly to: ShieldedAddress;
  readonly tag: Bytes16;
  readonly amount: bigint;
  readonly mint?: Address;
}

interface Spendable {
  readonly utxo: Utxo;
  readonly hash: Bytes32;
  readonly treeId: number;
  readonly leafIndex: bigint;
}

interface Note extends Spendable {
  readonly slotSecret: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly slotIndex: number;
}

interface Holding {
  readonly hash: string;
  readonly amount: bigint;
  readonly spent: boolean;
}

/** Ring transfers on one indexer, each output a fresh leaf. */
class Chain {
  readonly indexer: Indexer;
  #leaf = 0n;
  #nonce = 0x10;

  constructor(persisted = INDEXED) {
    this.indexer = new Indexer(persisted);
  }

  /** `payer` derives the transaction key from the first nullifier, scheme 9 under each tag. */
  transfer(
    input: Readonly<{
      payer: ViewingKey;
      nullifiers: readonly [Bytes32, ...Bytes32[]];
      epoch: bigint;
      outputs: readonly Output[];
      treeId?: number;
    }>,
  ): readonly Note[] {
    const [firstNullifier] = input.nullifiers;
    const treeId = input.treeId ?? DEFAULT_TREE_ID;
    const txKey = input.payer.transactionViewingKey(firstNullifier);
    const salt = firstNullifier.slice(16) as Bytes16;
    const sealed = input.outputs.map((output, slotIndex) => {
      const agreement = txKey.ecdh(output.to.viewingPublicKey);
      const slotSecret = deliveredSlotSecret({
        agreement,
        txViewingKey: txKey.publicKey(),
        recipientViewingKey: output.to.viewingPublicKey,
        salt,
        outputIndex: slotIndex,
        firstNullifier,
      });
      agreement.fill(0);
      const utxo = new Utxo({
        owner: output.to.signingPublicKey,
        asset: output.mint ?? SOL_MINT,
        amount: output.amount,
        blinding: ringOutputBlinding({
          firstNullifier,
          ringSecret: anonymousRingSecret(slotSecret, output.tag),
          outputIndex: slotIndex,
        }),
        data: new Data(),
        ringProgramId: RING,
      });
      const note: Note = {
        utxo,
        hash: utxo.hash(output.to.nullifierPublicKey, treeId),
        slotSecret,
        firstNullifier,
        slotIndex,
        treeId,
        leafIndex: this.#leaf++,
      };
      const slot: OutputSlot = {
        viewTag: ringTagField(output.tag),
        outputContext: {
          hash: note.hash,
          tree: treeAddress(treeId),
          treeId,
          leafIndex: note.leafIndex,
        },
        payload: encodeOutputData(
          EncryptedScheme.ringAnonymous,
          sealDeliveredBody(slotSecret, {
            assetAddress: new Uint8Array(addressEncoder.encode(output.mint ?? SOL_MINT)) as Bytes32,
            amount: output.amount,
          }),
          "encrypted",
        ),
      };
      return { note, slot };
    });
    this.indexer.publish({
      slot: slotOf(input.epoch, this.#leaf),
      txSignature: signatureOf(firstNullifier, sealed[0]?.note.hash ?? firstNullifier),
      txViewingPublicKey: txKey.publicKey(),
      salt,
      outputSlots: sealed.map(({ slot }) => slot),
      messages: [],
      nullifiers: input.nullifiers,
      proofless: false,
      ringProgramId: RING,
    });
    txKey.destroy();
    return sealed.map(({ note }) => note);
  }

  /** A payment from someone the wallet never spent with. */
  pay(to: RingAddress, tag: Bytes16, amount: bigint, epoch: bigint, payer = SENDER): Note {
    const [note] = this.transfer({
      payer: payer.viewingKey(),
      nullifiers: [field(this.#nonce++)],
      epoch,
      outputs: [{ to: to.recipient, tag, amount }],
    });
    if (note === undefined) throw new TypeError("one output");
    return note;
  }

  /** `owner` spends `note`, its change last. */
  spend(
    owner: ShieldedKeypair,
    note: Spendable,
    outputs: readonly Output[],
    epoch: bigint,
    treeId?: number,
  ): readonly Note[] {
    return this.transfer({
      payer: owner.viewingKey(),
      nullifiers: [owner.nullifier(note.hash, note.utxo.blinding)],
      epoch,
      outputs,
      ...(treeId === undefined ? {} : { treeId }),
    });
  }

  /** `owner` merges `notes` into one ring note sealed under its merge output key. */
  merge(owner: ShieldedKeypair, notes: readonly Spendable[], epoch: bigint): Spendable {
    const nullifiers = notes.map((note) => owner.nullifier(note.hash, note.utxo.blinding));
    const [firstNullifier, ...rest] = nullifiers;
    if (firstNullifier === undefined) throw new TypeError("a merge spends a note");
    const amount = notes.reduce((sum, note) => sum + note.utxo.amount, 0n);
    const salt = new Uint8Array(16).fill(11) as Bytes16;
    const nullifierKey = owner.nullifierKey();
    const utxo = new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: mergeOutputBlinding(nullifierKey, firstNullifier),
      data: new Data(),
      ringProgramId: RING,
    });
    const payload = encodeMergeOutputData({
      salt,
      ciphertext: encryptMergeOutput(
        { amount, mint: SOL_MINT },
        mergeOutputKey(nullifierKey, firstNullifier),
        salt,
      ),
      ringDataHash: new Uint8Array(32) as Bytes32,
    });
    nullifierKey.destroy();
    const merged: Spendable = {
      utxo,
      hash: utxo.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID),
      treeId: DEFAULT_TREE_ID,
      leafIndex: this.#leaf++,
    };
    this.indexer.publish({
      slot: slotOf(epoch, merged.leafIndex),
      txSignature: signatureOf(firstNullifier, merged.hash),
      outputSlots: [
        {
          viewTag: firstNullifier,
          outputContext: {
            hash: merged.hash,
            tree: treeAddress(DEFAULT_TREE_ID),
            treeId: DEFAULT_TREE_ID,
            leafIndex: merged.leafIndex,
          },
          payload,
        },
      ],
      messages: [],
      nullifiers: [firstNullifier, ...rest],
      proofless: false,
      ringProgramId: RING,
    });
    return merged;
  }

  /** Borsh `RingDepositOutput` behind scheme 8. */
  deposit(
    owner: ShieldedKeypair,
    counter: bigint,
    amount: bigint,
    epoch: bigint,
    options: Readonly<{
      frame?: (ciphertext: Uint8Array) => Uint8Array;
      sealedBlinding?: Bytes32;
      ring?: Address;
    }> = {},
  ): Spendable {
    const { frame = (ciphertext: Uint8Array) => ciphertext, sealedBlinding, ring = RING } = options;
    const blinding = field(0x60 + Number(counter));
    const salt = new Uint8Array(16).fill(6) as Bytes16;
    const envelope = ViewingKey.fromBytes(bytes(0x40));
    const utxo = new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding,
      data: new Data([{ kind: "ringData", bytes: new Uint8Array() }]),
      ringProgramId: ring,
    });
    const hash = utxo.hash(owner.nullifierPublicKey(), DEFAULT_TREE_ID);
    const ciphertext = frame(
      envelope.encryptRingDeposit(
        owner.viewingPublicKey(),
        encodeRingDepositPlaintext({
          blinding: sealedBlinding ?? blinding,
          ringData: new Uint8Array(),
        }),
        salt,
      ),
    );
    const amountBytes = new Uint8Array(8);
    new DataView(amountBytes.buffer).setBigUint64(0, amount, true);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, ciphertext.length, true);
    const body = Uint8Array.from([
      ...ownerUtxoHash(owner.ownerHash(), blinding),
      ...SOL_ADDRESS,
      ...amountBytes,
      0,
      ...addressEncoder.encode(ring),
      ...new Uint8Array(32),
      ...envelope.publicKey().toBytes(),
      ...salt,
      ...length,
      ...ciphertext,
    ]);
    envelope.destroy();
    const leafIndex = this.#leaf++;
    this.indexer.publish({
      slot: slotOf(epoch, leafIndex),
      txSignature: signatureOf(hash, hash),
      outputSlots: [
        {
          viewTag: owner.viewingKey().senderViewTag(counter),
          outputContext: {
            hash,
            tree: treeAddress(DEFAULT_TREE_ID),
            treeId: DEFAULT_TREE_ID,
            leafIndex,
          },
          payload: encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted"),
        },
      ],
      messages: [],
      nullifiers: [],
      proofless: true,
    });
    return { utxo, hash, treeId: DEFAULT_TREE_ID, leafIndex };
  }
}

async function ringAddress(
  owner: ShieldedKeypair,
  index: number,
  pairing = Pairing.any(),
  ring: Address = RING,
): Promise<RingAddress> {
  return ringAddressOf({ keys: LocalShieldedKeys.fromKeypair(owner), ring, index, pairing });
}

function inboxTagOf(to: RingAddress, epoch: bigint, index: number): Bytes16 {
  return inboxTag(
    inboxKey(ringIdField(RING), to.recipient.viewingPublicKey),
    epoch,
    tagIndex(index),
  );
}

/** The key the owner's change in the ring is delivered to. */
function changeOf(owner: ShieldedKeypair): ShieldedAddress {
  const key = owner.viewingKey().ringChangeKey(RING);
  try {
    return ShieldedAddress.fromPublicKeys(
      owner.signingPublicKey(),
      owner.nullifierPublicKey(),
      key.publicKey(),
    );
  } finally {
    key.destroy();
  }
}

/** An output to a wallet no test syncs. */
async function elsewhere(amount: bigint, tag: Bytes16): Promise<Output> {
  return { to: (await ringAddress(OTHER, 0)).recipient, tag, amount };
}

/** The sender's record of a confirmed inbox payment. */
function contactOf(
  to: RingAddress,
  note: Note,
  tag: Pick<PaymentTag, "epoch" | "index">,
): SentFirstContact {
  return {
    recipient: to.recipient.viewingPublicKey,
    treeId: note.treeId,
    leafIndex: note.leafIndex,
    utxoHash: note.hash,
    slotSecret: note.slotSecret,
    firstNullifier: note.firstNullifier,
    slotIndex: note.slotIndex,
    epoch: tag.epoch,
    index: tag.index,
    asset: note.utxo.asset,
    amount: note.utxo.amount,
  };
}

function pair<T>(values: readonly T[]): readonly [T, T] {
  const [left, right] = values;
  if (values.length !== 2 || left === undefined || right === undefined)
    throw new TypeError("two outputs");
  return [left, right];
}

function holding(note: Spendable, spent: boolean): Holding {
  return { hash: hex(note.hash), amount: note.utxo.amount, spent };
}

function sorted(values: readonly Holding[]): readonly Holding[] {
  return [...values].sort((left, right) => left.hash.localeCompare(right.hash));
}

function holdings(wallet: Wallet): readonly Holding[] {
  return sorted(
    wallet.utxos().map((entry) => ({
      hash: hex(entry.outputContext.hash),
      amount: entry.utxo.amount,
      spent: entry.spent,
    })),
  );
}

function deliveringKeys(
  owner: ShieldedKeypair,
  answer: (secrets: readonly Bytes32[]) => readonly Bytes32[],
): RingKeys {
  const local = LocalShieldedKeys.fromKeypair(owner);
  return {
    address: () => local.address(),
    viewingPublicKeys: () => local.viewingPublicKeys(),
    decrypt: async (requests) => local.decrypt(requests),
    derive: async (requests) => local.derive(requests),
    transactionKeys: async (requests) => local.transactionKeys(requests),
    ringAddressKeys: async (ring, indexes) => local.ringAddressKeys(ring, indexes),
    ringDeliverySecrets: async (requests) => answer(await local.ringDeliverySecrets(requests)),
    ringChangeKey: async (ring) => local.ringChangeKey(ring),
    senderViewTags: async (counters) => local.senderViewTags(counters),
  };
}

function wiped(buffer: Uint8Array): boolean {
  return buffer.every((byte) => byte === 0);
}

async function sync(
  chain: Chain,
  input: Readonly<{
    wallet?: Wallet;
    keys?: RingKeys;
    slot?: bigint;
    creationEpoch?: bigint;
    config?: SyncWalletConfig;
  }> = {},
) {
  const wallet = input.wallet ?? new Wallet({ identity: RECIPIENT.shieldedAddress() });
  const report = await syncWallet({
    wallet,
    client: chain.indexer,
    keys: input.keys ?? LocalShieldedKeys.fromKeypair(RECIPIENT),
    ...(input.config === undefined ? {} : { config: input.config }),
    anonymousRings: {
      slot: input.slot ?? slotOf(3n),
      start: [{ ring: RING, creationEpoch: input.creationEpoch ?? 0n }],
    },
  });
  const ring = report.anonymousRings?.[0];
  const state = wallet.anonymousRing(RING);
  if (ring === undefined || state === undefined) throw new TypeError("the ring was read");
  return { wallet, ring, state };
}

/** The first free index of every draw, fixtures pin their tags on it. */
const zeros = (length: number): Uint8Array => new Uint8Array(length);

/** `count` leaves of `treeId` a scan could hold, none a first contact here. */
function decoyLeaves(count: number, treeId = DEFAULT_TREE_ID) {
  return Array.from({ length: count }, (_, at) => ({
    treeId,
    leafIndex: 900n + BigInt(at),
    hash: field(0xc0 + at),
  }));
}

/** `state` once a scan held a full decoy set beside every first contact. */
function pinned(state: AnonymousRingState): AnonymousRingState {
  return state
    .rememberDecoys(state.sent.flatMap((contact) => decoyLeaves(ANCHOR_DECOYS, contact.treeId)))
    .pinAnchors();
}

/**
 * A deposit and an inbox payment in `early`, a pair payment and the inbox note spent in `middle`,
 * its change spent in the second tree and the deposit spent in `late`.
 */
async function restoreHistory(early: bigint, middle: bigint, late: bigint) {
  const chain = new Chain();
  const to = await ringAddress(RECIPIENT, 0);
  const change = changeOf(RECIPIENT);
  let sender = AnonymousRingState.create(RING, 0n);

  const deposit = chain.deposit(RECIPIENT, 0n, 11_000n, early);
  const first = new TagAllocation(sender, early).allocate(to, zeros);
  const inbox = chain.pay(to, first.tag, 5_000n, early);
  sender = pinned(sender.recordFirstContact(contactOf(to, inbox, first)));
  const second = new TagAllocation(sender, middle).allocate(to, zeros);
  const paired = chain.pay(to, second.tag, 7_000n, middle);
  const spendInbox = pair(
    chain.spend(
      RECIPIENT,
      inbox,
      [await elsewhere(2_000n, freeTag(0x77)), { to: change, tag: freeTag(1), amount: 3_000n }],
      middle,
    ),
  );
  const spendChange = pair(
    chain.spend(
      RECIPIENT,
      spendInbox[1],
      [await elsewhere(1_000n, freeTag(0x78)), { to: change, tag: freeTag(2), amount: 2_000n }],
      late,
      SECOND_TREE_ID,
    ),
  );
  const spendDeposit = pair(
    chain.spend(
      RECIPIENT,
      deposit,
      [await elsewhere(4_000n, freeTag(0x79)), { to: change, tag: freeTag(3), amount: 7_000n }],
      late,
    ),
  );
  return {
    chain,
    streams: [first.stream.kind, second.stream.kind],
    inbox,
    paired,
    deposit,
    read: [inbox, paired, ...spendInbox, ...spendChange, ...spendDeposit],
    expected: sorted([
      holding(deposit, true),
      holding(inbox, true),
      holding(paired, false),
      holding(spendInbox[1], true),
      holding(spendChange[1], false),
      holding(spendDeposit[1], false),
    ]),
  };
}

describe("restore from seed over three epochs", () => {
  let history: Awaited<ReturnType<typeof restoreHistory>>;
  let restored: Awaited<ReturnType<typeof sync>>;

  beforeAll(async () => {
    history = await restoreHistory(0n, 1n, 2n);
    restored = await sync(history.chain, { slot: slotOf(2n) });
  });

  it("finds every inbox, pair, change and deposit note and the anchor", () => {
    const { wallet, ring, state } = restored;

    expect(history.streams).toEqual(["inbox", "pair"]);
    expect(holdings(wallet)).toEqual(history.expected);
    expect(ring.anchors).toEqual([{ addressIndex: 0, epoch: 0n, asset: SOL_MINT, amount: 5_000n }]);
    expect(state.received.map((anchor) => hex(anchor.pairKey))).toEqual([
      hex(pairKey(history.inbox.slotSecret)),
    ]);
    expect(ring.notes.map((note) => note.stream.kind).sort()).toEqual([
      "change",
      "change",
      "change",
      "deposit",
      "inbox",
      "pair",
    ]);
    expect(ring.notes.find((note) => note.stream.kind === "pair")?.utxoHash).toEqual(
      history.paired.hash,
    );
    expect(ring.notes.find((note) => note.stream.kind === "deposit")).toEqual({
      utxoHash: history.deposit.hash,
      stream: { kind: "deposit", counter: 0n },
    });
    // Epoch 1 stays open while epoch 2 can still land its previous-epoch transfers.
    expect(ring.scannedEpoch).toBe(0n);
    expect(state.depositNext).toBe(1n);
    expect(state.issued.map((entry) => entry.index)).toEqual([0]);
  });

  it("remembers the leaves of every transaction it read per tree, never a deposit's", () => {
    const leaves = (treeId: number) =>
      history.read
        .filter((note) => note.treeId === treeId)
        .map((note) => note.leafIndex)
        .sort((left, right) => (left < right ? -1 : 1));
    const decoys = (treeId: number) =>
      (restored.state.decoys.get(treeId) ?? []).map((leaf) => leaf.leafIndex);

    expect(decoys(DEFAULT_TREE_ID)).toEqual(leaves(DEFAULT_TREE_ID));
    expect(decoys(SECOND_TREE_ID)).toEqual(leaves(SECOND_TREE_ID));
    expect(decoys(SECOND_TREE_ID)).toHaveLength(2);
    expect(decoys(DEFAULT_TREE_ID)).not.toContain(history.deposit.leafIndex);
  });
});

describe("anonymous ring sync", () => {
  it("syncs through a key holder that forwards only the ring port", async () => {
    const history = await restoreHistory(0n, 0n, 0n);
    const local = LocalShieldedKeys.fromKeypair(RECIPIENT);
    const called = new Set<string>();
    const holder: RingKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: async (requests) => {
        called.add("decrypt");
        return local.decrypt(requests);
      },
      derive: async (requests) => {
        called.add("derive");
        return local.derive(requests);
      },
      transactionKeys: async (requests) => {
        called.add("transactionKeys");
        return local.transactionKeys(requests);
      },
      ringAddressKeys: async (ring, indexes) => {
        called.add("ringAddressKeys");
        return local.ringAddressKeys(ring, indexes);
      },
      ringDeliverySecrets: async (requests) => {
        called.add("ringDeliverySecrets");
        return local.ringDeliverySecrets(requests);
      },
      ringChangeKey: async (ring) => {
        called.add("ringChangeKey");
        return local.ringChangeKey(ring);
      },
      senderViewTags: async (counters) => {
        called.add("senderViewTags");
        return local.senderViewTags(counters);
      },
    };
    const port = Object.keys(holder);
    const exported = Object.getOwnPropertyNames(LocalShieldedKeys.prototype).filter(
      (member) => member !== "constructor" && !port.includes(member),
    );
    expect(exported.length).toBeGreaterThan(0);
    for (const member of exported) expect(member in holder, member).toBe(false);

    const { wallet, ring } = await sync(history.chain, { keys: holder, slot: slotOf(0n) });

    expect(history.streams).toEqual(["inbox", "pair"]);
    expect(holdings(wallet)).toEqual(history.expected);
    expect(ring.anchors).toHaveLength(1);
    expect([...called].sort()).toEqual([
      "decrypt",
      "derive",
      "ringAddressKeys",
      "ringChangeKey",
      "ringDeliverySecrets",
      "senderViewTags",
      "transactionKeys",
    ]);
  });

  it("wipes every slot secret its keys answered once the sync commits", async () => {
    const history = await restoreHistory(0n, 0n, 0n);
    const answered: Bytes32[] = [];
    const keys = deliveringKeys(RECIPIENT, (secrets) => {
      answered.push(...secrets);
      return secrets;
    });

    const { wallet, ring } = await sync(history.chain, { keys, slot: slotOf(0n) });

    expect(holdings(wallet)).toEqual(history.expected);
    expect(ring.anchors).toHaveLength(1);
    expect(answered.length).toBeGreaterThan(0);
    expect(answered.filter((secret) => !wiped(secret))).toEqual([]);
  });

  it("turns no pair key into a string while it reads the pair streams", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const keyed: Uint8Array[] = [];
    keyedBytes.values = keyed;
    try {
      const { state } = await sync(chain, { slot: slotOf(0n) });

      expect(state.received).toHaveLength(1);
      expect(keyed).not.toContainEqual(state.received[0]!.pairKey);
    } finally {
      keyedBytes.values = undefined;
    }
  });

  it.each([
    ["one secret short", "count", (secrets: readonly Bytes32[]) => secrets.slice(1)],
    [
      "a secret of 31 bytes",
      "type",
      (secrets: readonly Bytes32[]) => [
        new Uint8Array(secrets[0]!.subarray(0, 31)) as Bytes32,
        ...secrets.slice(1),
      ],
    ],
  ] as const)(
    "refuses a slot secret batch %s, wipes every answered secret and changes nothing",
    async (_, reason, malformed) => {
      const chain = new Chain();
      const to = await ringAddress(RECIPIENT, 0);
      chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
      chain.pay(to, inboxTagOf(to, 0n, 1), 7_000n, 0n);
      const returned: Bytes32[] = [];
      const keys = deliveringKeys(RECIPIENT, (secrets) => {
        const answer = malformed(secrets);
        returned.push(...answer);
        return answer;
      });
      const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
      const before = serializeWallet(wallet);

      await expect(sync(chain, { wallet, keys, slot: slotOf(0n) })).rejects.toMatchObject({
        code: "WALLET_SYNC",
        causeCode: "WALLET_KEYS_BATCH_MISMATCH",
        cause: { details: { reason } },
      });
      expect(returned.length).toBeGreaterThan(0);
      expect(returned.filter((secret) => !wiped(secret))).toEqual([]);
      expect(serializeWallet(wallet)).toBe(before);
    },
  );

  it("refuses a slot secret answer that is no list as a type mismatch", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const keys = LocalShieldedKeys.fromKeypair(RECIPIENT);
    Object.defineProperty(keys, "ringDeliverySecrets", { value: async () => ({}) });

    await expect(sync(chain, { keys, slot: slotOf(0n) })).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_KEYS_BATCH_MISMATCH",
      cause: { details: { expected: 1, reason: "type" } },
    });
  });

  it("wipes the slot secrets of a scan a later answer refuses and changes nothing", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const answered: Bytes32[] = [];
    const keys: RingKeys = {
      ...deliveringKeys(RECIPIENT, (secrets) => {
        answered.push(...secrets);
        return secrets;
      }),
      derive: async () => [],
    };
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
    const before = serializeWallet(wallet);

    await expect(sync(chain, { wallet, keys, slot: slotOf(0n) })).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_KEYS_BATCH_MISMATCH",
    });
    expect(answered).toHaveLength(1);
    expect(answered.filter((secret) => !wiped(secret))).toEqual([]);
    expect(serializeWallet(wallet)).toBe(before);
  });

  it("reports only the deposits into its own ring under its deposit tags", async () => {
    const chain = new Chain();
    chain.deposit(RECIPIENT, 0n, 1_000n, 0n, { ring: FOREIGN_RING });
    const kept = chain.deposit(RECIPIENT, 1n, 2_000n, 0n);

    const { ring, state } = await sync(chain, { slot: slotOf(0n) });

    expect(ring.notes).toEqual([{ utxoHash: kept.hash, stream: { kind: "deposit", counter: 1n } }]);
    expect(state.depositNext).toBe(2n);
  });

  it("keeps a note of an unregistered mint pending through syncs that read no chain, then admits it", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const [note] = chain.transfer({
      payer: SENDER.viewingKey(),
      nullifiers: [field(0x41)],
      epoch: 0n,
      outputs: [
        { to: to.recipient, tag: inboxTagOf(to, 0n, 0), amount: 5_000n, mint: UNKNOWN_MINT },
      ],
    });
    if (note === undefined) throw new TypeError("one output");
    const keys = LocalShieldedKeys.fromKeypair(RECIPIENT);

    const first = await sync(chain, { keys, slot: slotOf(0n) });
    const again = await sync(chain, { wallet: first.wallet, keys, slot: slotOf(0n) });

    expect(again.wallet.utxos()).toEqual([]);
    expect(again.wallet.pendingNotes().map((pending) => pending.outputContext.hash)).toEqual([
      note.hash,
    ]);
    again.wallet.ensureAsset(7n, UNKNOWN_MINT);
    const admitted = await resolvePendingNotes({ wallet: again.wallet, keys });
    expect(admitted.map((resolved) => resolved.spent)).toEqual([false]);
    expect(holdings(again.wallet)).toEqual([holding(note, false)]);
    expect(again.wallet.pendingNotes()).toEqual([]);
  });

  it("refuses a malformed first contact, anchor or pairing before copying any secret", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const paid = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const contact = contactOf(to, paid, { epoch: 0n, index: tagIndex(0) });
    const state = AnonymousRingState.create(RING, 0n);
    const contacted = state.recordFirstContact({ ...contact, epoch: 1n });
    const anchor = {
      addressIndex: 0,
      pairKey: field(1),
      epoch: 0n,
      lastEpoch: 0n,
      asset: SOL_MINT,
      amount: 1n,
    };
    const anchored = state.receive(anchor);
    const pairing: Pairing = { rows: [], isOff: () => true, admits: () => false };
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
    const reads: PropertyKey[] = [];
    const watched = (secret: Bytes32) =>
      new Proxy(secret, {
        get: (target, key) => {
          reads.push(key);
          const value: unknown = Reflect.get(target, key);
          return value;
        },
      });

    expect(() =>
      state.recordFirstContact({ ...contact, slotSecret: new Uint8Array(31) as Bytes32 }),
    ).toThrow("TRANSACTION_INVALID_LENGTH");
    expect(() => state.recordFirstContact({ ...contact, slotIndex: 256 })).toThrow(
      "TRANSACTION_INVALID_POSITION",
    );
    expect(() =>
      contacted.recordFirstContact({
        ...contact,
        slotSecret: watched(contact.slotSecret),
        amount: -1n,
      }),
    ).toThrow("TRANSACTION_INVALID_AMOUNT");
    expect(() => anchored.receive({ ...anchor, addressIndex: MAX_ISSUED_ADDRESSES })).toThrow(
      "TRANSACTION_TOO_MANY_ISSUED_ADDRESSES",
    );
    expect(() =>
      state.receive({ ...anchor, pairKey: watched(anchor.pairKey), amount: -1n }),
    ).toThrow("TRANSACTION_INVALID_AMOUNT");
    expect(reads).toEqual([]);
    await expect(
      issueRingAddress({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(RECIPIENT),
        ring: RING,
        creationEpoch: 0n,
        pairing,
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_DESERIALIZE" });
    expect(wallet.anonymousRing(RING)).toBeUndefined();
  });

  it("refuses to issue an address from another wallet's keys and tracks no ring", async () => {
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });

    await expect(
      issueRingAddress({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(OTHER),
        ring: RING,
        creationEpoch: 0n,
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_KEYS_IDENTITY_MISMATCH" });
    expect(wallet.anonymousRing(RING)).toBeUndefined();
  });

  it("opens the ring change of a payment its default-ring note funded", async () => {
    const chain = new Chain();
    const funding = new Utxo({
      owner: RECIPIENT.signingPublicKey(),
      asset: SOL_MINT,
      amount: 9_000n,
      blinding: field(0x52),
      data: new Data(),
    });
    const held: Spendable = {
      utxo: funding,
      hash: funding.hash(RECIPIENT.nullifierPublicKey(), DEFAULT_TREE_ID),
      treeId: DEFAULT_TREE_ID,
      leafIndex: 900n,
    };
    const nullifier = RECIPIENT.nullifier(held.hash, funding.blinding);
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: funding,
          outputContext: { hash: held.hash, tree: treeAddress(DEFAULT_TREE_ID), leafIndex: 900n },
          nullifier,
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const [, change] = pair(
      chain.spend(
        RECIPIENT,
        held,
        [
          await elsewhere(4_000n, freeTag(0x7b)),
          { to: changeOf(RECIPIENT), tag: freeTag(6), amount: 5_000n },
        ],
        0n,
      ),
    );

    const { ring } = await sync(chain, { wallet, slot: slotOf(0n) });

    expect(holdings(wallet)).toEqual(sorted([holding(held, true), holding(change, false)]));
    expect(ring.notes.map((note) => note.stream.kind)).toEqual(["change"]);
  });

  it("asks for an anonymous ring note's nullifier apart from the default and confidential ring ones", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const held = (leafIndex: bigint, ringProgramId?: Address) => {
      const utxo = new Utxo({
        owner: RECIPIENT.signingPublicKey(),
        asset: SOL_MINT,
        amount: 1_000n,
        blinding: field(Number(leafIndex)),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      });
      const hash = utxo.hash(RECIPIENT.nullifierPublicKey(), DEFAULT_TREE_ID);
      return {
        utxo,
        outputContext: { hash, tree: treeAddress(DEFAULT_TREE_ID), leafIndex },
        nullifier: RECIPIENT.nullifier(hash, utxo.blinding),
        spent: false,
      };
    };
    const owned = [held(900n), held(901n, FOREIGN_RING)];
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
    wallet._replace({ utxos: owned, transactions: [], nullifiers: new Set() });
    const requests: string[][] = [];
    const client: SyncClient = {
      getShieldedTransactionsByTags: (request) =>
        chain.indexer.getShieldedTransactionsByTags(request),
      getEncryptedUtxosByTags: (request) => chain.indexer.getEncryptedUtxosByTags(request),
      getShieldedTransactionsByNullifiers: (request) => {
        requests.push(request.nullifiers.map(hex));
        return chain.indexer.getShieldedTransactionsByNullifiers(request);
      },
    };
    const synced = () =>
      syncWallet({
        wallet,
        client,
        keys: LocalShieldedKeys.fromKeypair(RECIPIENT),
        anonymousRings: { slot: slotOf(0n), start: [{ ring: RING, creationEpoch: 0n }] },
      });

    await synced();
    await synced();

    const anonymous = wallet.utxos().find((entry) => entry.utxo.ringProgramId === RING);
    if (anonymous === undefined) throw new Error("the inbox note was read");
    const [plain, confidential] = owned.map((entry) => hex(entry.nullifier));
    const ring = hex(anonymous.nullifier);
    expect(requests.some((names) => names.includes(plain!) && names.includes(confidential!))).toBe(
      true,
    );
    const asked = requests.filter((names) => names.includes(ring));
    expect(asked).not.toEqual([]);
    expect(asked).toEqual(asked.map(() => [ring]));
  });

  it("opens the change of a spend it first read under its own inbox tag", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const own = await ringAddress(RECIPIENT, 1);
    const inbox = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const [self, change] = pair(
      chain.spend(
        RECIPIENT,
        inbox,
        [
          { to: own.recipient, tag: inboxTagOf(own, 0n, 0), amount: 2_000n },
          { to: changeOf(RECIPIENT), tag: freeTag(1), amount: 3_000n },
        ],
        0n,
      ),
    );

    const { wallet, ring } = await sync(chain, { slot: slotOf(0n) });

    expect(holdings(wallet)).toEqual(
      sorted([holding(inbox, true), holding(self, false), holding(change, false)]),
    );
    expect(ring.notes.map((note) => note.stream.kind).sort()).toEqual(["change", "inbox", "inbox"]);
  });

  it("opens deposits under the configured payload framing before reading change", async () => {
    const chain = new Chain();
    const deposit = chain.deposit(RECIPIENT, 0n, 11_000n, 0n, {
      frame: (ciphertext) => Uint8Array.from([0xab, ...ciphertext]),
    });
    const [, change] = pair(
      chain.spend(
        RECIPIENT,
        deposit,
        [
          await elsewhere(4_000n, freeTag(0x79)),
          { to: changeOf(RECIPIENT), tag: freeTag(3), amount: 7_000n },
        ],
        0n,
      ),
    );

    const { wallet, state } = await sync(chain, {
      slot: slotOf(0n),
      config: { depositPayloadDecoder: (framed) => framed.subarray(1) },
    });

    expect(holdings(wallet)).toEqual(sorted([holding(deposit, true), holding(change, false)]));
    expect(state.depositNext).toBe(1n);
  });

  it("passes a deposit with a malformed capsule or a blinding outside the field and keeps its tag", async () => {
    const chain = new Chain();
    const capsule = encodeRingDepositCapsule({
      slotIndex: 0,
      ephemeralPublicKey: new Uint8Array(33) as Bytes33,
      ciphertext: new Uint8Array(96) as Bytes96,
      recipientCiphertext: new Uint8Array(8),
    });
    chain.deposit(RECIPIENT, 0n, 1_000n, 0n, { frame: () => capsule.slice(0, 12) });
    chain.deposit(RECIPIENT, 1n, 2_000n, 0n, {
      sealedBlinding: new Uint8Array(32).fill(0xff) as Bytes32,
    });
    const kept = chain.deposit(RECIPIENT, 2n, 3_000n, 0n);

    const { wallet, state } = await sync(chain, { slot: slotOf(0n) });

    expect(holdings(wallet)).toEqual([holding(kept, false)]);
    expect(state.depositNext).toBe(3n);
  });

  it("finds the note a merge of its own notes lands, on the next sync and on a restore", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const first = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const second = chain.pay(to, inboxTagOf(to, 0n, 1), 7_000n, 0n);
    const { wallet } = await sync(chain, { slot: slotOf(0n) });
    expect(holdings(wallet)).toEqual(sorted([holding(first, false), holding(second, false)]));

    const merged = chain.merge(RECIPIENT, [first, second], 1n);
    const next = await sync(chain, { wallet, slot: slotOf(1n) });
    const expected = sorted([holding(first, true), holding(second, true), holding(merged, false)]);
    expect(holdings(next.wallet)).toEqual(expected);
    expect(next.ring.notes.find((note) => hex(note.utxoHash) === hex(merged.hash))).toEqual({
      utxoHash: merged.hash,
      stream: {
        kind: "merge",
        firstNullifier: RECIPIENT.nullifier(first.hash, first.utxo.blinding),
      },
    });
    const restored = await sync(chain, { slot: slotOf(1n) });
    expect(holdings(restored.wallet)).toEqual(expected);
  });

  it("follows a merged note into the change of its spend in one restore", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const first = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const second = chain.pay(to, inboxTagOf(to, 0n, 1), 7_000n, 0n);
    const merged = chain.merge(RECIPIENT, [first, second], 1n);
    const [, change] = pair(
      chain.spend(
        RECIPIENT,
        merged,
        [
          await elsewhere(2_000n, freeTag(0x7a)),
          { to: changeOf(RECIPIENT), tag: freeTag(4), amount: 10_000n },
        ],
        2n,
      ),
    );

    const { wallet, ring } = await sync(chain, { slot: slotOf(2n) });
    expect(holdings(wallet)).toEqual(
      sorted([
        holding(first, true),
        holding(second, true),
        holding(merged, true),
        holding(change, false),
      ]),
    );
    expect(ring.notes.map((note) => note.stream.kind)).toContain("change");
  });

  it("keeps a note whose transaction another tracked ring's scan reads too", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const elsewhereRing = await ringAddress(RECIPIENT, 0, Pairing.any(), FOREIGN_RING);
    const copied = inboxTag(
      inboxKey(ringIdField(FOREIGN_RING), elsewhereRing.recipient.viewingPublicKey),
      0n,
      tagIndex(0),
    );
    const [note] = chain.transfer({
      payer: SENDER.viewingKey(),
      nullifiers: [field(0x30)],
      epoch: 0n,
      outputs: [
        { to: to.recipient, tag: inboxTagOf(to, 0n, 0), amount: 5_000n },
        { to: elsewhereRing.recipient, tag: copied, amount: 1n },
      ],
    });
    if (note === undefined) throw new TypeError("two outputs");
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });

    const report = await syncWallet({
      wallet,
      client: chain.indexer,
      keys: LocalShieldedKeys.fromKeypair(RECIPIENT),
      anonymousRings: {
        slot: slotOf(0n),
        start: [
          { ring: RING, creationEpoch: 0n },
          { ring: FOREIGN_RING, creationEpoch: 0n },
        ],
      },
    });

    expect(report.anonymousRings?.map((ring) => ring.notes.length)).toEqual([1, 0]);
    expect(holdings(wallet)).toEqual([holding(note, false)]);
  });

  it("marks no epoch the indexer has not persisted, the next sync reads it", async () => {
    const chain = new Chain(slotOf(1n));
    const to = await ringAddress(RECIPIENT, 0);
    const late = chain.pay(to, inboxTagOf(to, 1n, 0), 5_000n, 1n);

    const lagging = await sync(chain, { slot: slotOf(2n) });
    expect(lagging.state.scannedEpoch).toBeUndefined();
    expect(holdings(lagging.wallet)).toEqual([]);

    chain.indexer.persisted = INDEXED;
    const caught = await sync(chain, { wallet: lagging.wallet, slot: slotOf(2n) });
    expect(caught.state.scannedEpoch).toBe(0n);
    expect(holdings(caught.wallet)).toEqual([holding(late, false)]);
  });

  it("reads the open epoch and marks an epoch only once the epoch after it is past", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const open = chain.pay(to, inboxTagOf(to, 1n, 0), 5_000n, 1n);

    const { wallet, state } = await sync(chain, { slot: slotOf(1n) });
    expect(state.scannedEpoch).toBeUndefined();
    expect(holdings(wallet)).toEqual([holding(open, false)]);

    const later = await sync(chain, { wallet, slot: slotOf(3n) });
    expect(later.state.scannedEpoch).toBe(1n);
    expect(holdings(later.wallet)).toEqual([holding(open, false)]);
  });

  it("restores from the epoch its ring config was created in", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const earlier = chain.pay(to, inboxTagOf(to, 1n, 0), 4_000n, 1n);
    const created = chain.pay(to, inboxTagOf(to, 2n, 0), 5_000n, 2n);
    const { creationEpoch } = decodeRingProgramConfig(
      ringProgramConfigData({
        authority: RING,
        auditorPublicKey: X25519Keypair.generate().publicKey().toBytes(),
        bump: 255,
        hasPolicy: false,
        mode: "anonymous",
        createdSlot: slotOf(2n),
      }),
    );

    const restored = await sync(chain, { creationEpoch });
    const fromGenesis = await sync(chain, { creationEpoch: 0n });

    expect(restored.state.creationEpoch).toBe(2n);
    expect(restored.ring.notes.map((note) => note.utxoHash)).toEqual([created.hash]);
    expect(fromGenesis.ring.notes.map((note) => note.utxoHash)).toEqual([
      earlier.hash,
      created.hash,
    ]);
  });

  it("names up to the indexer's request cap of nullifiers whatever the page limit", async () => {
    const chain = new Chain();
    const sizes: number[] = [];
    const indexer: AnonymousIndexer = {
      getEncryptedUtxosByTags: async (request) => chain.indexer.getEncryptedUtxosByTags(request),
      getShieldedTransactionsByTags: async (request) =>
        chain.indexer.getShieldedTransactionsByTags(request),
      getShieldedTransactionsByNullifiers: async (request) => {
        sizes.push(request.nullifiers.length);
        return chain.indexer.getShieldedTransactionsByNullifiers(request);
      },
    };
    const cap = Number(PAGE_LIMIT);
    await scanAnonymousRing({
      keys: LocalShieldedKeys.fromKeypair(RECIPIENT),
      indexer,
      state: AnonymousRingState.create(RING, 0n),
      slot: slotOf(0n),
      heldUtxos: Array.from({ length: cap + 1 }, (_, index) => {
        const nullifier = new Uint8Array(32) as Bytes32;
        new DataView(nullifier.buffer).setUint32(28, index + 1);
        return { ringProgramId: RING, nullifier, utxoHash: field(index + 1) };
      }),
      defaultRingSpends: [],
      pageLimit: 1,
      nextRpcConfig: () => DEFAULT_INDEXER_RPC_CONFIG,
    });
    expect(sizes).toEqual([cap, 1]);
  });

  it("reads the open epoch again while it is the creation epoch", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const open = chain.pay(to, inboxTagOf(to, 1n, 0), 5_000n, 1n);

    const first = await sync(chain, { slot: slotOf(1n), creationEpoch: 1n });
    const again = await sync(chain, { wallet: first.wallet, slot: slotOf(1n), creationEpoch: 1n });

    expect(first.state.scannedEpoch).toBeUndefined();
    expect(again.state.scannedEpoch).toBeUndefined();
    expect(again.ring.notes.map((note) => note.utxoHash)).toEqual([open.hash]);
    expect(holdings(again.wallet)).toEqual([holding(open, false)]);
  });

  it("keeps a tracked ring's creation epoch when a later start names another", async () => {
    const chain = new Chain();
    const { wallet } = await sync(chain, { creationEpoch: 1n });

    const { state } = await sync(chain, { wallet, creationEpoch: 0n });

    expect(state.creationEpoch).toBe(1n);
  });

  it.each([[["mine", "mine"]], [["mine", "theirs"]], [["theirs"]]] as const)(
    "keeps only its own outputs among %j under one inbox tag",
    async (served) => {
      const chain = new Chain();
      const to = await ringAddress(RECIPIENT, 0);
      const foreign = await ringAddress(OTHER, 0);
      const tag = inboxTagOf(to, 0n, 0);
      const mine: Note[] = [];
      for (const [at, kind] of served.entries()) {
        if (kind === "theirs") chain.pay(foreign, tag, 9_000n, 0n, OTHER);
        else mine.push(chain.pay(to, tag, 5_000n + BigInt(at), 0n, at === 0 ? SENDER : OTHER));
      }

      const { wallet, ring, state } = await sync(chain, { slot: slotOf(0n) });

      expect(holdings(wallet)).toEqual(sorted(mine.map((note) => holding(note, false))));
      expect(ring.notes).toHaveLength(mine.length);
      expect(state.received).toHaveLength(mine.length);
    },
  );

  it("skips a delivered body of another length under its inbox tag", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const tag = inboxTagOf(to, 0n, 0);
    const txKey = OTHER.viewingKey().transactionViewingKey(field(0x31));
    chain.indexer.publish({
      slot: slotOf(0n),
      txSignature: signatureOf(field(0x31), field(0x32)),
      txViewingPublicKey: txKey.publicKey(),
      salt: field(0x31).slice(16) as Bytes16,
      outputSlots: [
        {
          viewTag: ringTagField(tag),
          outputContext: {
            hash: field(0x32),
            tree: treeAddress(DEFAULT_TREE_ID),
            treeId: DEFAULT_TREE_ID,
            leafIndex: 100n,
          },
          payload: encodeOutputData(EncryptedScheme.ringAnonymous, new Uint8Array(50), "encrypted"),
        },
      ],
      messages: [],
      nullifiers: [field(0x31)],
      proofless: false,
      ringProgramId: RING,
    });
    txKey.destroy();
    const paid = chain.pay(to, tag, 5_000n, 0n);

    const { wallet, ring } = await sync(chain, { slot: slotOf(0n) });

    expect(holdings(wallet)).toEqual([holding(paid, false)]);
    expect(ring.notes).toHaveLength(1);
  });

  it("reads past the highest issued or used address within the gap", async () => {
    const window = async (paid: readonly number[], issued?: number) => {
      const chain = new Chain();
      const keys = LocalShieldedKeys.fromKeypair(RECIPIENT);
      const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
      if (issued !== undefined)
        await issueRingAddress({ wallet, keys, ring: RING, creationEpoch: 0n, index: issued });
      for (const index of paid) {
        const to = await ringAddress(RECIPIENT, index);
        chain.pay(to, inboxTagOf(to, 0n, 0), 1_000n + BigInt(index), 0n);
      }
      const { state } = await sync(chain, { wallet, keys, slot: slotOf(0n) });
      return {
        found: wallet
          .utxos()
          .map((entry) => Number(entry.utxo.amount - 1_000n))
          .sort((left, right) => left - right),
        issued: state.issued.map((entry) => entry.index),
      };
    };

    expect(await window([ADDRESS_GAP - 1, 2 * ADDRESS_GAP - 1])).toEqual({
      found: [ADDRESS_GAP - 1, 2 * ADDRESS_GAP - 1],
      issued: [ADDRESS_GAP - 1, 2 * ADDRESS_GAP - 1],
    });
    expect(await window([ADDRESS_GAP], 0)).toEqual({
      found: [ADDRESS_GAP],
      issued: [0, ADDRESS_GAP],
    });
    expect(await window([ADDRESS_GAP])).toEqual({ found: [], issued: [] });
  });

  it("refuses an address past the issued maximum and leaves the wallet untouched", async () => {
    const keys = LocalShieldedKeys.fromKeypair(RECIPIENT);
    const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
    const issue = (index: number) =>
      issueRingAddress({ wallet, keys, ring: RING, creationEpoch: 0n, index });

    await expect(issue(MAX_ISSUED_ADDRESSES)).rejects.toMatchObject({
      code: "WALLET_INVALID_ISSUED_ADDRESSES",
      details: { index: MAX_ISSUED_ADDRESSES, maximum: MAX_ISSUED_ADDRESSES },
    });
    expect(wallet.anonymousRing(RING)).toBeUndefined();

    await issue(MAX_ISSUED_ADDRESSES - 1);
    const state = wallet.anonymousRing(RING);
    expect(state?.issued.map((entry) => entry.index)).toEqual([MAX_ISSUED_ADDRESSES - 1]);
    expect(state?.addressWindow()).toBe(MAX_ISSUED_ADDRESSES);
  });

  it("keeps the lowest and highest leaf of a tree and spreads the rest", () => {
    const leaves = Array.from({ length: 3 * DECOYS_PER_TREE }, (_, at) => ({
      treeId: DEFAULT_TREE_ID,
      leafIndex: BigInt(at),
      hash: field(at),
    }));

    const kept = (
      AnonymousRingState.create(RING, 0n).rememberDecoys(leaves).decoys.get(DEFAULT_TREE_ID) ?? []
    ).map((leaf) => leaf.leafIndex);

    expect(kept).toHaveLength(DECOYS_PER_TREE);
    expect(kept[0]).toBe(0n);
    expect(kept.at(-1)).toBe(BigInt(3 * DECOYS_PER_TREE - 1));
    expect(kept).toEqual([...new Set(kept)].sort((left, right) => (left < right ? -1 : 1)));
  });
});

describe("sender tag allocation", () => {
  it("puts the index its random source draws into the inbox tag", async () => {
    const to = await ringAddress(RECIPIENT, 0);
    const allocation = new TagAllocation(AnonymousRingState.create(RING, 0n), 5n);

    expect(allocation.allocate(to, (length) => new Uint8Array(length).fill(5))).toEqual({
      stream: { kind: "inbox" },
      epoch: 5n,
      index: 5,
      tag: inboxTagOf(to, 5n, 5),
    });
  });

  it("never hands one index to two payments of a transaction until every index is taken", async () => {
    const to = await ringAddress(RECIPIENT, 0);
    const allocation = new TagAllocation(AnonymousRingState.create(RING, 0n), 5n);

    const indexes = Array.from({ length: J_INBOX }, () =>
      Number(allocation.allocate(to, zeros).index),
    );
    expect(new Set(indexes).size).toBe(J_INBOX);
    expect(Number(allocation.allocate(to, zeros).index)).toBe(0);
  });

  it.each([
    [1_000n, "pair", 1],
    [999n, "inbox", 0],
  ] as const)(
    "a first contact of %i under a 1000 row takes the %s stream next, the recipient tracks %i pair",
    async (amount, stream, anchors) => {
      const chain = new Chain();
      const keys = LocalShieldedKeys.fromKeypair(RECIPIENT);
      const wallet = new Wallet({ identity: RECIPIENT.shieldedAddress() });
      const to = await issueRingAddress({
        wallet,
        keys,
        ring: RING,
        creationEpoch: 0n,
        index: 0,
        pairing: Pairing.of([{ mint: SOL_MINT, minAmount: 1_000n }]),
      });
      const first = new TagAllocation(AnonymousRingState.create(RING, 0n), 0n).allocate(to, zeros);
      const contact = chain.pay(to, first.tag, amount, 0n);
      const sender = pinned(
        AnonymousRingState.create(RING, 0n).recordFirstContact(contactOf(to, contact, first)),
      );

      const received = await sync(chain, { wallet, keys, slot: slotOf(0n) });
      expect(holdings(received.wallet)).toEqual([holding(contact, false)]);
      expect(received.ring.anchors).toHaveLength(anchors);
      expect(received.state.received).toHaveLength(anchors);

      const next = new TagAllocation(sender, 0n).allocate(to, zeros);
      expect(next.stream.kind).toBe(stream);
      const later = chain.pay(to, next.tag, 2_000n, 0n);
      const caught = await sync(chain, { wallet, keys, slot: slotOf(0n) });
      expect(holdings(caught.wallet)).toEqual(
        sorted([holding(contact, false), holding(later, false)]),
      );
    },
  );

  it("keeps a first contact and its pinned decoys across a save, the next payment pairs on them", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const wallet = new Wallet({ identity: SENDER.shieldedAddress() });
    await expect(recordFirstContacts({ wallet, ring: RING, contacts: [] })).rejects.toMatchObject({
      code: "WALLET_INVALID_RING_DESTINATION",
    });
    await issueRingAddress({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(SENDER),
      ring: RING,
      creationEpoch: 0n,
    });
    const first = new TagAllocation(wallet.anonymousRing(RING)!, 0n).allocate(to, zeros);
    const paid = chain.pay(to, first.tag, 5_000n, 0n);

    const recorded = await recordFirstContacts({
      wallet,
      ring: RING,
      contacts: [contactOf(to, paid, first)],
    });
    wallet._setAnonymousRing(pinned(recorded));
    const restored = deserializeWallet(serializeWallet(wallet)).anonymousRing(RING)!;
    const next = new TagAllocation(restored, 0n).allocate(to, zeros);

    expect(restored.sent.map((contact) => contact.utxoHash)).toEqual([paid.hash]);
    expect(next.stream).toEqual({
      kind: "pair",
      anchor: pinned(recorded).pairAnchor(to.recipient.viewingPublicKey, 0n),
    });
  });

  it("pairs on its own copy of a first contact whose source the caller wiped", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const paid = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const source = contactOf(
      to,
      { ...paid, slotSecret: new Uint8Array(paid.slotSecret) as Bytes32 },
      { epoch: 0n, index: tagIndex(0) },
    );
    const sender = pinned(AnonymousRingState.create(RING, 0n).recordFirstContact(source));
    source.slotSecret.fill(0);

    const next = new TagAllocation(sender, 0n).allocate(to, zeros);

    expect(next.stream.kind).toBe("pair");
    expect(next.tag).toEqual(pairTag(pairKey(paid.slotSecret), 0n, tagIndex(0)));
  });

  it("wipes the pair key it derives for a pair tag", async () => {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const paid = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const sender = pinned(
      AnonymousRingState.create(RING, 0n).recordFirstContact(
        contactOf(to, paid, { epoch: 0n, index: tagIndex(0) }),
      ),
    );
    derivedPairKeys.length = 0;

    const next = new TagAllocation(sender, 0n).allocate(to, zeros);

    expect(next.stream.kind).toBe("pair");
    expect(derivedPairKeys).toHaveLength(1);
    expect(wiped(derivedPairKeys[0]!)).toBe(true);
  });

  it("pairs one payment per transaction and only while the contact lives", async () => {
    const chain = new Chain(slotOf(K_PAIR_EPOCHS + 1n));
    const first = await ringAddress(RECIPIENT, 0);
    const second = await ringAddress(RECIPIENT, 1);
    let sender = AnonymousRingState.create(RING, 0n);
    for (const to of [first, second]) {
      const contact = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
      sender = sender.recordFirstContact(contactOf(to, contact, { epoch: 0n, index: tagIndex(0) }));
    }
    sender = pinned(sender);

    const live = new TagAllocation(sender, PAIR_IDLE_EPOCHS - 1n);
    expect(live.allocate(first, zeros).stream.kind).toBe("pair");
    expect(live.allocate(second, zeros).stream.kind).toBe("inbox");
    const expired = new TagAllocation(sender, PAIR_IDLE_EPOCHS);
    expect(expired.allocate(first, zeros).stream.kind).toBe("inbox");
    const foreign = await ringAddress(RECIPIENT, 0, Pairing.any(), FOREIGN_RING);
    expect(() => live.allocate(foreign, zeros)).toThrow("WALLET_FOREIGN_RING_ADDRESS");
  });
});

describe("first contact decoy pins", () => {
  /** A sender whose inbox payment to address 0 landed in epoch 0. */
  async function contacted() {
    const chain = new Chain();
    const to = await ringAddress(RECIPIENT, 0);
    const paid = chain.pay(to, inboxTagOf(to, 0n, 0), 5_000n, 0n);
    const contact = contactOf(to, paid, { epoch: 0n, index: tagIndex(0) });
    const state = AnonymousRingState.create(RING, 0n).recordFirstContact(contact);
    return { chain, to, contact, state };
  }

  async function scanned(chain: Chain, state: AnonymousRingState): Promise<AnonymousRingState> {
    const scan = await scanAnonymousRing({
      keys: LocalShieldedKeys.fromKeypair(SENDER),
      indexer: chain.indexer,
      state,
      slot: slotOf(0n),
      heldUtxos: [],
      defaultRingSpends: [],
      pageLimit: Number(PAGE_LIMIT),
      nextRpcConfig: () => DEFAULT_INDEXER_RPC_CONFIG,
    });
    return scan.state;
  }

  it("pins a contact's decoys once a scan holds a full set beside the anchor", async () => {
    const { chain, to, contact, state } = await contacted();
    const anchorLeaf = {
      treeId: contact.treeId,
      leafIndex: contact.leafIndex,
      hash: contact.utxoHash,
    };
    const short = await scanned(
      chain,
      state.rememberDecoys([...decoyLeaves(ANCHOR_DECOYS - 1), anchorLeaf]),
    );
    expect(short.pairAnchor(contact.recipient, 0n)).toBeUndefined();
    expect(new TagAllocation(short, 0n).allocate(to, zeros).stream).toEqual({ kind: "inbox" });

    const full = await scanned(chain, short.rememberDecoys(decoyLeaves(ANCHOR_DECOYS)));
    const anchor = full.pairAnchor(contact.recipient, 0n);
    expect(anchor?.leaves.map(hex).sort()).toEqual(
      [...decoyLeaves(ANCHOR_DECOYS).map((leaf) => leaf.hash), contact.utxoHash].map(hex).sort(),
    );
    expect(new TagAllocation(full, 0n).allocate(to, zeros).stream).toEqual({
      kind: "pair",
      anchor,
    });
  });

  it("keeps the pinned leaves as the pool grows, across a save and a repeated record", async () => {
    const { chain, contact, state } = await contacted();
    const first = await scanned(chain, state.rememberDecoys(decoyLeaves(ANCHOR_DECOYS)));
    const anchor = first.pairAnchor(contact.recipient, 0n);
    const grown = await scanned(chain, first.rememberDecoys(decoyLeaves(40)));
    const saved = AnonymousRingState.deserialize(
      JSON.parse(JSON.stringify(grown.serialize())),
      "state",
    );

    expect(anchor).toBeDefined();
    for (const later of [grown, saved, saved.recordFirstContact(contact)])
      expect(later.pairAnchor(contact.recipient, 0n)).toEqual(anchor);
  });

  it("pays the inbox once retired until a fresh first contact lands with its own pin", async () => {
    const { chain, to, contact, state } = await contacted();
    const pinnedOnce = await scanned(chain, state.rememberDecoys(decoyLeaves(ANCHOR_DECOYS)));
    const retired = pinnedOnce.retireFirstContact(contact.recipient);
    expect(retired.firstContact(contact.recipient, 0n)).toBeUndefined();
    expect(new TagAllocation(retired, 0n).allocate(to, zeros).stream).toEqual({ kind: "inbox" });
    const rescanned = await scanned(chain, retired);
    expect(rescanned.firstContact(contact.recipient, 0n)).toBeUndefined();

    const paid = chain.pay(to, inboxTagOf(to, 0n, 1), 5_000n, 0n);
    const fresh = contactOf(to, paid, { epoch: 0n, index: tagIndex(1) });
    const repinned = await scanned(chain, rescanned.recordFirstContact(fresh));
    const anchor = repinned.pairAnchor(contact.recipient, 0n);
    expect(anchor?.contact.utxoHash).toEqual(fresh.utxoHash);
    expect(anchor?.leaves.map(hex)).toContain(hex(fresh.utxoHash));
    expect(new TagAllocation(repinned, 0n).allocate(to, zeros).stream).toEqual({
      kind: "pair",
      anchor,
    });
  });

  it("refuses a stored pin that is no full set of distinct leaves beside the anchor", async () => {
    const { chain, contact, state } = await contacted();
    const stored = (
      await scanned(chain, state.rememberDecoys(decoyLeaves(ANCHOR_DECOYS)))
    ).serialize();
    const [sent] = stored.sent;
    const decoys = sent?.decoys;
    if (sent === undefined || decoys === null || decoys === undefined)
      throw new TypeError("the scan pinned the contact");
    for (const corrupt of [
      decoys.slice(1),
      [...decoys.slice(1), decoys[1]!],
      [...decoys.slice(1), hex(contact.utxoHash)],
    ])
      expect(() =>
        AnonymousRingState.deserialize(
          { ...stored, sent: [{ ...sent, decoys: corrupt }] },
          "state",
        ),
      ).toThrow(expect.objectContaining({ code: "TRANSACTION_DESERIALIZE" }));
  });

  it("retires a wallet's first contact under its sync lock and refuses an untracked ring", async () => {
    const { chain, contact, state } = await contacted();
    const wallet = new Wallet({ identity: SENDER.shieldedAddress() });
    await expect(
      retireFirstContact({ wallet, ring: RING, recipient: contact.recipient }),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_RING_DESTINATION" });
    wallet._setAnonymousRing(
      await scanned(chain, state.rememberDecoys(decoyLeaves(ANCHOR_DECOYS))),
    );
    expect(wallet.anonymousRing(RING)?.pairAnchor(contact.recipient, 0n)).toBeDefined();

    const retired = await retireFirstContact({ wallet, ring: RING, recipient: contact.recipient });

    expect(retired.sent).toEqual([]);
    expect(wallet.anonymousRing(RING)).toBe(retired);
  });

  it("pins the decoys and the read order the shared vector holds", async () => {
    const bytes = (value: string) => new Uint8Array(Buffer.from(value, "hex")) as Bytes32;
    const to = await ringAddress(RECIPIENT, 0);
    const contact: SentFirstContact = {
      recipient: to.recipient.viewingPublicKey,
      treeId: DEFAULT_TREE_ID,
      leafIndex: BigInt(pinVector.anchor.leaf_index),
      utxoHash: bytes(pinVector.anchor.hash),
      slotSecret: bytes(pinVector.slot_secret),
      firstNullifier: field(0x10),
      slotIndex: 0,
      epoch: 0n,
      index: tagIndex(0),
      asset: SOL_MINT,
      amount: 70n,
    };
    const state = AnonymousRingState.create(RING, 0n)
      .recordFirstContact(contact)
      .rememberDecoys(
        pinVector.pool.map((leaf) => ({
          treeId: DEFAULT_TREE_ID,
          leafIndex: BigInt(leaf.leaf_index),
          hash: bytes(leaf.hash),
        })),
      )
      .pinAnchors();

    expect(state.serialize().sent[0]?.decoys).toEqual(pinVector.pinned);
    expect(state.pairAnchor(contact.recipient, 0n)?.leaves.map(hex)).toEqual(pinVector.leaves);
  });

  it("reads at most MAX_FETCH_EPOCHS epochs past the last scanned one", () => {
    const state = AnonymousRingState.create(RING, 0n).scanned({
      scannedEpoch: 2n,
      depositNext: 0n,
    });

    expect(state.fetchEpochs(slotOf(1_000_000n))).toEqual({
      first: 3n,
      open: 3n + MAX_FETCH_EPOCHS - 1n,
    });
    expect(state.fetchEpochs(slotOf(5n))).toEqual({ first: 3n, open: 5n });
    expect(MAX_FETCH_EPOCHS).toBe(1n << 10n);
  });
});
