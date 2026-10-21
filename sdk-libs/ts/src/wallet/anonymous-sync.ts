import type { IndexerReader } from "../client/ports.js";
import { DEFAULT_INDEXER_RPC_CONFIG, type IndexerRpcConfig } from "../client/retry.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type { Address, Bytes16, Bytes31, Bytes32, RequestContext } from "../interface/types.js";
import {
  BODY_LEN,
  J_INBOX,
  K_PAIR_EPOCHS,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  ringTagField,
  ringTagFromOwnerTag,
  tagEpoch,
  tagIndex,
  type TagIndex,
} from "../keypair/ring-stream.js";
import { Pairing, RingAddress } from "../keypair/ring-address.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { X25519PublicKey, isSmallOrder } from "../keypair/x25519.js";
import { TransactionError } from "../transaction/error.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { EncryptedScheme, readOutputData } from "../transaction/serialization/codecs.js";
import type { DepositPayloadDecoder } from "../transaction/serialization/ring-deposit.js";
import {
  openRingDelivery,
  type RingDeliveredNote,
} from "../transaction/serialization/ring-delivered.js";
import type { Utxo } from "../transaction/utxo.js";
import type { AnonymousRingNote, RingDeliveredCandidate } from "../transaction/wallet/anonymous.js";
import {
  AnonymousRingState,
  DEPOSIT_TAG_WINDOW,
  MAX_ISSUED_ADDRESSES,
  type ReceivedAnchor,
  type SentFirstContact,
} from "../transaction/wallet/anonymous-state.js";
import {
  byteAnswers,
  deriveAnswers,
  destroyTransactionKeys,
  ownedDerivations,
  publicKeyAnswers,
  transactionKeyAnswers,
  wipeByteAnswers,
} from "../transaction/wallet/key-batch.js";
import {
  checkKeysIdentity,
  type RingDeliveryRequest,
  type RingKeys,
} from "../transaction/wallet/keys.js";
import type { Wallet } from "../transaction/wallet/state.js";
import {
  mergeOutputUtxo,
  ringDepositNote,
  ringDepositRequest,
} from "../transaction/wallet/sync.js";
import { readMergeOutputBody } from "../transaction/serialization/merge.js";

import {
  collectProoflessDeposits,
  collectShieldedTransactions,
  collectShieldedTransactionsByNullifiers,
} from "./collect.js";
import { WalletError } from "./error.js";
import { bytesKey, equalBytes } from "./internal.js";

/** Tags or nullifiers one indexer request names, Rust `TAGS_PER_REQUEST`. */
const TAGS_PER_REQUEST = Number(PAGE_LIMIT);
/** Tags read per request round, a chunk of epochs fills it. */
const TAGS_PER_ROUND = 4 * TAGS_PER_REQUEST;

export type AnonymousIndexer = Pick<
  IndexerReader,
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
  | "getShieldedTransactionsByTags"
>;

/** What one scan of one anonymous ring read. */
export interface AnonymousRingScan {
  /** Complete through two epochs before the lower of the open and the persisted epoch. */
  readonly state: AnonymousRingState;
  readonly notes: readonly AnonymousRingNote[];
  /** Anchors the scan added, each opens a pair stream. */
  readonly anchors: readonly ReceivedAnchor[];
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly deposits: readonly IndexedShieldedTransaction[];
  /** The slots the wallet stores, each with the secret its keys answered, the caller wipes them. */
  readonly candidates: readonly RingDeliveredCandidate[];
  readonly depositTags: readonly Bytes32[];
}

/** One payment's place in its recipient's tag streams. */
export type PaymentStream =
  | Readonly<{ kind: "inbox" }>
  /** Anchored on the sender's live first contact to the address. */
  | Readonly<{ kind: "pair"; contact: SentFirstContact }>;

/** The tag a payment publishes in the epoch its proof binds. */
export interface PaymentTag {
  readonly stream: PaymentStream;
  readonly epoch: bigint;
  readonly index: TagIndex;
  readonly tag: Bytes31;
}

/**
 * Reads the inbox streams of the issued addresses, the pair streams of the
 * live anchors, the deposit stream and the change of the wallet's own spends
 * through `slot`'s epoch, every derivation by `keys`, Rust `AnonymousRingSync`.
 * @internal
 */
export async function scanAnonymousRing(
  input: Readonly<{
    keys: RingKeys;
    indexer: AnonymousIndexer;
    state: AnonymousRingState;
    slot: bigint;
    /** Nullifiers of every note the wallet holds that the ring can spend, their spends carry its change. */
    knownNullifiers: readonly Bytes32[];
    pageLimit: number;
    nextRpcConfig: () => IndexerRpcConfig;
    depositPayloadDecoder?: DepositPayloadDecoder | undefined;
  }>,
  context?: RequestContext,
): Promise<AnonymousRingScan> {
  const scan = new Scan(input, context);
  try {
    await scan.streams();
    // The change frontier starts from every note found, deposits included.
    await scan.deposits();
    await scan.change();
    return scan.finish();
  } catch (cause) {
    scan.wipe();
    throw cause;
  }
}

/** The pair stream of a live first contact the address's rows admit, else the inbox stream, Rust `TagAllocation`. */
export class TagAllocation {
  readonly #indexer: AnonymousIndexer;
  readonly #state: AnonymousRingState;
  readonly #epoch: bigint;
  readonly #config: IndexerRpcConfig | undefined;
  readonly #taken = new Set<string>();
  #paired = false;

  /** `state` is the sender's, its first contacts anchor pair payments. */
  constructor(
    indexer: AnonymousIndexer,
    state: AnonymousRingState,
    epoch: bigint,
    config?: IndexerRpcConfig,
  ) {
    this.#indexer = indexer;
    this.#state = state;
    this.#epoch = epoch;
    this.#config = config;
  }

  /** Refuses with `WALLET_INBOX_STREAM_FULL` once every inbox index of the epoch is used. */
  async allocate(address: RingAddress, context?: RequestContext): Promise<PaymentTag> {
    if (address.ringProgramId !== this.#state.ring)
      throw new WalletError("WALLET_FOREIGN_RING_ADDRESS", {
        details: { addressRing: address.ringProgramId, ring: this.#state.ring },
      });
    const recipient = address.recipient.viewingPublicKey;
    const contact = this.#paired ? undefined : this.#state.firstContact(recipient, this.#epoch);
    if (contact !== undefined && address.pairing.admits(contact.asset, contact.amount)) {
      const pair = pairKey(contact.slotSecret);
      let free: FreeTag | undefined;
      try {
        free = await this.#lowestFree((index) => pairTag(pair, this.#epoch, index), context);
      } finally {
        pair.fill(0);
      }
      if (free !== undefined) {
        this.#paired = true;
        return this.#take({ kind: "pair", contact }, free);
      }
    }
    const inbox = inboxKey(ringIdField(this.#state.ring), recipient);
    const free = await this.#lowestFree((index) => inboxTag(inbox, this.#epoch, index), context);
    if (free === undefined)
      throw new WalletError("WALLET_INBOX_STREAM_FULL", { details: { epoch: this.#epoch } });
    return this.#take({ kind: "inbox" }, free);
  }

  #take(stream: PaymentStream, free: FreeTag): PaymentTag {
    this.#taken.add(bytesKey(free.tag));
    return Object.freeze({ stream, epoch: this.#epoch, ...free });
  }

  /** The lowest index whose tag no output publishes and no earlier payment took. */
  async #lowestFree(
    tagAt: (index: TagIndex) => Bytes31,
    context: RequestContext | undefined,
  ): Promise<FreeTag | undefined> {
    const stream = Array.from({ length: J_INBOX }, (_, at) => {
      const index = tagIndex(at);
      return { index, tag: tagAt(index) };
    });
    const used = new Set<string>();
    const out = new Map<string, IndexedShieldedTransaction>();
    await collectShieldedTransactions(
      {
        indexer: this.#indexer,
        chunk: stream.map(({ tag }) => ringTagField(tag)),
        pageLimit: Number(PAGE_LIMIT),
        nextRpcConfig: () => this.#config ?? DEFAULT_INDEXER_RPC_CONFIG,
        out,
        from: undefined,
      },
      context,
    );
    for (const tx of out.values()) {
      for (const slot of tx.outputSlots) used.add(bytesKey(slot.viewTag));
    }
    return stream.find(
      ({ tag }) => !used.has(bytesKey(ringTagField(tag))) && !this.#taken.has(bytesKey(tag)),
    );
  }
}

type FreeTag = Pick<PaymentTag, "index" | "tag">;

/** The stream position a derived tag stands for. */
interface TagSite {
  readonly tag: Bytes32;
  readonly addressIndex: number;
  readonly epoch: bigint;
  readonly index: TagIndex;
  readonly pair: boolean;
}

/** The public values every delivered slot of one transaction is keyed by. */
interface DeliveryContext {
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
}

class Scan {
  readonly #keys: RingKeys;
  readonly #indexer: AnonymousIndexer;
  readonly #pageLimit: number;
  readonly #nextRpcConfig: () => IndexerRpcConfig;
  readonly #context: RequestContext | undefined;
  readonly #ringId: Bytes32;
  readonly #epochs: readonly bigint[];
  readonly #openEpoch: bigint;
  readonly #knownNullifiers: readonly Bytes32[];
  readonly #depositPayloadDecoder: DepositPayloadDecoder | undefined;
  #state: AnonymousRingState;
  /** The lowest slot the indexer reported persisted, no epoch past it is complete. */
  #indexedSlot: bigint | undefined;
  readonly #notes: AnonymousRingNote[] = [];
  readonly #anchors: ReceivedAnchor[] = [];
  readonly #candidates: RingDeliveredCandidate[] = [];
  /** Every slot secret the scan holds, wiped when it fails and handed to the caller by `finish`. */
  readonly #slotSecrets = new Set<Bytes32>();
  readonly #transactions = new Map<string, IndexedShieldedTransaction>();
  /** Tag reads and spend reads dedupe apart, a spend first read under a tag still carries change. */
  readonly #tagged = new Set<string>();
  readonly #spends = new Set<string>();
  readonly #deposits = new Map<string, IndexedShieldedTransaction>();
  readonly #depositTags: Bytes32[] = [];
  /** Nullifiers of the notes the scan found, their spends carry the next change. */
  readonly #found: Bytes32[] = [];

  constructor(input: Parameters<typeof scanAnonymousRing>[0], context: RequestContext | undefined) {
    this.#keys = input.keys;
    this.#pageLimit = input.pageLimit;
    this.#nextRpcConfig = input.nextRpcConfig;
    this.#context = context;
    this.#state = input.state;
    this.#knownNullifiers = input.knownNullifiers;
    this.#depositPayloadDecoder = input.depositPayloadDecoder;
    this.#ringId = ringIdField(input.state.ring);
    this.#openEpoch = tagEpoch(input.slot);
    const first =
      input.state.scannedEpoch === undefined
        ? input.state.creationEpoch
        : input.state.scannedEpoch + 1n;
    this.#epochs = Array.from(
      { length: first > this.#openEpoch ? 0 : Number(this.#openEpoch - first + 1n) },
      (_, offset) => first + BigInt(offset),
    );
    this.#indexer = this.#observed(input.indexer);
  }

  /** Rounds until no address joins the window and no anchor joins the pair streams. */
  async streams(): Promise<void> {
    const readAddresses = new Set<number>();
    const readAnchors = new Set<string>();
    for (;;) {
      const addresses = Array.from({ length: this.#state.addressWindow() }, (_, at) => at).filter(
        (index) => !readAddresses.has(index),
      );
      const anchors = this.#state.received.filter(
        (anchor) => !readAnchors.has(bytesKey(anchor.pairKey)),
      );
      if (addresses.length === 0 && anchors.length === 0) return;
      const keys = publicKeys(
        await this.#keys.ringAddressKeys(this.#state.ring, addresses, this.#context),
        addresses.length,
      );
      const inboxes = addresses.map((index, at) => ({
        index,
        key: inboxKey(this.#ringId, keys[at]!),
      }));
      const pairs = anchors.map((anchor) => ({ anchor, key: anchor.pairKey }));
      for (const index of addresses) readAddresses.add(index);
      for (const anchor of anchors) readAnchors.add(bytesKey(anchor.pairKey));
      const perChunk = Math.max(
        1,
        Math.floor(TAGS_PER_ROUND / (J_INBOX * Math.max(1, inboxes.length + pairs.length))),
      );
      for (let offset = 0; offset < this.#epochs.length; offset += perChunk) {
        const sites = new Map<string, TagSite>();
        for (const epoch of this.#epochs.slice(offset, offset + perChunk)) {
          for (let at = 0; at < J_INBOX; at++) {
            const index = tagIndex(at);
            for (const inbox of inboxes) {
              const tag = ringTagField(inboxTag(inbox.key, epoch, index));
              sites.set(bytesKey(tag), {
                tag,
                addressIndex: inbox.index,
                epoch,
                index,
                pair: false,
              });
            }
            for (const pair of pairs) {
              if (epoch < pair.anchor.epoch || epoch - pair.anchor.epoch >= K_PAIR_EPOCHS) continue;
              const tag = ringTagField(pairTag(pair.key, epoch, index));
              sites.set(bytesKey(tag), {
                tag,
                addressIndex: pair.anchor.addressIndex,
                epoch,
                index,
                pair: true,
              });
            }
          }
        }
        if (sites.size === 0) continue;
        const transactions = await this.#byTags([...sites.values()].map((site) => site.tag));
        await this.#openStreams(sites, transactions);
      }
    }
  }

  /** Windows of the deposit stream until one holds no deposit, every deposit note joins the change frontier. */
  async deposits(): Promise<void> {
    let next = this.#state.depositNext;
    for (;;) {
      const counters = Array.from(
        { length: Number(DEPOSIT_TAG_WINDOW) },
        (_, at) => next + BigInt(at),
      );
      const answered = await this.#keys.senderViewTags(counters, this.#context);
      const tags = deriveAnswers(answered, counters.length, () =>
        batchMismatch(counters.length, answered),
      );
      const out = new Map<string, IndexedShieldedTransaction>();
      await collectProoflessDeposits(
        {
          indexer: this.#indexer,
          chunk: tags,
          pageLimit: this.#pageLimit,
          nextRpcConfig: this.#nextRpcConfig,
          out,
          from: undefined,
        },
        this.#context,
      );
      const occupied = new Set(
        [...out.values()].flatMap((tx) => tx.outputSlots.map((slot) => bytesKey(slot.viewTag))),
      );
      const highest = tags.findLastIndex((tag) => occupied.has(bytesKey(tag)));
      if (highest < 0) break;
      for (const [key, tx] of out) this.#deposits.set(key, tx);
      this.#depositTags.push(...tags);
      await this.#openDeposits(
        [...out.values()],
        new Map(tags.map((tag, at) => [bytesKey(tag), counters[at]!])),
      );
      next += BigInt(highest) + 1n;
    }
    this.#state = this.#state.scanned({
      scannedEpoch: this.#state.scannedEpoch,
      depositNext: next,
    });
  }

  /** The wallet's spends in rounds, each round's change notes are spent in the next one. */
  async change(): Promise<void> {
    const changeKey = await this.#keys.ringChangeKey(this.#state.ring, this.#context);
    if (!(changeKey instanceof X25519PublicKey)) throw batchMismatch(1, [changeKey]);
    const viewingPublicKey = this.#keys.address().viewingPublicKey;
    const queried = new Set<string>();
    let frontier = [...this.#knownNullifiers, ...this.#found];
    for (;;) {
      frontier = frontier.filter((nullifier) => {
        const key = bytesKey(nullifier);
        if (queried.has(key)) return false;
        queried.add(key);
        return true;
      });
      if (frontier.length === 0) return;
      const spends = await this.#spending(frontier);
      const before = this.#found.length;
      await this.#openChange(spends, changeKey, viewingPublicKey);
      await this.#openMerges(spends);
      frontier = this.#found.slice(before);
    }
  }

  finish(): AnonymousRingScan {
    let state = this.#state.rememberDecoys(
      [...this.#transactions.values()].flatMap((tx) =>
        tx.outputSlots.map((slot) => ({
          treeId: slot.outputContext.treeId,
          leafIndex: slot.outputContext.leafIndex,
          hash: slot.outputContext.hash,
        })),
      ),
    );
    const indexed = this.#indexedSlot === undefined ? this.#openEpoch : tagEpoch(this.#indexedSlot);
    // A transfer proven in epoch e lands until e + 1 ends, so epoch e completes once e + 1 is persisted.
    const through = (indexed < this.#openEpoch ? indexed : this.#openEpoch) - 2n;
    if (
      through >= state.creationEpoch &&
      (state.scannedEpoch === undefined || state.scannedEpoch < through)
    )
      state = state.scanned({ scannedEpoch: through, depositNext: state.depositNext });
    this.#slotSecrets.clear();
    return Object.freeze({
      state,
      notes: Object.freeze([...this.#notes]),
      anchors: Object.freeze([...this.#anchors]),
      transactions: Object.freeze([...this.#transactions.values()]),
      deposits: Object.freeze([...this.#deposits.values()]),
      candidates: Object.freeze([...this.#candidates]),
      depositTags: Object.freeze([...this.#depositTags]),
    });
  }

  wipe(): void {
    for (const secret of this.#slotSecrets) secret.fill(0);
    this.#slotSecrets.clear();
  }

  /** Every delivered output under a derived tag, an inbox hit within its address's rows anchors a pair stream. */
  async #openStreams(
    sites: ReadonlyMap<string, TagSite>,
    transactions: readonly IndexedShieldedTransaction[],
  ): Promise<void> {
    const hits: Array<
      Readonly<{ tx: IndexedShieldedTransaction; slotIndex: number; site: TagSite }>
    > = [];
    const requests: RingDeliveryRequest[] = [];
    for (const tx of transactions) {
      const delivery = this.#deliveryContext(tx);
      if (delivery === undefined) continue;
      tx.outputSlots.forEach((slot, slotIndex) => {
        const site = sites.get(bytesKey(slot.viewTag));
        if (site === undefined) return;
        hits.push({ tx, slotIndex, site });
        requests.push({
          recipient: { kind: "address", ring: this.#state.ring, index: site.addressIndex },
          txViewingPublicKey: delivery.txViewingPublicKey,
          salt: delivery.salt,
          outputIndex: slotIndex,
          firstNullifier: delivery.firstNullifier,
        });
      });
    }
    if (requests.length === 0) return;
    const secrets = this.#own(
      await this.#keys.ringDeliverySecrets(requests, this.#context),
      requests.length,
    );
    const finds: Array<
      Readonly<{
        note: RingDeliveredNote;
        candidate: RingDeliveredCandidate;
        site: TagSite;
        slotSecret: Bytes32;
      }>
    > = [];
    for (const [at, hit] of hits.entries()) {
      const slotSecret = secrets[at]!;
      const candidate = candidateOf(hit.tx, hit.slotIndex, slotSecret, false);
      const note = this.#open(candidate);
      if (note === undefined) this.#discard(slotSecret);
      else finds.push({ note, candidate, site: hit.site, slotSecret });
    }
    await this.#keep(finds.map(({ note }) => note));
    for (const { note, candidate, site, slotSecret } of finds) {
      this.#candidates.push(candidate);
      this.#notes.push(
        Object.freeze({
          utxoHash: note.utxoHash,
          stream: Object.freeze({
            kind: site.pair ? "pair" : "inbox",
            addressIndex: site.addressIndex,
            epoch: site.epoch,
            index: site.index,
          }),
        }),
      );
      if (site.pair) continue;
      if (!this.#state.issued.some((entry) => entry.index === site.addressIndex))
        this.#state = this.#state.issue(site.addressIndex, this.#state.pairing(site.addressIndex));
      const { asset, amount } = note.utxo;
      if (!this.#state.pairing(site.addressIndex).admits(asset, amount)) continue;
      const key = pairKey(slotSecret);
      try {
        const before = this.#state.received.length;
        this.#state = this.#state.receive({
          addressIndex: site.addressIndex,
          pairKey: key,
          epoch: site.epoch,
          asset,
          amount,
        });
        if (this.#state.received.length !== before)
          this.#anchors.push(this.#state.received.at(-1)!);
      } finally {
        key.fill(0);
      }
    }
  }

  /** Every deposit into the ring under the window's tags, opened with the current viewing key. */
  async #openDeposits(
    deposits: readonly IndexedShieldedTransaction[],
    counters: ReadonlyMap<string, bigint>,
  ): Promise<void> {
    const address = this.#keys.address();
    const opened = deposits.flatMap((tx) =>
      tx.outputSlots.flatMap((slot) => {
        const counter = counters.get(bytesKey(slot.viewTag));
        if (counter === undefined) return [];
        const body = encryptedBody(slot.payload, EncryptedScheme.ringDeposit);
        if (body === undefined) return [];
        const deposit = ringDepositRequest({
          body,
          viewingPublicKey: address.viewingPublicKey,
          decoder: this.#depositPayloadDecoder,
        });
        return deposit === undefined || deposit.output.ringProgramId !== this.#state.ring
          ? []
          : [{ slot, counter, ...deposit }];
      }),
    );
    if (opened.length === 0) return;
    const answered = await this.#keys.decrypt(
      opened.map(({ request }) => request),
      this.#context,
    );
    const notes: Array<Readonly<{ utxoHash: Bytes32; utxo: Utxo; counter: bigint }>> = [];
    try {
      const plaintexts = byteAnswers(answered, opened.length, () =>
        batchMismatch(opened.length, answered),
      );
      for (const [at, { slot, counter, output }] of opened.entries()) {
        const { hash, treeId } = slot.outputContext;
        try {
          const note = ringDepositNote({
            output,
            plaintext: plaintexts[at]!,
            owner: address.signingPublicKey,
          });
          const rebuilt = note.utxo.hash(
            address.nullifierPublicKey,
            treeId,
            note.dataHash,
            note.ringDataHash,
          );
          if (equalBytes(rebuilt, hash)) notes.push({ utxoHash: hash, utxo: note.utxo, counter });
        } catch {
          // A plaintext under another key opens no deposit of the wallet.
        }
      }
    } finally {
      wipeByteAnswers(answered);
    }
    await this.#keep(notes);
    for (const { utxoHash, counter } of notes)
      this.#notes.push(
        Object.freeze({ utxoHash, stream: Object.freeze({ kind: "deposit", counter }) }),
      );
  }

  /** The sender agrees with its own change key from the re-derived transaction key. */
  async #openChange(
    spends: readonly IndexedShieldedTransaction[],
    changeKey: X25519PublicKey,
    viewingPublicKey: X25519PublicKey,
  ): Promise<void> {
    const own = spends.flatMap((tx) => {
      const delivery = this.#deliveryContext(tx);
      return delivery === undefined ? [] : [{ tx, delivery }];
    });
    if (own.length === 0) return;
    const answered = await this.#keys.transactionKeys(
      own.map(({ delivery }) => ({ viewingPublicKey, firstNullifier: delivery.firstNullifier })),
      this.#context,
    );
    const finds: Array<
      Readonly<{
        note: RingDeliveredNote;
        candidate: RingDeliveredCandidate;
        firstNullifier: Bytes32;
      }>
    > = [];
    try {
      const txKeys = transactionKeyAnswers(answered, own.length, () =>
        batchMismatch(own.length, answered),
      );
      for (const [at, { tx, delivery }] of own.entries()) {
        const txKey = txKeys[at]!;
        // Another holder of the spent note signed it, its outputs are not the wallet's change.
        if (!txKey.publicKey().equals(delivery.txViewingPublicKey)) continue;
        const agreement = txKey.ecdh(changeKey);
        try {
          for (const [slotIndex, slot] of tx.outputSlots.entries()) {
            if (encryptedBody(slot.payload, EncryptedScheme.ringAnonymous) === undefined) continue;
            const slotSecret = deliveredSlotSecret({
              agreement,
              txViewingKey: delivery.txViewingPublicKey,
              recipientViewingKey: changeKey,
              salt: delivery.salt,
              outputIndex: slotIndex,
              firstNullifier: delivery.firstNullifier,
            });
            this.#slotSecrets.add(slotSecret);
            const candidate = candidateOf(tx, slotIndex, slotSecret, true);
            const note = this.#open(candidate);
            if (note === undefined) this.#discard(slotSecret);
            else finds.push({ note, candidate, firstNullifier: delivery.firstNullifier });
          }
        } finally {
          agreement.fill(0);
        }
      }
    } finally {
      destroyTransactionKeys(answered);
    }
    await this.#keep(finds.map(({ note }) => note));
    for (const { note, candidate, firstNullifier } of finds) {
      this.#candidates.push(candidate);
      this.#notes.push(
        Object.freeze({
          utxoHash: note.utxoHash,
          stream: Object.freeze({ kind: "change", firstNullifier }),
        }),
      );
    }
  }

  /** The wallet's own merges among its spends, each merged note joins the frontier like change. */
  async #openMerges(spends: readonly IndexedShieldedTransaction[]): Promise<void> {
    const merges = spends.flatMap((tx) => {
      const [firstNullifier] = tx.nullifiers;
      if (tx.ringProgramId !== this.#state.ring || firstNullifier === undefined) return [];
      return tx.outputSlots.flatMap((slot) => {
        const body = readMergeOutputBody(slot.payload);
        return body?.ringDataHash === undefined ? [] : [{ slot, body, firstNullifier }];
      });
    });
    if (merges.length === 0) return;
    const address = this.#keys.address();
    const answers = await this.#keys.derive(
      merges.flatMap(({ firstNullifier }) => [
        { kind: "mergeOutputKey" as const, firstNullifier },
        { kind: "mergeOutputBlinding" as const, firstNullifier },
      ]),
      this.#context,
    );
    const notes: Array<Readonly<{ utxoHash: Bytes32; utxo: Utxo; firstNullifier: Bytes32 }>> = [];
    try {
      const derived = deriveAnswers(answers, 2 * merges.length, () =>
        batchMismatch(2 * merges.length, answers),
      );
      for (const [at, { slot, body, firstNullifier }] of merges.entries()) {
        const { hash, treeId } = slot.outputContext;
        try {
          const utxo = mergeOutputUtxo({
            body,
            key: derived[2 * at]!,
            blinding: derived[2 * at + 1]!,
            owner: address.signingPublicKey,
            ringProgramId: this.#state.ring,
          });
          const rebuilt = utxo.hash(
            address.nullifierPublicKey,
            treeId,
            undefined,
            body.ringDataHash,
          );
          if (equalBytes(rebuilt, hash)) notes.push({ utxoHash: hash, utxo, firstNullifier });
        } catch {
          // Another wallet's merge decrypts to noise.
        }
      }
    } finally {
      wipeByteAnswers(answers);
    }
    await this.#keep(notes);
    for (const { utxoHash, firstNullifier } of notes)
      this.#notes.push(
        Object.freeze({ utxoHash, stream: Object.freeze({ kind: "merge", firstNullifier }) }),
      );
  }

  /** Opens one candidate to learn its note, the wallet stores it in the sync pass. */
  #open(candidate: RingDeliveredCandidate): RingDeliveredNote | undefined {
    const tx = candidate.transaction;
    const slot = tx.outputSlots[candidate.slotIndex];
    const firstNullifier = tx.nullifiers[0];
    if (slot === undefined || firstNullifier === undefined) return undefined;
    const body = encryptedBody(slot.payload, EncryptedScheme.ringAnonymous);
    if (body?.length !== BODY_LEN) return undefined;
    const address = this.#keys.address();
    return openRingDelivery(
      {
        ring: this.#state.ring,
        firstNullifier,
        outputIndex: candidate.slotIndex,
        ...(candidate.tag === undefined ? {} : { tag: candidate.tag }),
      },
      {
        body,
        slotSecret: candidate.slotSecret,
        owner: {
          signingPublicKey: address.signingPublicKey,
          nullifierPublicKey: address.nullifierPublicKey,
        },
        commitment: slot.outputContext.hash,
        treeId: slot.outputContext.treeId,
      },
    );
  }

  /** One batch derives the round's nullifiers, their spends carry the next change. */
  async #keep(notes: readonly Readonly<{ utxoHash: Bytes32; utxo: Utxo }>[]): Promise<void> {
    if (notes.length === 0) return;
    const answers = await this.#keys.derive(
      notes.map(({ utxoHash, utxo }) => ({ kind: "nullifier", utxoHash, blinding: utxo.blinding })),
      this.#context,
    );
    this.#found.push(...ownedAnswers(answers, notes.length));
  }

  #own(answers: unknown, count: number): readonly Bytes32[] {
    const secrets = ownedAnswers(answers, count);
    for (const secret of secrets) this.#slotSecrets.add(secret);
    return secrets;
  }

  #discard(secret: Bytes32): void {
    secret.fill(0);
    this.#slotSecrets.delete(secret);
  }

  /** `undefined` for another ring's transaction, without a key, a salt or an input, or under a low-order key. */
  #deliveryContext(tx: IndexedShieldedTransaction): DeliveryContext | undefined {
    const firstNullifier = tx.nullifiers[0];
    if (
      tx.ringProgramId !== this.#state.ring ||
      tx.txViewingPublicKey === undefined ||
      tx.salt === undefined ||
      firstNullifier === undefined ||
      isSmallOrder(tx.txViewingPublicKey)
    )
      return undefined;
    return { txViewingPublicKey: tx.txViewingPublicKey, salt: tx.salt, firstNullifier };
  }

  async #byTags(tags: readonly Bytes32[]): Promise<readonly IndexedShieldedTransaction[]> {
    const out = new Map<string, IndexedShieldedTransaction>();
    for (let offset = 0; offset < tags.length; offset += TAGS_PER_REQUEST) {
      await collectShieldedTransactions(
        {
          indexer: this.#indexer,
          chunk: tags.slice(offset, offset + TAGS_PER_REQUEST),
          pageLimit: this.#pageLimit,
          nextRpcConfig: this.#nextRpcConfig,
          out,
          from: undefined,
        },
        this.#context,
      );
    }
    return this.#fresh(this.#tagged, out);
  }

  async #spending(nullifiers: readonly Bytes32[]): Promise<readonly IndexedShieldedTransaction[]> {
    const out = new Map<string, IndexedShieldedTransaction>();
    for (let offset = 0; offset < nullifiers.length; offset += TAGS_PER_REQUEST) {
      await collectShieldedTransactionsByNullifiers(
        {
          indexer: this.#indexer,
          chunk: nullifiers.slice(offset, offset + TAGS_PER_REQUEST),
          pageLimit: this.#pageLimit,
          nextRpcConfig: this.#nextRpcConfig,
          out,
        },
        this.#context,
      );
    }
    return this.#fresh(this.#spends, out);
  }

  /** The reads `seen` does not hold yet, each the one object every candidate of its transaction names. */
  #fresh(
    seen: Set<string>,
    out: ReadonlyMap<string, IndexedShieldedTransaction>,
  ): readonly IndexedShieldedTransaction[] {
    const fresh: IndexedShieldedTransaction[] = [];
    for (const [key, tx] of out) {
      if (seen.has(key)) continue;
      seen.add(key);
      const read = this.#transactions.get(key) ?? tx;
      this.#transactions.set(key, read);
      fresh.push(read);
    }
    return fresh;
  }

  /** Every indexer answer reports the slot it persisted, the lowest bounds the complete epochs. */
  #observed(indexer: AnonymousIndexer): AnonymousIndexer {
    const observe = <T extends Readonly<{ context: Readonly<{ slot: bigint }> }>>(
      response: T,
    ): T => {
      const slot = response.context.slot;
      if (this.#indexedSlot === undefined || slot < this.#indexedSlot) this.#indexedSlot = slot;
      return response;
    };
    return {
      getShieldedTransactionsByTags: async (request, config, context) =>
        observe(await indexer.getShieldedTransactionsByTags(request, config, context)),
      getShieldedTransactionsByNullifiers: async (request, config, context) =>
        observe(await indexer.getShieldedTransactionsByNullifiers(request, config, context)),
      getEncryptedUtxosByTags: async (request, config, context) =>
        observe(await indexer.getEncryptedUtxosByTags(request, config, context)),
    };
  }
}

/** Hands out ring address `index`, the next free one by default, the caller persists the wallet before sharing it. */
export async function issueRingAddress(
  input: Readonly<{
    wallet: Wallet;
    keys: RingKeys;
    ring: Address;
    /** The ring config's `creationEpoch`, needed the first time the wallet tracks `ring`. */
    creationEpoch?: bigint;
    index?: number;
    pairing?: Pairing;
  }>,
  context?: RequestContext,
): Promise<RingAddress> {
  return input.wallet._withSyncLock(async () => {
    checkKeysIdentity(input.keys, input.wallet.identity);
    const tracked = input.wallet.anonymousRing(input.ring);
    if (tracked === undefined && input.creationEpoch === undefined)
      throw new WalletError("WALLET_INVALID_RING_DESTINATION", {
        details: { reason: "creationEpoch", ring: input.ring },
      });
    const state = tracked ?? AnonymousRingState.create(input.ring, input.creationEpoch ?? 0n);
    const index = input.index ?? (state.issued.at(-1)?.index ?? -1) + 1;
    const pairing = input.pairing ?? Pairing.any();
    let issued: AnonymousRingState;
    try {
      issued = state.issue(index, pairing);
    } catch (cause) {
      if (
        !(cause instanceof TransactionError) ||
        cause.code !== "TRANSACTION_TOO_MANY_ISSUED_ADDRESSES"
      )
        throw cause;
      throw new WalletError("WALLET_INVALID_ISSUED_ADDRESSES", {
        details: { index, maximum: MAX_ISSUED_ADDRESSES },
        cause,
      });
    }
    const address = await ringAddressOf({ ...input, index, pairing }, context);
    input.wallet._setAnonymousRing(issued);
    return address;
  });
}

/** The address an issued index hands out, its viewing key the per-address one, Rust `AnonymousRingState::address`. */
export async function ringAddressOf(
  input: Readonly<{ keys: RingKeys; ring: Address; index: number; pairing: Pairing }>,
  context?: RequestContext,
): Promise<RingAddress> {
  const keys = publicKeys(await input.keys.ringAddressKeys(input.ring, [input.index], context), 1);
  const address = input.keys.address();
  return new RingAddress({
    recipient: ShieldedAddress.fromPublicKeys(
      address.signingPublicKey,
      address.nullifierPublicKey,
      keys[0]!,
    ),
    ringProgramId: input.ring,
    pairing: input.pairing,
  });
}

/** Each landed inbox payment becomes its address's newest first contact, kept once the caller persists the wallet. */
export async function recordFirstContacts(
  input: Readonly<{ wallet: Wallet; ring: Address; contacts: readonly SentFirstContact[] }>,
): Promise<AnonymousRingState> {
  return input.wallet._withSyncLock(async () => {
    const tracked = input.wallet.anonymousRing(input.ring);
    if (tracked === undefined)
      throw new WalletError("WALLET_INVALID_RING_DESTINATION", {
        details: { reason: "untracked", ring: input.ring },
      });
    const recorded = input.contacts.reduce(
      (state, contact) => state.recordFirstContact(contact),
      tracked,
    );
    input.wallet._setAnonymousRing(recorded);
    return recorded;
  });
}

/** `0x00 ‖ tag` owner tags carry a tag, any other owner tag none. */
function candidateOf(
  transaction: IndexedShieldedTransaction,
  slotIndex: number,
  slotSecret: Bytes32,
  change: boolean,
): RingDeliveredCandidate {
  const viewTag = transaction.outputSlots[slotIndex]?.viewTag;
  const tag = viewTag === undefined ? undefined : ringTagFromOwnerTag(viewTag);
  return Object.freeze({
    transaction,
    slotIndex,
    slotSecret,
    change,
    ...(tag === undefined ? {} : { tag }),
  });
}

/** The body after `scheme`'s byte, `undefined` for any other frame. */
function encryptedBody(payload: Uint8Array, scheme: EncryptedScheme): Uint8Array | undefined {
  try {
    const frame = readOutputData(payload);
    return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
  } catch {
    return undefined;
  }
}

/** A key holder answers once per request with the type the request asks for. */
function batchMismatch(expected: number, answers: unknown): WalletError {
  const actual = Array.isArray(answers) ? answers.length : undefined;
  return new WalletError("WALLET_KEYS_BATCH_MISMATCH", {
    details: {
      expected,
      ...(actual === undefined ? {} : { actual }),
      reason: actual === undefined || actual === expected ? "type" : "count",
    },
  });
}

function ownedAnswers(answers: unknown, count: number): readonly Bytes32[] {
  return ownedDerivations(answers, count, () => batchMismatch(count, answers));
}

function publicKeys(answers: unknown, count: number): readonly X25519PublicKey[] {
  return publicKeyAnswers(answers, count, () => batchMismatch(count, answers));
}
