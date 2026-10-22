import type { IndexerReader } from "../client/ports.js";
import type { IndexerRpcConfig } from "../client/retry.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type { Address, Bytes16, Bytes32, RequestContext } from "../interface/types.js";
import {
  BODY_LEN,
  J_INBOX,
  J_PAIR,
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
import { bytesToBigInt } from "../keypair/bytes.js";
import { U64_MAX } from "../keypair/derivation.js";
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
  DEPOSIT_GAP,
  DEPOSIT_TAG_WINDOW,
  MAX_ISSUED_ADDRESSES,
  pairLiveThrough,
  type PairAnchor,
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
  shieldedTransactionKey,
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
  readonly utxos: readonly AnonymousRingNote[];
  /** Anchors the scan added whose pair stream is still live. */
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
  | Readonly<{ kind: "pair"; anchor: PairAnchor }>;

/** The tag a payment publishes in the epoch its proof binds. */
export interface PaymentTag {
  readonly stream: PaymentStream;
  readonly epoch: bigint;
  readonly index: TagIndex;
  readonly tag: Bytes16;
}

/**
 * Reads the inbox streams of the issued addresses, the pair streams of the
 * live anchors, the deposit stream and the change of the wallet's own spends
 * through `slot`'s epoch, at most `MAX_FETCH_EPOCHS` epochs past the last scanned
 * one, every derivation by `keys`, Rust `AnonymousRingSync`.
 * @internal
 */
export async function scanAnonymousRing(
  input: Readonly<{
    keys: RingKeys;
    indexer: AnonymousIndexer;
    state: AnonymousRingState;
    slot: bigint;
    /** The change scan asks for the nullifiers of the scanned ring's UTXOs among them alone. */
    heldUtxos: readonly HeldUtxo[];
    /** Spends the default-ring sync read, their ring change opens with no nullifier query. */
    defaultRingSpends: readonly IndexedShieldedTransaction[];
    pageLimit: number;
    nextRpcConfig: () => IndexerRpcConfig;
    depositPayloadDecoder?: DepositPayloadDecoder | undefined;
  }>,
  context?: RequestContext,
): Promise<AnonymousRingScan> {
  const scan = new Scan(input, context);
  try {
    await scan.streams();
    // The change frontier starts from every UTXO found, deposits included.
    await scan.deposits();
    await scan.change();
    return scan.finish();
  } catch (cause) {
    scan.wipe();
    throw cause;
  }
}

/** The pair stream of a pinned first contact the address's rows admit, else the inbox stream, Rust `TagAllocation`. */
export class TagAllocation {
  readonly #state: AnonymousRingState;
  readonly #epoch: bigint;
  /** The inbox indexes this transaction took, by inbox key. */
  readonly #taken = new Map<string, Set<number>>();
  #paired = false;

  /** `state` is the sender's, its first contacts anchor pair payments. */
  constructor(state: AnonymousRingState, epoch: bigint) {
    this.#state = state;
    this.#epoch = epoch;
  }

  /** Each index is uniform over the ones this transaction left free, `random` draws it. */
  allocate(address: RingAddress, random: (length: number) => Uint8Array): PaymentTag {
    if (address.ringProgramId !== this.#state.ring)
      throw new WalletError("WALLET_FOREIGN_RING_ADDRESS", {
        details: { addressRing: address.ringProgramId, ring: this.#state.ring },
      });
    const recipient = address.recipient.viewingPublicKey;
    const anchor = this.#paired ? undefined : this.#state.pairAnchor(recipient, this.#epoch);
    if (
      anchor !== undefined &&
      address.pairing.admits(anchor.contact.asset, anchor.contact.amount)
    ) {
      const pair = pairKey(anchor.contact.slotSecret);
      try {
        // One pair slot per transaction, no index of the stream is taken yet.
        const index = draw({ taken: new Set(), size: J_PAIR }, random);
        this.#paired = true;
        const stream: PaymentStream = { kind: "pair", anchor };
        return Object.freeze({
          stream,
          epoch: this.#epoch,
          index,
          tag: pairTag(pair, this.#epoch, index),
        });
      } finally {
        pair.fill(0);
      }
    }
    const inbox = inboxKey(ringIdField(this.#state.ring), recipient);
    const taken = this.#taken.get(bytesKey(inbox)) ?? new Set<number>();
    this.#taken.set(bytesKey(inbox), taken);
    const index = draw({ taken, size: J_INBOX }, random);
    const stream: PaymentStream = { kind: "inbox" };
    return Object.freeze({
      stream,
      epoch: this.#epoch,
      index,
      tag: inboxTag(inbox, this.#epoch, index),
    });
  }
}

/** Uniform over the free indexes below `size`, over all of them once none is free, Rust `TagAllocation::draw`. */
function draw(
  stream: Readonly<{ taken: Set<number>; size: number }>,
  random: (length: number) => Uint8Array,
): TagIndex {
  const { taken, size } = stream;
  const free = Array.from({ length: size }, (_, at) => at).filter((at) => !taken.has(at));
  const pool = free.length === 0 ? Array.from({ length: size }, (_, at) => at) : free;
  const index = pool[uniformBelow(random, pool.length)]!;
  taken.add(index);
  return tagIndex(index);
}

/** A draw past the largest multiple of `bound` is drawn again, the rest are uniform, Rust `uniform_below`. */
function uniformBelow(random: (length: number) => Uint8Array, bound: number): number {
  const range = BigInt(bound);
  const zone = U64_MAX - (U64_MAX % range);
  for (;;) {
    const value = bytesToBigInt(random(8));
    if (value < zone) return Number(value % range);
  }
}

/** The stream position a derived tag stands for. */
interface TagSite {
  readonly tag: Bytes32;
  readonly addressIndex: number;
  readonly epoch: bigint;
  readonly index: TagIndex;
  /** The position of its anchor among the state's received ones, `undefined` on the inbox stream. */
  readonly anchor: number | undefined;
}

/** One address's unread streams of a round, Rust `AddressStreams`. */
interface AddressStreams {
  inbox: Bytes32 | undefined;
  readonly pairs: Readonly<{ anchor: number; key: Bytes32; from: bigint; to: bigint }>[];
}

/** The public values every delivered slot of one transaction is keyed by. */
interface DeliveryContext {
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
}

/** A UTXO the wallet holds, `ringProgramId` `undefined` on the default ring. */
export type HeldUtxo = Readonly<{
  ringProgramId: Address | undefined;
  nullifier: Bytes32;
  utxoHash: Bytes32;
}>;

class Scan {
  readonly #keys: RingKeys;
  readonly #indexer: AnonymousIndexer;
  readonly #pageLimit: number;
  readonly #nextRpcConfig: () => IndexerRpcConfig;
  readonly #context: RequestContext | undefined;
  readonly #ringId: Bytes32;
  readonly #epochs: readonly bigint[];
  readonly #openEpoch: bigint;
  readonly #heldUtxos: readonly HeldUtxo[];
  readonly #defaultRingSpends: readonly IndexedShieldedTransaction[];
  readonly #depositPayloadDecoder: DepositPayloadDecoder | undefined;
  #state: AnonymousRingState;
  /** The lowest slot the indexer reported persisted, no epoch past it is complete. */
  #indexedSlot: bigint | undefined;
  readonly #utxos: AnonymousRingNote[] = [];
  /** Pair keys of the anchors the scan added. */
  readonly #added: Bytes32[] = [];
  readonly #candidates: RingDeliveredCandidate[] = [];
  /** Every slot secret the scan holds, wiped when it fails and handed to the caller by `finish`. */
  readonly #slotSecrets = new Set<Bytes32>();
  readonly #transactions = new Map<string, IndexedShieldedTransaction>();
  readonly #spends = new Set<string>();
  readonly #deposits = new Map<string, IndexedShieldedTransaction>();
  readonly #depositTags: Bytes32[] = [];
  /** A deposit counts once, a replay under a later counter moves nothing. */
  readonly #countedDeposits = new Set<string>();
  /** Nullifiers of the ring's UTXOs the scan found, their spends carry the next change. */
  readonly #found: Bytes32[] = [];

  constructor(input: Parameters<typeof scanAnonymousRing>[0], context: RequestContext | undefined) {
    this.#keys = input.keys;
    this.#pageLimit = input.pageLimit;
    this.#nextRpcConfig = input.nextRpcConfig;
    this.#context = context;
    this.#state = input.state;
    this.#heldUtxos = input.heldUtxos;
    this.#defaultRingSpends = input.defaultRingSpends;
    this.#depositPayloadDecoder = input.depositPayloadDecoder;
    this.#ringId = ringIdField(input.state.ring);
    const { first, open } = input.state.fetchEpochs(input.slot);
    this.#openEpoch = open;
    this.#epochs = Array.from(
      { length: first > open ? 0 : Number(open - first + 1n) },
      (_, offset) => first + BigInt(offset),
    );
    this.#indexer = this.#observed(input.indexer);
  }

  /** Rounds until none adds an address or a live pair epoch, a request names one address. */
  async streams(): Promise<void> {
    const readAddresses = new Set<number>();
    const readThrough: (bigint | undefined)[] = [];
    for (;;) {
      const round = await this.#round(readAddresses, readThrough);
      if (round.size === 0) return;
      for (const [addressIndex, streams] of [...round].sort(([left], [right]) => left - right)) {
        for (const sites of this.#chunks(addressIndex, streams)) {
          const transactions = await this.#byTags([...sites.values()].map((site) => site.tag));
          await this.#openStreams(sites, transactions);
        }
      }
    }
  }

  /** Windows from `depositNext` until `DEPOSIT_GAP` counters past the highest deposit of the wallet in any ring. */
  async deposits(): Promise<void> {
    let next = this.#state.depositNext;
    for (let start = next; start < next + DEPOSIT_GAP; start += DEPOSIT_TAG_WINDOW) {
      const counters = Array.from(
        { length: Number(DEPOSIT_TAG_WINDOW) },
        (_, at) => start + BigInt(at),
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
      for (const [key, tx] of out) this.#deposits.set(key, tx);
      this.#depositTags.push(...tags);
      const highest = await this.#openDeposits(
        [...out.values()],
        new Map(tags.map((tag, at) => [bytesKey(tag), counters[at]!])),
      );
      if (highest !== undefined && highest >= next) next = highest + 1n;
    }
    this.#state = this.#state.scanned({
      scannedEpoch: this.#state.scannedEpoch,
      depositNext: next,
    });
  }

  /** The default-ring spends open first, then every spend of a ring UTXO, round after round. */
  async change(): Promise<void> {
    const changeKey = await this.#keys.ringChangeKey(this.#state.ring, this.#context);
    if (!(changeKey instanceof X25519PublicKey)) throw batchMismatch(1, [changeKey]);
    const viewingPublicKey = this.#keys.address().viewingPublicKey;
    const queried = new Set<string>();
    let frontier = this.#heldUtxos
      .filter((held) => held.ringProgramId === this.#state.ring)
      .map((held) => held.nullifier);
    let spends = this.#fresh(
      this.#spends,
      new Map(this.#defaultRingSpends.map((tx) => [shieldedTransactionKey(tx), tx])),
    );
    for (;;) {
      await this.#openChange(spends, changeKey, viewingPublicKey);
      await this.#openMerges(spends);
      frontier = [...frontier, ...this.#found].filter((nullifier) => {
        const key = bytesKey(nullifier);
        if (queried.has(key)) return false;
        queried.add(key);
        return true;
      });
      if (frontier.length === 0) return;
      spends = await this.#spending(frontier);
      frontier = [];
    }
  }

  finish(): AnonymousRingScan {
    // Only a leaf shaped as a first contact hides one among its decoys.
    let state = this.#state.rememberDecoys(
      [...this.#transactions.values()]
        .filter((tx) => tx.ringProgramId === this.#state.ring)
        .flatMap((tx) =>
          tx.outputSlots
            .filter(
              (slot) =>
                encryptedBody(slot.payload, EncryptedScheme.ringAnonymous)?.length === BODY_LEN,
            )
            .map((slot) => ({
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
    state = state.pruned(this.#openEpoch).pinAnchors();
    this.#slotSecrets.clear();
    return Object.freeze({
      state,
      utxos: Object.freeze([...this.#utxos]),
      anchors: Object.freeze(
        state.received.filter((anchor) =>
          this.#added.some((pairKey) => equalBytes(pairKey, anchor.pairKey)),
        ),
      ),
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

  /** The inbox streams and pair epochs of this fetch no earlier round read, by address, Rust `Scan::round`. */
  async #round(
    readAddresses: Set<number>,
    readThrough: (bigint | undefined)[],
  ): Promise<Map<number, AddressStreams>> {
    const round = new Map<number, AddressStreams>();
    const streamsOf = (addressIndex: number): AddressStreams => {
      const known = round.get(addressIndex);
      if (known !== undefined) return known;
      const created: AddressStreams = { inbox: undefined, pairs: [] };
      round.set(addressIndex, created);
      return created;
    };
    const addresses = Array.from({ length: this.#state.addressWindow() }, (_, at) => at).filter(
      (index) => !readAddresses.has(index),
    );
    if (addresses.length > 0) {
      const keys = publicKeys(
        await this.#keys.ringAddressKeys(this.#state.ring, addresses, this.#context),
        addresses.length,
      );
      for (const [at, index] of addresses.entries()) {
        readAddresses.add(index);
        streamsOf(index).inbox = inboxKey(this.#ringId, keys[at]!);
      }
    }
    const [firstEpoch, lastEpoch] = [this.#epochs[0], this.#epochs.at(-1)];
    if (firstEpoch === undefined || lastEpoch === undefined) return new Map();
    for (const [at, anchor] of this.#state.received.entries()) {
      const through = readThrough[at];
      const from =
        through === undefined
          ? anchor.epoch > firstEpoch
            ? anchor.epoch
            : firstEpoch
          : through + 1n;
      const live = pairLiveThrough(anchor.epoch, anchor.lastEpoch);
      const to = live < lastEpoch ? live : lastEpoch;
      if (from > to) continue;
      readThrough[at] = to;
      streamsOf(anchor.addressIndex).pairs.push({ anchor: at, key: anchor.pairKey, from, to });
    }
    return round;
  }

  /** Whole epochs per chunk, past `TAGS_PER_ROUND` tags only when one epoch alone is. */
  #chunks(addressIndex: number, streams: AddressStreams): ReadonlyMap<string, TagSite>[] {
    const chunks: Map<string, TagSite>[] = [];
    let sites = new Map<string, TagSite>();
    for (const epoch of this.#epochs) {
      const epochSites: TagSite[] = [];
      for (let at = 0; at < J_INBOX && streams.inbox !== undefined; at++) {
        const index = tagIndex(at);
        const tag = ringTagField(inboxTag(streams.inbox, epoch, index));
        epochSites.push({ tag, addressIndex, epoch, index, anchor: undefined });
      }
      for (const pair of streams.pairs) {
        if (epoch < pair.from || epoch > pair.to) continue;
        for (let at = 0; at < J_PAIR; at++) {
          const index = tagIndex(at);
          const tag = ringTagField(pairTag(pair.key, epoch, index));
          epochSites.push({ tag, addressIndex, epoch, index, anchor: pair.anchor });
        }
      }
      if (sites.size > 0 && sites.size + epochSites.length > TAGS_PER_ROUND) {
        chunks.push(sites);
        sites = new Map();
      }
      for (const site of epochSites) sites.set(bytesKey(site.tag), site);
    }
    if (sites.size > 0) chunks.push(sites);
    return chunks;
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
        delivered: RingDeliveredNote;
        candidate: RingDeliveredCandidate;
        site: TagSite;
        slotSecret: Bytes32;
      }>
    > = [];
    for (const [at, hit] of hits.entries()) {
      const slotSecret = secrets[at]!;
      const candidate = candidateOf(hit.tx, hit.slotIndex, slotSecret, false);
      const delivered = this.#open(candidate);
      if (delivered === undefined) this.#discard(slotSecret);
      else finds.push({ delivered, candidate, site: hit.site, slotSecret });
    }
    await this.#keep(finds.map(({ delivered }) => delivered));
    for (const { delivered, candidate, site, slotSecret } of finds) {
      this.#candidates.push(candidate);
      this.#utxos.push(
        Object.freeze({
          utxoHash: delivered.utxoHash,
          stream: Object.freeze({
            kind: site.anchor === undefined ? "inbox" : "pair",
            addressIndex: site.addressIndex,
            epoch: site.epoch,
            index: site.index,
          }),
        }),
      );
      if (site.anchor !== undefined) {
        this.#state = this.#state.anchorPaid(site.anchor, site.epoch);
        continue;
      }
      if (!this.#state.issued.some((entry) => entry.index === site.addressIndex))
        this.#state = this.#state.issue(site.addressIndex, this.#state.pairing(site.addressIndex));
      const { asset, amount } = delivered.utxo;
      if (!this.#state.pairing(site.addressIndex).admits(asset, amount)) continue;
      const key = pairKey(slotSecret);
      try {
        const before = this.#state.received.length;
        this.#state = this.#state.receive({
          addressIndex: site.addressIndex,
          pairKey: key,
          epoch: site.epoch,
          lastEpoch: site.epoch,
          asset,
          amount,
        });
        if (this.#state.received.length !== before)
          this.#added.push(this.#state.received.at(-1)!.pairKey);
      } finally {
        key.fill(0);
      }
    }
  }

  /** Keeps the ring's deposits, the highest counter holding a new deposit of the wallet in any ring. */
  async #openDeposits(
    deposits: readonly IndexedShieldedTransaction[],
    counters: ReadonlyMap<string, bigint>,
  ): Promise<bigint | undefined> {
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
        return deposit === undefined ? [] : [{ slot, counter, ...deposit }];
      }),
    );
    if (opened.length === 0) return undefined;
    const answered = await this.#keys.decrypt(
      opened.map(({ request }) => request),
      this.#context,
    );
    const owned: Array<
      Readonly<{ utxoHash: Bytes32; utxo: Utxo; counter: bigint; ours: boolean }>
    > = [];
    try {
      const plaintexts = byteAnswers(answered, opened.length, () =>
        batchMismatch(opened.length, answered),
      );
      for (const [at, { slot, counter, output }] of opened.entries()) {
        const { hash, treeId } = slot.outputContext;
        try {
          const deposit = ringDepositNote({
            output,
            plaintext: plaintexts[at]!,
            owner: address.signingPublicKey,
          });
          const rebuilt = deposit.utxo.hash(
            address.nullifierPublicKey,
            treeId,
            deposit.dataHash,
            deposit.ringDataHash,
          );
          if (equalBytes(rebuilt, hash))
            owned.push({
              utxoHash: hash,
              utxo: deposit.utxo,
              counter,
              ours: output.ringProgramId === this.#state.ring,
            });
        } catch {
          // A plaintext under another key opens no deposit of the wallet.
        }
      }
    } finally {
      wipeByteAnswers(answered);
    }
    const ours = owned.filter((deposit) => deposit.ours);
    await this.#keep(ours);
    for (const { utxoHash, counter } of ours)
      this.#utxos.push(
        Object.freeze({ utxoHash, stream: Object.freeze({ kind: "deposit", counter }) }),
      );
    const held = new Set(this.#heldUtxos.map((utxo) => bytesKey(utxo.utxoHash)));
    let highest: bigint | undefined;
    // A replay of a held or counted deposit under a later tag moves nothing.
    for (const { utxoHash, counter } of [...owned].sort((left, right) =>
      left.counter < right.counter ? -1 : left.counter > right.counter ? 1 : 0,
    )) {
      const key = bytesKey(utxoHash);
      if (held.has(key) || this.#countedDeposits.has(key)) continue;
      this.#countedDeposits.add(key);
      if (highest === undefined || counter > highest) highest = counter;
    }
    return highest;
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
        delivered: RingDeliveredNote;
        candidate: RingDeliveredCandidate;
        firstNullifier: Bytes32;
      }>
    > = [];
    const signed: IndexedShieldedTransaction[] = [];
    try {
      const txKeys = transactionKeyAnswers(answered, own.length, () =>
        batchMismatch(own.length, answered),
      );
      for (const [at, { tx, delivery }] of own.entries()) {
        const txKey = txKeys[at]!;
        // Another holder of the spent note signed it, its outputs are not the wallet's change.
        if (!txKey.publicKey().equals(delivery.txViewingPublicKey)) continue;
        signed.push(tx);
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
            const delivered = this.#open(candidate);
            if (delivered === undefined) this.#discard(slotSecret);
            else finds.push({ delivered, candidate, firstNullifier: delivery.firstNullifier });
          }
        } finally {
          agreement.fill(0);
        }
      }
    } finally {
      destroyTransactionKeys(answered);
    }
    // An earlier payment extends the window a later one is checked against.
    signed.sort((left, right) => (left.slot < right.slot ? -1 : left.slot > right.slot ? 1 : 0));
    for (const tx of signed) this.#state = this.#state.notePairPayment(tx);
    await this.#keep(finds.map(({ delivered }) => delivered));
    for (const { delivered, candidate, firstNullifier } of finds) {
      this.#candidates.push(candidate);
      this.#utxos.push(
        Object.freeze({
          utxoHash: delivered.utxoHash,
          stream: Object.freeze({ kind: "change", firstNullifier }),
        }),
      );
    }
  }

  /** The wallet's own merges among its spends, each merged UTXO joins the frontier like change. */
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
    const merged: Array<Readonly<{ utxoHash: Bytes32; utxo: Utxo; firstNullifier: Bytes32 }>> = [];
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
          if (equalBytes(rebuilt, hash)) merged.push({ utxoHash: hash, utxo, firstNullifier });
        } catch {
          // Another wallet's merge decrypts to noise.
        }
      }
    } finally {
      wipeByteAnswers(answers);
    }
    await this.#keep(merged);
    for (const { utxoHash, firstNullifier } of merged)
      this.#utxos.push(
        Object.freeze({ utxoHash, stream: Object.freeze({ kind: "merge", firstNullifier }) }),
      );
  }

  /** Opens one candidate to learn its UTXO, the wallet stores it in the sync pass. */
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
  async #keep(utxos: readonly Readonly<{ utxoHash: Bytes32; utxo: Utxo }>[]): Promise<void> {
    if (utxos.length === 0) return;
    const answers = await this.#keys.derive(
      utxos.map(({ utxoHash, utxo }) => ({ kind: "nullifier", utxoHash, blinding: utxo.blinding })),
      this.#context,
    );
    this.#found.push(...ownedAnswers(answers, utxos.length));
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
    return [...out].map(([key, tx]) => this.#read(key, tx));
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

  /** The reads `seen` does not hold yet. */
  #fresh(
    seen: Set<string>,
    out: ReadonlyMap<string, IndexedShieldedTransaction>,
  ): readonly IndexedShieldedTransaction[] {
    const fresh: IndexedShieldedTransaction[] = [];
    for (const [key, tx] of out) {
      if (seen.has(key)) continue;
      seen.add(key);
      fresh.push(this.#read(key, tx));
    }
    return fresh;
  }

  /** The one object every candidate of a transaction names. */
  #read(key: string, tx: IndexedShieldedTransaction): IndexedShieldedTransaction {
    const read = this.#transactions.get(key) ?? tx;
    this.#transactions.set(key, read);
    return read;
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
  return changeAnonymousRing(input, (tracked) =>
    input.contacts.reduce((state, contact) => state.recordFirstContact(contact), tracked),
  );
}

/** The next payment to `recipient` takes its inbox stream, kept once the caller persists the wallet. */
export async function retireFirstContact(
  input: Readonly<{ wallet: Wallet; ring: Address; recipient: X25519PublicKey }>,
): Promise<AnonymousRingState> {
  return changeAnonymousRing(input, (tracked) => tracked.retireFirstContact(input.recipient));
}

async function changeAnonymousRing(
  input: Readonly<{ wallet: Wallet; ring: Address }>,
  change: (tracked: AnonymousRingState) => AnonymousRingState,
): Promise<AnonymousRingState> {
  return input.wallet._withSyncLock(async () => {
    const tracked = input.wallet.anonymousRing(input.ring);
    if (tracked === undefined)
      throw new WalletError("WALLET_INVALID_RING_DESTINATION", {
        details: { reason: "untracked", ring: input.ring },
      });
    const changed = change(tracked);
    input.wallet._setAnonymousRing(changed);
    return changed;
  });
}

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
