import { address, type Address } from "@solana/kit";

import { wireDecoder } from "../../interface/decode.js";
import { sha256 } from "../../interface/internal.js";
import type { Bytes32 } from "../../interface/types.js";
import { concatBytes } from "../../keypair/bytes.js";
import { Pairing } from "../../keypair/ring-address.js";
import {
  J_PAIR,
  K_PAIR_EPOCHS,
  pairKey,
  pairTag,
  ringTagField,
  tagEpoch,
  tagIndex,
  type TagIndex,
} from "../../keypair/ring-stream.js";
import { X25519PublicKey } from "../../keypair/x25519.js";

import { TransactionError } from "../error.js";
import { U64_MAX, checkU64, checked, equal } from "../internal.js";
import { checkedTreeId } from "../utxo.js";
import { hex } from "./state.js";

/** Unused addresses past the highest issued one that a scan still reads. */
export const ADDRESS_GAP = 20;
/** Every scan reads the inbox stream of each issued address, the count bounds its cost. */
export const MAX_ISSUED_ADDRESSES = 1 << 10;
/** Deposit tags read per window. */
export const DEPOSIT_TAG_WINDOW = 64n;
/** Counters a deposit scan reads past the highest holding a deposit of the wallet. */
export const DEPOSIT_GAP = 2n * DEPOSIT_TAG_WINDOW;
/** Epochs a pair stream lives past its last payment, the same at both ends. */
export const PAIR_IDLE_EPOCHS = 8n;
/** Leaves of one tree kept as anchor decoys. */
export const DECOYS_PER_TREE = 64;
/** Decoy paths fetched beside the anchor's, the leaves of its tree a scan already holds, Rust `ANCHOR_DECOYS`. */
export const ANCHOR_DECOYS = 7;
/** Epochs one scan reads, the next scan continues past them, Rust `MAX_FETCH_EPOCHS`. */
export const MAX_FETCH_EPOCHS = 1n << 10n;
/** Rust `ANONYMOUS_RING_STATE_VERSION`, the layout `serialize` writes. */
export const ANONYMOUS_RING_STATE_VERSION = 3;

/** A ring address handed out, the rows its recipient tracks first contacts under. */
export interface IssuedAddress {
  readonly index: number;
  readonly pairing: Pairing;
}

/** A first contact an issued address received, the anchor of a pair stream the wallet scans. */
export interface ReceivedAnchor {
  readonly addressIndex: number;
  readonly pairKey: Bytes32;
  /** The epoch of the first contact's inbox tag. */
  readonly epoch: bigint;
  /** The epoch of the newest pair payment found, `epoch` until one. */
  readonly lastEpoch: bigint;
  readonly asset: Address;
  readonly amount: bigint;
}

/** The newest first contact the wallet paid to one recipient address, the anchor its pair payments prove. */
export interface SentFirstContact {
  /** The recipient address's key, the inbox stream it took derives from it. */
  readonly recipient: X25519PublicKey;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly utxoHash: Bytes32;
  readonly slotSecret: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly slotIndex: number;
  /** The inbox tag's epoch and index. */
  readonly epoch: bigint;
  readonly index: TagIndex;
  readonly asset: Address;
  readonly amount: bigint;
}

/** A leaf the wallet saw in a scan, a candidate decoy beside an anchor's path. */
export interface DecoyLeaf {
  readonly leafIndex: bigint;
  readonly hash: Bytes32;
}

/** A live first contact whose decoys a scan pinned, Rust `PairAnchor`. */
export interface PairAnchor {
  readonly contact: SentFirstContact;
  /** Every read of the anchor names these leaves, in order. */
  readonly leaves: readonly Bytes32[];
}

/** What a wallet keeps of one anonymous ring between scans, Rust `AnonymousRingState`. */
export class AnonymousRingState {
  readonly ring: Address;
  readonly creationEpoch: bigint;
  /** Ascending index. */
  readonly issued: readonly IssuedAddress[];
  /** The last epoch every stream was read through, `undefined` before the first scan. */
  readonly scannedEpoch: bigint | undefined;
  readonly received: readonly ReceivedAnchor[];
  /** One per recipient key. */
  readonly sent: readonly SentFirstContact[];
  readonly depositNext: bigint;
  /** Ascending leaf index per tree id. */
  readonly decoys: ReadonlyMap<number, readonly DecoyLeaf[]>;
  /** By recipient key, the newest pair payment a scan saw the wallet make. */
  readonly #paid: ReadonlyMap<string, bigint>;
  /** By recipient key, the decoys every read of the anchor names. */
  readonly #pins: ReadonlyMap<string, readonly Bytes32[]>;

  private constructor(fields: AnonymousRingStateFields) {
    this.ring = fields.ring;
    this.creationEpoch = fields.creationEpoch;
    this.issued = Object.freeze([...fields.issued]);
    this.scannedEpoch = fields.scannedEpoch;
    this.received = Object.freeze([...fields.received]);
    this.sent = Object.freeze([...fields.sent]);
    this.depositNext = fields.depositNext;
    this.decoys = new Map(fields.decoys);
    this.#paid = new Map(fields.paid);
    this.#pins = new Map(fields.pins);
    Object.freeze(this);
  }

  /** A wallet that never scanned `ring`, a restore from seed reads every epoch from its creation. */
  static create(ring: Address, creationEpoch: bigint): AnonymousRingState {
    return new AnonymousRingState({
      ring,
      creationEpoch: unsigned(creationEpoch, "creationEpoch"),
      issued: [],
      scannedEpoch: undefined,
      received: [],
      sent: [],
      depositNext: 0n,
      decoys: new Map(),
      paid: new Map(),
      pins: new Map(),
    });
  }

  /** Every later scan reads the inbox stream of `index`, the pairing replaces an earlier one. */
  issue(index: number, pairing: Pairing): AnonymousRingState {
    issuedIndex(index);
    if (!(pairing instanceof Pairing))
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "pairing" });
    const issued = [...this.issued.filter((entry) => entry.index !== index), { index, pairing }];
    issued.sort((left, right) => left.index - right.index);
    return this.#with({ issued });
  }

  /** Live in `epoch`, pinned or not. */
  firstContact(recipient: X25519PublicKey, epoch: bigint): SentFirstContact | undefined {
    return this.sent.find(
      (contact) => contact.recipient.equals(recipient) && this.#sentLive(contact, epoch),
    );
  }

  /** The anchor a payment to `recipient` in `epoch` may pair on, live with its decoys pinned, Rust `pair_anchor`. */
  pairAnchor(recipient: X25519PublicKey, epoch: bigint): PairAnchor | undefined {
    const contact = this.firstContact(recipient, epoch);
    const decoys =
      contact === undefined ? undefined : this.#pins.get(recipientKey(contact.recipient));
    if (contact === undefined || decoys === undefined) return undefined;
    const leaves = byRank(contact.slotSecret, [...decoys, contact.utxoHash]);
    return Object.freeze({ contact, leaves: Object.freeze(leaves) });
  }

  /** A confirmed inbox payment becomes its address's newest first contact, the state keeps its own copy. */
  recordFirstContact(contact: SentFirstContact): AnonymousRingState {
    const recorded = checkedContact(contact);
    const known = this.sent.find((sent) => sent.recipient.equals(recorded.recipient));
    if (known !== undefined && sameLeaf(known, recorded)) {
      recorded.slotSecret.fill(0);
      return this;
    }
    if (known === undefined || known.epoch <= recorded.epoch) {
      const paid = new Map(this.#paid);
      paid.set(recipientKey(recorded.recipient), recorded.epoch);
      const pins = new Map(this.#pins);
      pins.delete(recipientKey(recorded.recipient));
      return this.#with({
        sent: [...this.sent.filter((sent) => sent !== known), recorded],
        paid,
        pins,
      });
    }
    recorded.slotSecret.fill(0);
    return this;
  }

  /** The next payment to `recipient` takes its inbox stream, Rust `retire_first_contact`. */
  retireFirstContact(recipient: X25519PublicKey): AnonymousRingState {
    const key = recipientKey(recipient);
    const paid = new Map(this.#paid);
    paid.delete(key);
    const pins = new Map(this.#pins);
    pins.delete(key);
    return this.#with({
      sent: this.sent.filter((contact) => !contact.recipient.equals(recipient)),
      paid,
      pins,
    });
  }

  /**
   * Pins the lowest ranked decoys of every unpinned contact whose tree's pool holds a full set, Rust `pin_anchors`.
   * @internal
   */
  pinAnchors(): AnonymousRingState {
    const pins = new Map(this.#pins);
    for (const contact of this.sent) {
      const key = recipientKey(contact.recipient);
      if (pins.has(key)) continue;
      const ranked = byRank(
        contact.slotSecret,
        (this.decoys.get(contact.treeId) ?? [])
          .map((leaf) => leaf.hash)
          .filter((hash) => !equal(hash, contact.utxoHash)),
      );
      if (ranked.length >= ANCHOR_DECOYS)
        pins.set(key, Object.freeze(ranked.slice(0, ANCHOR_DECOYS)));
    }
    return this.#with({ pins });
  }

  /** A pair tag of a live first contact among the outputs of the wallet's own spend, Rust `note_pair_payment`. */
  notePairPayment(spend: IndexedSpend): AnonymousRingState {
    const landed = tagEpoch(spend.slot);
    const tags = new Set(spend.outputSlots.map((slot) => hex(slot.viewTag)));
    const paid = new Map(this.#paid);
    for (const contact of this.sent) {
      // A proof of epoch e lands in e, or flagged in e + 1.
      const epochs = [landed - 1n, landed].filter(
        (epoch) =>
          epoch >= 0n &&
          epoch > (paid.get(recipientKey(contact.recipient)) ?? contact.epoch) &&
          this.#sentLive(contact, epoch),
      );
      if (epochs.length === 0) continue;
      const key = pairKey(contact.slotSecret);
      try {
        for (const epoch of epochs) {
          for (let at = 0; at < J_PAIR; at++) {
            if (tags.has(hex(ringTagField(pairTag(key, epoch, tagIndex(at))))))
              paid.set(recipientKey(contact.recipient), epoch);
          }
        }
      } finally {
        key.fill(0);
      }
    }
    return this.#with({ paid });
  }

  /** A pair payment found on the anchor at `at`, its stream lives `PAIR_IDLE_EPOCHS` past it. */
  anchorPaid(at: number, epoch: bigint): AnonymousRingState {
    const anchor = this.received[at];
    if (anchor === undefined || epoch <= anchor.lastEpoch) return this;
    const received = [...this.received];
    received[at] = Object.freeze({ ...anchor, lastEpoch: epoch });
    return this.#with({ received });
  }

  /** Drops the pair streams no later payment reaches, Rust `prune`. */
  pruned(openEpoch: bigint): AnonymousRingState {
    const scanned = this.scannedEpoch;
    const received = this.received.filter(
      (anchor) =>
        scanned === undefined || pairLiveThrough(anchor.epoch, anchor.lastEpoch) > scanned,
    );
    const sent = this.sent.filter((contact) => this.#sentLive(contact, openEpoch));
    const paid = new Map(
      sent.map((contact) => [
        recipientKey(contact.recipient),
        this.#paid.get(recipientKey(contact.recipient)) ?? contact.epoch,
      ]),
    );
    const pins = new Map(
      [...this.#pins].filter(([key]) =>
        sent.some((contact) => recipientKey(contact.recipient) === key),
      ),
    );
    return this.#with({ received, sent, paid, pins });
  }

  /**
   * At most `MAX_FETCH_EPOCHS`, the first one past the last scanned, Rust `fetch_epochs`.
   * @internal
   */
  fetchEpochs(slot: bigint): Readonly<{ first: bigint; open: bigint }> {
    const first = this.scannedEpoch === undefined ? this.creationEpoch : this.scannedEpoch + 1n;
    const capped = first + MAX_FETCH_EPOCHS - 1n;
    const open = tagEpoch(slot);
    return Object.freeze({ first, open: open < capped ? open : capped });
  }

  /** Issued, used or past them within `ADDRESS_GAP`, the addresses a scan reads. */
  addressWindow(): number {
    const last = this.issued.at(-1);
    return Math.min((last === undefined ? 0 : last.index + 1) + ADDRESS_GAP, MAX_ISSUED_ADDRESSES);
  }

  /** The rows an address was issued with, the default rows for one a payer found first. */
  pairing(index: number): Pairing {
    return this.issued.find((entry) => entry.index === index)?.pairing ?? Pairing.any();
  }

  /** An inbox first contact the address's rows admit, one anchor per pair key, the state keeps its own copy. */
  receive(anchor: ReceivedAnchor): AnonymousRingState {
    const received = checkedAnchor(anchor);
    if (!this.received.some((known) => equal(known.pairKey, received.pairKey)))
      return this.#with({ received: [...this.received, received] });
    received.pairKey.fill(0);
    return this;
  }

  /** Every epoch through `scannedEpoch` read, the deposit stream read up to `depositNext`. */
  scanned(
    progress: Readonly<{ scannedEpoch: bigint | undefined; depositNext: bigint }>,
  ): AnonymousRingState {
    const { scannedEpoch, depositNext } = progress;
    if (
      (scannedEpoch !== undefined &&
        (scannedEpoch < this.creationEpoch ||
          (this.scannedEpoch !== undefined && scannedEpoch < this.scannedEpoch))) ||
      depositNext < this.depositNext
    )
      throw new TransactionError("TRANSACTION_WALLET_STATE_STALE");
    return this.#with({ scannedEpoch: scannedEpoch ?? this.scannedEpoch, depositNext });
  }

  /** Keeps the lowest and highest leaf of each tree and spreads the rest evenly between them. */
  rememberDecoys(
    leaves: readonly Readonly<{ treeId: number; leafIndex: bigint; hash: Bytes32 }>[],
  ): AnonymousRingState {
    const decoys = new Map(this.decoys);
    for (const leaf of leaves) {
      const known = [...(decoys.get(leaf.treeId) ?? [])];
      if (
        !known.some((entry) => entry.leafIndex === leaf.leafIndex && equal(entry.hash, leaf.hash))
      )
        known.push(Object.freeze({ leafIndex: leaf.leafIndex, hash: leaf.hash }));
      known.sort(compareLeaves);
      decoys.set(leaf.treeId, known);
    }
    for (const [treeId, known] of decoys) {
      if (known.length <= DECOYS_PER_TREE) continue;
      const last = known.length - 1;
      decoys.set(
        treeId,
        Array.from(
          { length: DECOYS_PER_TREE },
          (_, k) => known[Math.floor((k * last) / (DECOYS_PER_TREE - 1))]!,
        ),
      );
    }
    return this.#with({ decoys });
  }

  /** Rust `StateJson`, field values hex, addresses base58, amounts decimal strings. */
  serialize(): SerializedAnonymousRingState {
    return {
      version: ANONYMOUS_RING_STATE_VERSION,
      ring: this.ring,
      creationEpoch: safeNumber(this.creationEpoch),
      issued: this.issued.map((entry) => ({
        index: entry.index,
        pairing: entry.pairing.rows.map((row) => ({
          mint: row.mint,
          minAmount: row.minAmount.toString(),
        })),
      })),
      scannedEpoch: this.scannedEpoch === undefined ? null : safeNumber(this.scannedEpoch),
      received: this.received.map((anchor) => ({
        addressIndex: anchor.addressIndex,
        pairKey: hex(anchor.pairKey),
        epoch: safeNumber(anchor.epoch),
        lastEpoch: safeNumber(anchor.lastEpoch),
        asset: anchor.asset,
        amount: anchor.amount.toString(),
      })),
      sent: this.sent.map((contact) => ({
        recipient: hex(contact.recipient.toBytes()),
        treeId: contact.treeId,
        leafIndex: safeNumber(contact.leafIndex),
        utxoHash: hex(contact.utxoHash),
        slotSecret: hex(contact.slotSecret),
        firstNullifier: hex(contact.firstNullifier),
        slotIndex: contact.slotIndex,
        epoch: safeNumber(contact.epoch),
        index: contact.index,
        asset: contact.asset,
        amount: contact.amount.toString(),
        lastEpoch: safeNumber(this.#paid.get(recipientKey(contact.recipient)) ?? contact.epoch),
        decoys: this.#pins.get(recipientKey(contact.recipient))?.map(hex) ?? null,
      })),
      depositNext: safeNumber(this.depositNext),
      decoys: [...this.decoys]
        .sort(([left], [right]) => left - right)
        .map(([treeId, leaves]) => ({
          treeId,
          leaves: leaves.map((leaf) => ({
            leafIndex: safeNumber(leaf.leafIndex),
            hash: hex(leaf.hash),
          })),
        })),
    };
  }

  /** Refuses another layout version, a rescan rebuilds all but the sent first contacts. */
  static deserialize(value: unknown, path: string): AnonymousRingState {
    const item = decode.record(value, path);
    known(item, path, [
      "version",
      "ring",
      "creationEpoch",
      "issued",
      "scannedEpoch",
      "received",
      "sent",
      "depositNext",
      "decoys",
    ]);
    if (item["version"] !== ANONYMOUS_RING_STATE_VERSION) fail(`${path}.version`);
    let state = AnonymousRingState.create(
      ringAddress(item["ring"], `${path}.ring`),
      integer(item["creationEpoch"], `${path}.creationEpoch`),
    );
    for (const [at, entry] of decode.list(item["issued"], `${path}.issued`).entries()) {
      const issuedPath = `${path}.issued[${String(at)}]`;
      const issued = decode.record(entry, issuedPath);
      known(issued, issuedPath, ["index", "pairing"]);
      const rows = decode.list(issued["pairing"], `${issuedPath}.pairing`).map((row, rowAt) => {
        const rowPath = `${issuedPath}.pairing[${String(rowAt)}]`;
        const pairingRow = decode.record(row, rowPath);
        known(pairingRow, rowPath, ["mint", "minAmount"]);
        return {
          mint: ringAddress(pairingRow["mint"], `${rowPath}.mint`),
          minAmount: decimal(pairingRow["minAmount"], `${rowPath}.minAmount`),
        };
      });
      const index = Number(integer(issued["index"], `${issuedPath}.index`, LAST_ADDRESS_INDEX));
      if (state.issued.some((entry) => entry.index === index)) fail(`${issuedPath}.index`);
      state = state.issue(index, Pairing.of(rows));
    }
    const scannedEpoch =
      item["scannedEpoch"] === null
        ? undefined
        : integer(item["scannedEpoch"], `${path}.scannedEpoch`);
    if (scannedEpoch !== undefined && scannedEpoch < state.creationEpoch)
      fail(`${path}.scannedEpoch`);
    const received = decode.list(item["received"], `${path}.received`).map((entry, at) => {
      const anchorPath = `${path}.received[${String(at)}]`;
      const anchor = decode.record(entry, anchorPath);
      known(anchor, anchorPath, [
        "addressIndex",
        "pairKey",
        "epoch",
        "lastEpoch",
        "asset",
        "amount",
      ]);
      return Object.freeze({
        addressIndex: Number(
          integer(anchor["addressIndex"], `${anchorPath}.addressIndex`, LAST_ADDRESS_INDEX),
        ),
        pairKey: bytes32(anchor["pairKey"], `${anchorPath}.pairKey`),
        epoch: integer(anchor["epoch"], `${anchorPath}.epoch`),
        lastEpoch: integer(anchor["lastEpoch"], `${anchorPath}.lastEpoch`),
        asset: ringAddress(anchor["asset"], `${anchorPath}.asset`),
        amount: decimal(anchor["amount"], `${anchorPath}.amount`),
      });
    });
    const paid = new Map<string, bigint>();
    const pins = new Map<string, readonly Bytes32[]>();
    const sent = decode.list(item["sent"], `${path}.sent`).map((entry, at) => {
      const contactPath = `${path}.sent[${String(at)}]`;
      const contact = decode.record(entry, contactPath);
      known(contact, contactPath, [
        "recipient",
        "treeId",
        "leafIndex",
        "utxoHash",
        "slotSecret",
        "firstNullifier",
        "slotIndex",
        "epoch",
        "index",
        "asset",
        "amount",
        "lastEpoch",
        "decoys",
      ]);
      const recipient = X25519PublicKey.fromBytes(
        hexBytes(contact["recipient"], 33, `${contactPath}.recipient`),
      );
      paid.set(recipientKey(recipient), integer(contact["lastEpoch"], `${contactPath}.lastEpoch`));
      const utxoHash = bytes32(contact["utxoHash"], `${contactPath}.utxoHash`);
      if (contact["decoys"] !== null && contact["decoys"] !== undefined)
        pins.set(
          recipientKey(recipient),
          pinnedDecoys(contact["decoys"], utxoHash, `${contactPath}.decoys`),
        );
      return Object.freeze({
        recipient,
        treeId: Number(integer(contact["treeId"], `${contactPath}.treeId`, 0xffffn)),
        leafIndex: integer(contact["leafIndex"], `${contactPath}.leafIndex`),
        utxoHash,
        slotSecret: bytes32(contact["slotSecret"], `${contactPath}.slotSecret`),
        firstNullifier: bytes32(contact["firstNullifier"], `${contactPath}.firstNullifier`),
        slotIndex: Number(integer(contact["slotIndex"], `${contactPath}.slotIndex`, 0xffn)),
        epoch: integer(contact["epoch"], `${contactPath}.epoch`),
        index: tagIndex(Number(integer(contact["index"], `${contactPath}.index`, 0xffn))),
        asset: ringAddress(contact["asset"], `${contactPath}.asset`),
        amount: decimal(contact["amount"], `${contactPath}.amount`),
      });
    });
    if (new Set(sent.map((contact) => hex(contact.recipient.toBytes()))).size !== sent.length)
      fail(`${path}.sent`);
    const decoys = new Map<number, readonly DecoyLeaf[]>();
    for (const [at, entry] of decode.list(item["decoys"], `${path}.decoys`).entries()) {
      const treePath = `${path}.decoys[${String(at)}]`;
      const tree = decode.record(entry, treePath);
      known(tree, treePath, ["treeId", "leaves"]);
      const treeId = Number(integer(tree["treeId"], `${treePath}.treeId`, 0xffffn));
      if (decoys.has(treeId)) fail(`${treePath}.treeId`);
      const leaves = decode.list(tree["leaves"], `${treePath}.leaves`).map((leaf, leafAt) => {
        const leafPath = `${treePath}.leaves[${String(leafAt)}]`;
        const fields = decode.record(leaf, leafPath);
        known(fields, leafPath, ["leafIndex", "hash"]);
        return Object.freeze({
          leafIndex: integer(fields["leafIndex"], `${leafPath}.leafIndex`),
          hash: bytes32(fields["hash"], `${leafPath}.hash`),
        });
      });
      if (leaves.length > DECOYS_PER_TREE || !ascending(leaves)) fail(`${treePath}.leaves`);
      decoys.set(treeId, Object.freeze(leaves));
    }
    return state.#with({
      scannedEpoch,
      received,
      sent,
      depositNext: integer(item["depositNext"], `${path}.depositNext`),
      decoys,
      paid,
      pins,
    });
  }

  #sentLive(contact: SentFirstContact, epoch: bigint): boolean {
    const last = this.#paid.get(recipientKey(contact.recipient)) ?? contact.epoch;
    return epoch >= contact.epoch && epoch <= pairLiveThrough(contact.epoch, last);
  }

  #with(changes: Partial<AnonymousRingStateFields>): AnonymousRingState {
    return new AnonymousRingState({
      ring: this.ring,
      creationEpoch: this.creationEpoch,
      issued: this.issued,
      scannedEpoch: this.scannedEpoch,
      received: this.received,
      sent: this.sent,
      depositNext: this.depositNext,
      decoys: this.decoys,
      paid: this.#paid,
      pins: this.#pins,
      ...changes,
    });
  }
}

/** A proof bounds a pair by its first contact, the idle rule by its last payment, Rust `pair_live_through`. */
export function pairLiveThrough(first: bigint, last: bigint): bigint {
  const anchored = first + K_PAIR_EPOCHS - 1n;
  const paid = last + PAIR_IDLE_EPOCHS - 1n;
  return anchored < paid ? anchored : paid;
}

/** The outputs of a spend the wallet signed, read for its pair tags. */
export type IndexedSpend = Readonly<{
  slot: bigint;
  outputSlots: readonly Readonly<{ viewTag: Bytes32 }>[];
}>;

/** The JSON form, Rust `StateJson` field for field. */
export interface SerializedAnonymousRingState {
  readonly version: number;
  readonly ring: Address;
  readonly creationEpoch: number;
  readonly issued: readonly Readonly<{
    index: number;
    pairing: readonly Readonly<{ mint: Address; minAmount: string }>[];
  }>[];
  readonly scannedEpoch: number | null;
  readonly received: readonly Readonly<{
    addressIndex: number;
    pairKey: string;
    epoch: number;
    lastEpoch: number;
    asset: Address;
    amount: string;
  }>[];
  readonly sent: readonly Readonly<{
    recipient: string;
    treeId: number;
    leafIndex: number;
    utxoHash: string;
    slotSecret: string;
    firstNullifier: string;
    slotIndex: number;
    epoch: number;
    index: number;
    asset: Address;
    amount: string;
    lastEpoch: number;
    decoys: readonly string[] | null;
  }>[];
  readonly depositNext: number;
  readonly decoys: readonly Readonly<{
    treeId: number;
    leaves: readonly Readonly<{ leafIndex: number; hash: string }>[];
  }>[];
}

interface AnonymousRingStateFields {
  readonly ring: Address;
  readonly creationEpoch: bigint;
  readonly issued: readonly IssuedAddress[];
  readonly scannedEpoch: bigint | undefined;
  readonly received: readonly ReceivedAnchor[];
  readonly sent: readonly SentFirstContact[];
  readonly depositNext: bigint;
  readonly decoys: ReadonlyMap<number, readonly DecoyLeaf[]>;
  readonly paid: ReadonlyMap<string, bigint>;
  readonly pins: ReadonlyMap<string, readonly Bytes32[]>;
}

const LAST_ADDRESS_INDEX = BigInt(MAX_ISSUED_ADDRESSES - 1);
const decode = wireDecoder((field) => new TransactionError("TRANSACTION_DESERIALIZE", { field }));

function issuedIndex(index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= MAX_ISSUED_ADDRESSES)
    throw new TransactionError("TRANSACTION_TOO_MANY_ISSUED_ADDRESSES", {
      index,
      maximum: MAX_ISSUED_ADDRESSES,
    });
  return index;
}

function checkedAnchor(anchor: ReceivedAnchor): ReceivedAnchor {
  return Object.freeze({
    addressIndex: issuedIndex(anchor.addressIndex),
    epoch: unsigned(anchor.epoch, "epoch"),
    lastEpoch: unsigned(anchor.lastEpoch, "lastEpoch"),
    asset: assetOf(anchor.asset),
    amount: amountOf(anchor.amount),
    // Copied after every check, a refused anchor leaves no secret copy.
    pairKey: checked<Bytes32>(anchor.pairKey, 32, "pairKey"),
  });
}

function recipientKey(recipient: X25519PublicKey): string {
  return hex(recipient.toBytes());
}

const ANCHOR_DECOY_DOMAIN = new TextEncoder().encode("zolana/ring-anchor-decoy/v1");

/** Distinct `hashes` in the order of a rank keyed by the slot secret, no reader of a request can tell the anchor from a decoy, Rust `by_rank`. */
function byRank(slotSecret: Bytes32, hashes: readonly Bytes32[]): Bytes32[] {
  const ranked = hashes.map((hash) => {
    const preimage = concatBytes(ANCHOR_DECOY_DOMAIN, slotSecret, hash);
    try {
      return { rank: sha256(preimage), hash };
    } finally {
      preimage.fill(0);
    }
  });
  ranked.sort(
    (left, right) => compareBytes(left.rank, right.rank) || compareBytes(left.hash, right.hash),
  );
  return ranked
    .filter((leaf, at) => at === 0 || !equal(leaf.hash, ranked[at - 1]!.hash))
    .map(({ hash }) => hash);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let at = 0; at < Math.min(left.length, right.length); at++) {
    const difference = (left[at] ?? 0) - (right[at] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

/** Rust `SentFirstContact::same_leaf`. */
function sameLeaf(left: SentFirstContact, right: SentFirstContact): boolean {
  return (
    left.treeId === right.treeId &&
    left.leafIndex === right.leafIndex &&
    equal(left.utxoHash, right.utxoHash)
  );
}

/** Distinct leaves beside the anchor, as `pinAnchors` keeps them, Rust `pinned_decoys`. */
function pinnedDecoys(value: unknown, anchor: Bytes32, path: string): readonly Bytes32[] {
  const decoys = decode
    .list(value, path)
    .map((entry, at) => bytes32(entry, `${path}[${String(at)}]`));
  const distinct = new Set(decoys.map(hex));
  if (
    decoys.length !== ANCHOR_DECOYS ||
    distinct.size !== ANCHOR_DECOYS ||
    distinct.has(hex(anchor))
  )
    fail(path);
  return Object.freeze(decoys);
}

function checkedContact(contact: SentFirstContact): SentFirstContact {
  if (!(contact.recipient instanceof X25519PublicKey))
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "recipient" });
  if (!Number.isInteger(contact.slotIndex) || contact.slotIndex < 0 || contact.slotIndex > 0xff)
    throw new TransactionError("TRANSACTION_INVALID_POSITION", { position: contact.slotIndex });
  return Object.freeze({
    recipient: contact.recipient,
    treeId: checkedTreeId(contact.treeId),
    leafIndex: unsigned(contact.leafIndex, "leafIndex"),
    utxoHash: checked<Bytes32>(contact.utxoHash, 32, "utxoHash"),
    firstNullifier: checked<Bytes32>(contact.firstNullifier, 32, "firstNullifier"),
    slotIndex: contact.slotIndex,
    epoch: unsigned(contact.epoch, "epoch"),
    index: tagIndex(contact.index),
    asset: assetOf(contact.asset),
    amount: amountOf(contact.amount),
    // Copied after every check, a refused contact leaves no secret copy.
    slotSecret: checked<Bytes32>(contact.slotSecret, 32, "slotSecret"),
  });
}

function assetOf(value: Address): Address {
  try {
    return address(value);
  } catch {
    throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { name: "asset" });
  }
}

function amountOf(value: bigint): bigint {
  if (typeof value !== "bigint")
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", { name: "amount" });
  return checkU64(value, "amount");
}

function known(
  record: Readonly<Record<string, unknown>>,
  path: string,
  fields: readonly string[],
): void {
  const extra = Object.keys(record).find((key) => !fields.includes(key));
  if (extra !== undefined) fail(`${path}.${extra}`);
}

/** Rust writes `u64` as a JSON number, a value past the safe range is refused. */
function integer(value: unknown, path: string, maximum = BigInt(Number.MAX_SAFE_INTEGER)): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum)
    fail(path);
  return BigInt(value);
}

function decimal(value: unknown, path: string): bigint {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail(path);
  const parsed = BigInt(value);
  if (parsed > U64_MAX) fail(path);
  return parsed;
}

function ringAddress(value: unknown, path: string): Address {
  if (typeof value !== "string") fail(path);
  try {
    return address(value);
  } catch {
    return fail(path);
  }
}

function hexBytes(value: unknown, length: number, path: string): Uint8Array {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${String(2 * length)}}$`).test(value))
    fail(path);
  return Uint8Array.from({ length }, (_, at) =>
    Number.parseInt(value.slice(2 * at, 2 * at + 2), 16),
  );
}

function bytes32(value: unknown, path: string): Bytes32 {
  return hexBytes(value, 32, path) as Bytes32;
}

function ascending(leaves: readonly DecoyLeaf[]): boolean {
  return leaves.every((leaf, at) => at === 0 || compareLeaves(leaves[at - 1]!, leaf) < 0);
}

/** Rust `DecoyLeaf` order, by leaf index and then by hash. */
function compareLeaves(left: DecoyLeaf, right: DecoyLeaf): number {
  if (left.leafIndex !== right.leafIndex) return left.leafIndex < right.leafIndex ? -1 : 1;
  return compareBytes(left.hash, right.hash);
}

function unsigned(value: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new TransactionError("TRANSACTION_INVALID_INTEGER", { name });
  return value;
}

function safeNumber(value: bigint): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new TransactionError("TRANSACTION_SERIALIZE", { field: "anonymousRing" });
  return Number(value);
}

function fail(field: string): never {
  throw new TransactionError("TRANSACTION_DESERIALIZE", { field });
}
