import type { Bytes32, RequestContext } from "../interface/types.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { EncryptedScheme, readOutputData } from "../transaction/serialization/codecs.js";
import {
  AnonymousTagRoutes,
  type AnonymousRingNote,
  type AnonymousRingReport,
  type AnonymousRingState,
  type AnonymousStream,
} from "../transaction/wallet/anonymous.js";
import type { RingTagKeys, RingTagRequest } from "../transaction/wallet/keys.js";
import { TransactionError } from "../transaction/error.js";

import { bytesKey } from "./internal.js";
import { DEFAULT_TAG_WINDOW, TagWindow, windowIndices } from "./tag-stream.js";

/** Consecutive unused addresses past the issued ones that end the address scan. */
export const ADDRESS_GAP = 20;

/** Outputs opened under one inbox index, the rest are spam. */
export const DECRYPTIONS_PER_INDEX = 16;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Change tags come from spends, not windows. */
type Window =
  | Readonly<{ kind: "inbox"; addressIndex: number }>
  | Readonly<{ kind: "pair"; counterparty: X25519PublicKey }>
  | Readonly<{ kind: "deposit" }>;

interface OpenStream {
  readonly window: Window;
  readonly start: bigint;
}

function request(window: Window, viewingPublicKey: X25519PublicKey, index: bigint): RingTagRequest {
  switch (window.kind) {
    case "inbox":
      return { kind: "inbox", viewingPublicKey, addressIndex: window.addressIndex, j: index };
    case "pair":
      return { kind: "pair", viewingPublicKey, counterparty: window.counterparty, k: index };
    case "deposit":
      return { kind: "deposit", viewingPublicKey, n: index };
  }
}

function hasRingAnonymousSlot(tx: IndexedShieldedTransaction): boolean {
  return tx.outputSlots.some((slot) => {
    try {
      const frame = readOutputData(slot.payload);
      return frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringAnonymous;
    } catch {
      return false;
    }
  });
}

/** @internal */
export class AnonymousStreams {
  readonly routes = new AnonymousTagRoutes(DECRYPTIONS_PER_INDEX);
  readonly #keys: RingTagKeys;
  readonly #viewingPublicKey: X25519PublicKey;
  readonly #counterparties = new Map<string, X25519PublicKey>();
  readonly #newCounterparties: X25519PublicKey[] = [];
  readonly #notes: AnonymousRingNote[] = [];
  readonly #recorded = new Set<string>();
  readonly #changeRouted = new Set<string>();
  readonly #inboxNext = new Map<number, bigint>();
  readonly #pairNext = new Map<string, Readonly<{ counterparty: X25519PublicKey; next: bigint }>>();
  readonly #attacked = new Set<number>();
  #depositNext = 0n;
  #usedAddresses: number;
  #openedAddresses = 0;
  #open: OpenStream[] = [{ window: { kind: "deposit" }, start: 0n }];
  #pending: readonly Readonly<{ open: OpenStream; window: TagWindow }>[] = [];

  constructor(keys: RingTagKeys, viewingPublicKey: X25519PublicKey, state: AnonymousRingState) {
    this.#keys = keys;
    this.#viewingPublicKey = viewingPublicKey;
    this.#usedAddresses = state.issuedAddresses;
    for (const counterparty of state.knownCounterparties) {
      this.#counterparties.set(bytesKey(counterparty.toBytes()), counterparty);
      this.#openPair(counterparty);
    }
    this.#openAddresses();
  }

  isDone(): boolean {
    return this.#open.length === 0;
  }

  /** Rows fetched under the returned tags go to `observe`. */
  async nextWindows(context?: RequestContext): Promise<readonly Bytes32[]> {
    const requests: RingTagRequest[] = [];
    const positions: number[] = [];
    this.#open.forEach((open, position) => {
      for (const index of windowIndices(open.start)) {
        requests.push(request(open.window, this.#viewingPublicKey, index));
        positions.push(position);
      }
    });
    const tags = await this.#derive(requests, context);
    const byStream: Bytes32[][] = this.#open.map(() => []);
    tags.forEach((tag, at) => byStream[positions[at] ?? 0]?.push(tag));
    this.#pending = this.#open.map((open, position) => {
      const window = new TagWindow(open.start, byStream[position] ?? []);
      for (const tag of window.tags()) {
        this.routes.route(tag, this.#viewingPublicKey, open.window);
      }
      return { open, window };
    });
    return tags;
  }

  /** A window with no occupied index closes its stream. */
  observe(transactions: Iterable<IndexedShieldedTransaction>): void {
    const rows = [...transactions];
    const stillOpen: OpenStream[] = [];
    for (const { open, window } of this.#pending) {
      const occupied = window.occupied(rows);
      if (occupied.size === 0) continue;
      const highest = [...occupied].reduce((left, right) => (left > right ? left : right));
      this.#advance(open.window, highest + 1n);
      const start = open.start + DEFAULT_TAG_WINDOW;
      if (start <= U64_MAX) stillOpen.push({ window: open.window, start });
    }
    this.#pending = [];
    this.#open = stillOpen;
  }

  async routeChange(
    transactions: Iterable<IndexedShieldedTransaction>,
    ownedNullifiers: ReadonlySet<string>,
    context?: RequestContext,
  ): Promise<boolean> {
    const requests: RingTagRequest[] = [];
    for (const tx of transactions) {
      const firstNullifier = tx.nullifiers[0];
      if (firstNullifier === undefined) continue;
      const key = bytesKey(firstNullifier);
      if (
        this.#changeRouted.has(key) ||
        !tx.nullifiers.some((nullifier) => ownedNullifiers.has(bytesKey(nullifier)))
      ) {
        continue;
      }
      this.#changeRouted.add(key);
      if (!hasRingAnonymousSlot(tx)) continue;
      tx.outputSlots.forEach((_, slot) => {
        requests.push({
          kind: "change",
          viewingPublicKey: this.#viewingPublicKey,
          firstNullifier,
          slot,
        });
      });
    }
    if (requests.length === 0) return false;
    const tags = await this.#derive(requests, context);
    tags.forEach((tag, at) => {
      const derived = requests[at];
      if (derived?.kind !== "change") return;
      this.routes.route(tag, this.#viewingPublicKey, {
        kind: "change",
        firstNullifier: derived.firstNullifier,
      });
    });
    return true;
  }

  record(): void {
    for (const note of this.routes.notes()) {
      const key = bytesKey(note.utxoHash);
      if (this.#recorded.has(key)) continue;
      this.#recorded.add(key);
      this.#notes.push({
        utxoHash: note.utxoHash,
        pairPublicKey: note.pairPublicKey,
        stream: note.stream,
      });
      if (note.stream.kind !== "inbox") continue;
      this.#usedAddresses = Math.max(this.#usedAddresses, note.stream.addressIndex + 1);
      const counterparty = bytesKey(note.pairPublicKey.toBytes());
      if (!this.#counterparties.has(counterparty)) {
        this.#counterparties.set(counterparty, note.pairPublicKey);
        this.#newCounterparties.push(note.pairPublicKey);
        this.#openPair(note.pairPublicKey);
      }
    }
    for (const tag of this.routes.cappedTags()) {
      const route = this.routes.routeOf(tag);
      if (route?.stream.kind === "inbox") this.#attacked.add(route.stream.addressIndex);
    }
    this.#openAddresses();
  }

  finish(): AnonymousRingReport {
    return Object.freeze({
      notes: Object.freeze([...this.#notes]),
      newCounterparties: Object.freeze([...this.#newCounterparties]),
      usedAddresses: this.#usedAddresses,
      inboxNext: new Map(this.#inboxNext),
      pairNext: Object.freeze([...this.#pairNext.values()]),
      depositNext: this.#depositNext,
      addressesUnderAttack: Object.freeze([...this.#attacked].sort((left, right) => left - right)),
    });
  }

  async #derive(
    requests: readonly RingTagRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    if (requests.length === 0) return [];
    const tags = await this.#keys.ringViewTags(requests, context);
    if (tags.length !== requests.length) {
      throw new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH", {
        expected: requests.length,
        actual: tags.length,
      });
    }
    return tags;
  }

  #advance(window: Window, next: bigint): void {
    switch (window.kind) {
      case "inbox":
        this.#inboxNext.set(window.addressIndex, next);
        return;
      case "pair":
        this.#pairNext.set(bytesKey(window.counterparty.toBytes()), {
          counterparty: window.counterparty,
          next,
        });
        return;
      case "deposit":
        this.#depositNext = next;
    }
  }

  #openAddresses(): void {
    const end = this.#usedAddresses + ADDRESS_GAP;
    while (this.#openedAddresses < end) {
      this.#open.push({
        window: { kind: "inbox", addressIndex: this.#openedAddresses },
        start: 0n,
      });
      this.#openedAddresses += 1;
    }
  }

  #openPair(counterparty: X25519PublicKey): void {
    this.#open.push({ window: { kind: "pair", counterparty }, start: 0n });
  }
}

export type { AnonymousRingNote, AnonymousRingReport, AnonymousRingState, AnonymousStream };
