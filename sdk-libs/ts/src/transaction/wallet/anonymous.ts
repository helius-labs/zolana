import type { Bytes32 } from "../../interface/types.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";

import { hex } from "./state.js";

export type AnonymousStream =
  | Readonly<{ kind: "inbox"; addressIndex: number }>
  | Readonly<{ kind: "pair"; counterparty: X25519PublicKey }>
  | Readonly<{ kind: "deposit" }>
  | Readonly<{ kind: "change"; firstNullifier: Bytes32 }>;

/** A scheme-9 note whose recomputed commitment matched the published one. */
export interface AnonymousNote {
  readonly viewTag: Bytes32;
  readonly utxoHash: Bytes32;
  readonly pairPublicKey: X25519PublicKey;
  readonly stream: AnonymousStream;
}

export interface AnonymousRingState {
  /** Ring addresses handed out, scanned whole before the gap rule applies. */
  readonly issuedAddresses: number;
  /** Pair keys of payers and viewing keys of recipients paid before. */
  readonly knownCounterparties: readonly X25519PublicKey[];
}

export interface AnonymousRingNote {
  readonly utxoHash: Bytes32;
  readonly pairPublicKey: X25519PublicKey;
  readonly stream: AnonymousStream;
}

export interface AnonymousRingReport {
  readonly notes: readonly AnonymousRingNote[];
  /** Pair keys read from first payments, absent from the state's counterparties. */
  readonly newCounterparties: readonly X25519PublicKey[];
  /** Never below the issued count. */
  readonly usedAddresses: number;
  readonly inboxNext: ReadonlyMap<number, bigint>;
  readonly pairNext: readonly Readonly<{ counterparty: X25519PublicKey; next: bigint }>[];
  readonly depositNext: bigint;
  /** Addresses with an inbox index past the per-index decryption cap. */
  readonly addressesUnderAttack: readonly number[];
}

interface Route {
  readonly viewingPublicKey: X25519PublicKey;
  readonly stream: AnonymousStream;
}

/** A scheme-9 output under an unrouted tag is never decrypted. */
export class AnonymousTagRoutes {
  readonly #routes = new Map<string, Route>();
  readonly #notes = new Map<string, AnonymousNote>();
  readonly #capped = new Map<string, Bytes32>();
  readonly #decryptionsPerTag: number;

  /** Openings per tag per `decryptTransactions` call, the rest count as spam. */
  constructor(decryptionsPerTag = Number.POSITIVE_INFINITY) {
    this.#decryptionsPerTag = decryptionsPerTag;
  }

  route(tag: Bytes32, viewingPublicKey: X25519PublicKey, stream: AnonymousStream): void {
    this.#routes.set(hex(tag), { viewingPublicKey, stream });
  }

  routeOf(tag: Bytes32): Route | undefined {
    return this.#routes.get(hex(tag));
  }

  /** @internal Routes by the hex of their tag, the key `TagIndex` uses. */
  entries(): Iterable<readonly [string, Route]> {
    return this.#routes.entries();
  }

  /** @internal */
  allows(opened: number): boolean {
    return opened < this.#decryptionsPerTag;
  }

  /** @internal */
  found(note: AnonymousNote): void {
    this.#notes.set(hex(note.utxoHash), note);
  }

  /** @internal */
  capped(tag: Bytes32): void {
    this.#capped.set(hex(tag), tag);
  }

  notes(): readonly AnonymousNote[] {
    return [...this.#notes.values()];
  }

  /** Tags with more outputs than one pass opens. */
  cappedTags(): readonly Bytes32[] {
    return [...this.#capped.values()];
  }
}
