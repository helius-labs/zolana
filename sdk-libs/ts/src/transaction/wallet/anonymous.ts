import type { Address, Bytes32, Signature } from "../../interface/types.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import {
  EncryptedScheme,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  readOutputData,
} from "../serialization/codecs.js";
import type { Utxo } from "../utxo.js";

import { hex } from "./state.js";

/** `recovered` marks a note the full history scan found under a tag the wallet never derived. */
export type AnonymousStream =
  | Readonly<{ kind: "inbox"; addressIndex: number }>
  | Readonly<{ kind: "pair"; counterparty: X25519PublicKey }>
  | Readonly<{ kind: "deposit" }>
  | Readonly<{ kind: "change"; firstNullifier: Bytes32 }>
  | Readonly<{ kind: "recovered" }>;

/** A scheme-9 note whose recomputed commitment matched the published one. */
export interface AnonymousNote {
  readonly viewTag: Bytes32;
  readonly utxoHash: Bytes32;
  /** Absent when the body carried a pair hint that is no canonical contributory X25519 key. */
  readonly pairPublicKey?: X25519PublicKey;
  readonly stream: AnonymousStream;
}

/** A commitment-verified scheme-9 note whose mint the registry does not know yet, the wallet keeps it until `resolvePendingNotes` admits it. */
export interface PendingAnonymousNote {
  readonly utxo: Utxo;
  readonly nullifierPublicKey: Bytes32;
  readonly outputContext: Readonly<{
    hash: Bytes32;
    tree: Address;
    treeId: number;
    leafIndex: bigint;
  }>;
  readonly txSignature: Signature;
  readonly slot: bigint;
  readonly slotIndex: number;
  readonly pairU: Bytes32;
}

export type AnonymousSlotDefect =
  | Readonly<{ kind: "missingTxViewingKey" }>
  | Readonly<{ kind: "missingSalt" }>
  | Readonly<{ kind: "bodyLength"; length: number }>;

/** A scheme-9 slot of a ring transaction the ring program refuses, left unopened. */
export interface MalformedAnonymousSlot {
  readonly txSignature: Signature;
  readonly slotIndex: number;
  readonly viewTag: Bytes32;
  readonly defect: AnonymousSlotDefect;
}

/** The body after the scheme-9 byte, `undefined` for any other frame. */
export function ringAnonymousBody(payload: Uint8Array): Uint8Array | undefined {
  try {
    const frame = readOutputData(payload);
    return frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringAnonymous
      ? frame.body
      : undefined;
  } catch {
    return undefined;
  }
}

/** `undefined` for a scheme-9 body of a ring transaction the ring program admits. */
export function anonymousSlotDefect(
  tx: IndexedShieldedTransaction,
  body: Uint8Array,
): AnonymousSlotDefect | undefined {
  if (tx.txViewingPublicKey === undefined) return { kind: "missingTxViewingKey" };
  if (tx.salt === undefined) return { kind: "missingSalt" };
  if (body.length !== RING_ANONYMOUS_PLAINTEXT_LENGTH) {
    return { kind: "bodyLength", length: body.length };
  }
  return undefined;
}

/** Every refused scheme-9 slot of a ring transaction in slot order, none outside a ring. */
export function malformedAnonymousSlots(
  tx: IndexedShieldedTransaction,
): readonly MalformedAnonymousSlot[] {
  if (tx.ringProgramId === undefined) return [];
  return tx.outputSlots.flatMap((slot, slotIndex) => {
    const body = ringAnonymousBody(slot.payload);
    const defect = body === undefined ? undefined : anonymousSlotDefect(tx, body);
    return defect === undefined
      ? []
      : [{ txSignature: tx.txSignature, slotIndex, viewTag: slot.viewTag, defect }];
  });
}

export interface AnonymousRingState {
  /** Ring addresses handed out, scanned whole before the gap rule applies. */
  readonly issuedAddresses: number;
  /** Pair keys of payers and viewing keys of recipients paid before. */
  readonly knownCounterparties: readonly X25519PublicKey[];
}

export interface AnonymousRingNote {
  readonly utxoHash: Bytes32;
  readonly pairPublicKey?: X25519PublicKey;
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
  /** Commitments of stored notes whose pair hint names no counterparty. */
  readonly badPairHints: readonly Bytes32[];
  /** Slots under a derived tag the ring program refuses, the indexer served them wrongly. */
  readonly malformedSlots: readonly MalformedAnonymousSlot[];
}

interface Route {
  readonly viewingPublicKeys: readonly X25519PublicKey[];
  readonly stream: AnonymousStream;
}

/** A scheme-9 output under an unrouted tag is never decrypted. */
export class AnonymousTagRoutes {
  readonly #routes = new Map<string, Route>();
  readonly #notes = new Map<string, AnonymousNote>();
  readonly #capped = new Map<string, Bytes32>();
  readonly #badPairHints = new Map<string, Bytes32>();
  readonly #malformed = new Map<string, MalformedAnonymousSlot>();
  readonly #decryptionsPerTag: number;

  /** Openings per tag per `decryptTransactions` call before the tag is flagged, every hit still opens. */
  constructor(decryptionsPerTag = Number.POSITIVE_INFINITY) {
    this.#decryptionsPerTag = decryptionsPerTag;
  }

  /** A slot under `tag` is tried under each key in order until one opens it. */
  route(
    tag: Bytes32,
    viewingPublicKeys: readonly X25519PublicKey[],
    stream: AnonymousStream,
  ): void {
    this.#routes.set(hex(tag), { viewingPublicKeys: [...viewingPublicKeys], stream });
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

  /** @internal */
  badPairHint(utxoHash: Bytes32): void {
    this.#badPairHints.set(hex(utxoHash), utxoHash);
  }

  /** @internal */
  malformed(slot: MalformedAnonymousSlot): void {
    this.#malformed.set(`${slot.txSignature}:${String(slot.slotIndex)}`, slot);
  }

  notes(): readonly AnonymousNote[] {
    return [...this.#notes.values()];
  }

  /** Tags with more outputs than the per-index cap, a stream to scan in full. */
  cappedTags(): readonly Bytes32[] {
    return [...this.#capped.values()];
  }

  /** Stored notes whose pair hint is no canonical contributory X25519 key. */
  badPairHints(): readonly Bytes32[] {
    return [...this.#badPairHints.values()];
  }

  malformedSlots(): readonly MalformedAnonymousSlot[] {
    return [...this.#malformed.values()];
  }
}
