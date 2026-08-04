import type { P256PublicKey } from "../../keypair/public-key.js";

/**
 * Primitives shared by the wallet state container and the decrypt pass. They
 * live apart from both so `state.ts` and `sync.ts` can each import them without
 * importing each other.
 */

/** Sender-side history rows sort after every recipient row of the same slot. */
export const SENDER_HISTORY_ROW_BASE = 1n << 63n;

/** One viewing key this wallet retains, with the slot it started covering. */
export interface ViewingKeyEntry {
  readonly viewingPublicKey: P256PublicKey;
  readonly createdAt: bigint;
}

export function newViewingKeyEntry(
  viewingPublicKey: P256PublicKey,
  createdAt: bigint,
): ViewingKeyEntry {
  return Object.freeze({
    viewingPublicKey,
    createdAt,
  });
}

export function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
