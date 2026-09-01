import type { Bytes32 } from "../interface/types.js";
import {
  hex,
  type NoteReservation,
  type Wallet,
  type WalletUtxo,
} from "../transaction/wallet/state.js";

/** A built transaction dies with its blockhash on roughly the same clock. */
export const DEFAULT_RESERVATION_TTL_MS = 120_000n;

/** @internal */
export function reservedNoteKeys(wallet: Wallet): ReadonlySet<string> {
  return wallet._reservedNoteKeys(BigInt(Date.now()));
}

/** @internal */
export function reserveEntries(wallet: Wallet, entries: readonly WalletUtxo[]): NoteReservation {
  return wallet._reserveNotes({
    noteHashes: entries.map((entry) => entry.outputContext.hash),
    nowMs: BigInt(Date.now()),
    ttlMs: DEFAULT_RESERVATION_TTL_MS,
  });
}

/** @internal */
export function unreserved(
  reserved: ReadonlySet<string>,
): (entry: Readonly<{ outputContext: Readonly<{ hash: Bytes32 }> }>) => boolean {
  return (entry) => !reserved.has(hex(entry.outputContext.hash));
}
