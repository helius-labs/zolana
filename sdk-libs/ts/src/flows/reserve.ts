import type { Bytes32 } from "../interface/types.js";
import {
  hex,
  type UtxoReservation,
  type Wallet,
  type WalletUtxo,
} from "../transaction/wallet/state.js";

/** A built transaction dies with its blockhash on roughly the same clock. */
export const DEFAULT_RESERVATION_TTL_MS = 120_000n;

/** @internal */
export function reservedUtxoKeys(wallet: Wallet): ReadonlySet<string> {
  return wallet._reservedUtxoKeys(BigInt(Date.now()));
}

/** @internal */
export function reserveEntries(
  wallet: Wallet,
  entries: readonly WalletUtxo[],
  lifetime: "lease" | "submission" = "lease",
): UtxoReservation {
  return wallet._reserveUtxos({
    utxoHashes: entries.map((entry) => entry.outputContext.hash),
    nowMs: BigInt(Date.now()),
    ttlMs: lifetime === "submission" ? null : DEFAULT_RESERVATION_TTL_MS,
  });
}

/** @internal */
export function extendReservation(wallet: Wallet, id: string): void {
  wallet._extendReservation({ id, nowMs: BigInt(Date.now()), ttlMs: DEFAULT_RESERVATION_TTL_MS });
}

/** @internal */
export function unreserved(
  reserved: ReadonlySet<string>,
): (entry: Readonly<{ outputContext: Readonly<{ hash: Bytes32 }> }>) => boolean {
  return (entry) => !reserved.has(hex(entry.outputContext.hash));
}
