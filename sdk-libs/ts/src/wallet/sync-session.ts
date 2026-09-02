import type { Address, Bytes32 } from "../interface/types.js";
import type { CursorStream, SyncDelta } from "../transaction/wallet/state.js";
import { Wallet } from "../transaction/wallet/state.js";

import { bytesKey } from "./internal.js";

/** @internal */
export interface WalletSyncSession {
  readonly staging: Wallet;
  readonly cursors: Readonly<Record<CursorStream, Map<string, Uint8Array>>>;
  readonly registryAdditions: { assetId: bigint; mint: Address }[];
  readonly baseRevision: number;
}

/** @internal */
export function beginSyncSession(wallet: Wallet): WalletSyncSession {
  return {
    staging: wallet._clone(),
    cursors: { transactions: new Map(), proofless: new Map(), nullifiers: new Map() },
    registryAdditions: [],
    baseRevision: wallet._revision,
  };
}

/** @internal Session advances shadow the committed value. */
export function sessionCursor(
  session: WalletSyncSession,
  stream: CursorStream,
  key: string,
): Uint8Array | undefined {
  return session.cursors[stream].get(key) ?? session.staging._syncCursor(stream, key);
}

/** @internal */
export function advanceSessionCursors(
  session: WalletSyncSession,
  stream: CursorStream,
  keys: readonly Bytes32[],
  furthest: Uint8Array,
): void {
  for (const key of keys) {
    session.cursors[stream].set(bytesKey(key), Uint8Array.from(furthest));
  }
}

/** @internal */
export function ensureSessionAsset(
  session: WalletSyncSession,
  assetId: bigint,
  mint: Address,
): boolean {
  if (!session.staging.ensureAsset(assetId, mint)) return false;
  session.registryAdditions.push({ assetId, mint });
  return true;
}

/** @internal */
export function sealSyncDelta(session: WalletSyncSession): SyncDelta {
  return {
    ...session.staging._state(),
    lastSynced: session.staging.lastSynced,
    cursors: session.cursors,
    registryAdditions: session.registryAdditions,
  };
}
