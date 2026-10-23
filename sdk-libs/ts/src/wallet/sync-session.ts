import type { Address, Bytes32 } from "../interface/types.js";
import type { CheckpointStream, SyncDelta } from "../transaction/wallet/state.js";
import { Wallet } from "../transaction/wallet/state.js";

import { bytesKey } from "./internal.js";

/** @internal */
export interface WalletSyncSession {
  readonly staging: Wallet;
  readonly checkpoints: Readonly<Record<CheckpointStream, Map<string, bigint>>>;
  readonly registryAdditions: { assetId: bigint; mint: Address }[];
  readonly baseRevision: number;
}

/** @internal */
export function beginSyncSession(wallet: Wallet): WalletSyncSession {
  return {
    staging: wallet._clone(),
    checkpoints: { transactions: new Map(), proofless: new Map(), nullifiers: new Map() },
    registryAdditions: [],
    baseRevision: wallet._revision,
  };
}

/** @internal Session advances shadow the committed value. */
export function sessionCheckpoint(
  session: WalletSyncSession,
  stream: CheckpointStream,
  key: string,
): bigint | undefined {
  return session.checkpoints[stream].get(key) ?? session.staging._syncCheckpoint(stream, key);
}

/** @internal */
export function advanceSessionCheckpoints(
  session: WalletSyncSession,
  stream: CheckpointStream,
  keys: readonly Bytes32[],
  slot: bigint,
): void {
  for (const key of keys) {
    session.checkpoints[stream].set(bytesKey(key), slot);
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
    checkpoints: session.checkpoints,
    registryAdditions: session.registryAdditions,
  };
}
