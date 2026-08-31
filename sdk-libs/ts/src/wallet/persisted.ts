import type { RequestContext } from "../interface/types.js";
import { deserializeWallet, serializeWallet } from "../transaction/wallet/persistence.js";
import type { SyncReport, Wallet } from "../transaction/wallet/state.js";

import { WalletError, wrapWalletError } from "./error.js";
import { runLockedWalletSync, type SyncWalletInput } from "./sync.js";

/**
 * Snapshots contain private note data, encrypt them at rest. `save` must
 * replace the stored snapshot atomically or leave it unchanged, a partial
 * write breaks the retry contract of `syncPersistedWallet`. Single writer
 * per stored snapshot, a stale overwrite loses only sync progress the next
 * sync recovers.
 */
export interface WalletStateStore {
  load(): Promise<string | undefined>;
  save(snapshot: string): Promise<void>;
}

/**
 * The authenticated boundary in front of the store. `open` must refuse a
 * sealed snapshot it did not seal for the same wallet, a store that can be
 * modified would otherwise advance the persisted cursors past owned history.
 * `walletSnapshotCipher` is the shipped implementation.
 */
export interface WalletStateCipher {
  seal(snapshot: string): Promise<string>;
  open(sealed: string): Promise<string>;
}

export interface SyncPersistedWalletResult {
  readonly report: SyncReport;
  readonly snapshot: string;
}

/**
 * Seals and saves the snapshot exactly once, only after the sync commits. A
 * failed sync saves nothing. Serialize, seal, and save run inside the wallet's
 * sync queue, an overlapping call on the same wallet waits and cannot store a
 * stale snapshot, and `save` must not sync the same wallet. On
 * `WALLET_PERSIST` the in-memory wallet is committed and ahead of the store,
 * the previous snapshot stays valid, call again to retry the save.
 */
export async function syncPersistedWallet(
  input: SyncWalletInput &
    Readonly<{ store: Pick<WalletStateStore, "save">; cipher: WalletStateCipher }>,
  context?: RequestContext,
): Promise<SyncPersistedWalletResult> {
  return runLockedWalletSync(input, context, async (report) => {
    const snapshot = serializeWallet(input.wallet);
    let sealed: string;
    try {
      sealed = await input.cipher.seal(snapshot);
    } catch (cause) {
      throw wrapWalletError("WALLET_SNAPSHOT", cause);
    }
    try {
      await input.store.save(sealed);
    } catch (cause) {
      throw wrapWalletError("WALLET_PERSIST", cause);
    }
    return Object.freeze({ report, snapshot });
  });
}

/** The stored snapshot, opened and restored, or `undefined` for an empty store. */
export async function loadPersistedWallet(
  input: Readonly<{ store: Pick<WalletStateStore, "load">; cipher: WalletStateCipher }>,
): Promise<Wallet | undefined> {
  const sealed = await input.store.load();
  if (sealed === undefined) return undefined;
  let snapshot: string;
  try {
    snapshot = await input.cipher.open(sealed);
  } catch (cause) {
    if (cause instanceof WalletError) throw cause;
    throw wrapWalletError("WALLET_SNAPSHOT", cause);
  }
  return deserializeWallet(snapshot);
}
