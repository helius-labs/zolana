import type { RequestContext } from "../interface/types.js";
import { serializeWallet } from "../transaction/wallet/persistence.js";
import type { SyncReport } from "../transaction/wallet/state.js";

import { wrapWalletError } from "./error.js";
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

export interface SyncPersistedWalletResult {
  readonly report: SyncReport;
  readonly snapshot: string;
}

/**
 * Saves the snapshot exactly once, only after the sync commits. A failed sync
 * saves nothing. Serialize and save run inside the wallet's sync queue, an
 * overlapping call on the same wallet waits and cannot store a stale
 * snapshot, and `save` must not sync the same wallet. On `WALLET_PERSIST`
 * the in-memory wallet is committed and ahead of the store, the previous
 * snapshot stays valid, call again to retry the save.
 */
export async function syncPersistedWallet(
  input: SyncWalletInput & Readonly<{ store: Pick<WalletStateStore, "save"> }>,
  context?: RequestContext,
): Promise<SyncPersistedWalletResult> {
  return runLockedWalletSync(input, context, async (report) => {
    const snapshot = serializeWallet(input.wallet);
    try {
      await input.store.save(snapshot);
    } catch (cause) {
      throw wrapWalletError("WALLET_PERSIST", cause);
    }
    return Object.freeze({ report, snapshot });
  });
}
