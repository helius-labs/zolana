import type { IndexerReader } from "../client/ports.js";
import type { IndexerRpcConfig } from "../client/retry.js";
import type { Address, RequestContext } from "../interface/types.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { EncryptedScheme, readOutputData } from "../transaction/serialization/codecs.js";
import { AnonymousTagRoutes } from "../transaction/wallet/anonymous.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import type { SyncReport, Wallet } from "../transaction/wallet/state.js";
import { decryptTransactions } from "../transaction/wallet/sync.js";
import type { DepositPayloadDecoder } from "../transaction/serialization/ring-deposit.js";

import { WalletError, wrapWalletError } from "./error.js";
import { equalBytes } from "./internal.js";

export type AnonymousRecoveryClient = Pick<IndexerReader, "getShieldedTransactionsByTags">;

export interface AnonymousRingRecoveryParams {
  readonly wallet: Wallet;
  readonly keys: ShieldedKeys;
  readonly client: AnonymousRecoveryClient;
  readonly ringProgramId: Address;
  /** The confirmed slot the scan runs through, a later transaction is left to sync. */
  readonly head: bigint;
  readonly pageSize?: number;
  readonly maxPages?: number;
  readonly indexerConfig?: IndexerRpcConfig;
  readonly depositPayloadDecoder?: DepositPayloadDecoder;
}

export interface AnonymousRingRecoveryReport {
  readonly head: bigint;
  /** Confirmed ring transactions through `head` whose scheme-9 slots were all tried. */
  readonly scannedTransactions: number;
  readonly sync: SyncReport;
}

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;

/** Tries every scheme-9 slot of every confirmed ring transaction through `head` regardless of tag, fails on an uncovered head, trusts the indexer for completeness. */
export async function recoverAnonymousRing(
  params: AnonymousRingRecoveryParams,
  context?: RequestContext,
): Promise<AnonymousRingRecoveryReport> {
  const pageSize = params.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = params.maxPages ?? DEFAULT_MAX_PAGES;
  for (const [name, value] of [
    ["pageSize", pageSize],
    ["maxPages", maxPages],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new WalletError("WALLET_INVALID_SYNC_CONFIG", { details: { field: name } });
    }
  }
  if (params.head < 0n) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", { details: { field: "head" } });
  }
  try {
    const transactions = await ringHistory(params, pageSize, maxPages, context);
    const viewingPublicKey = params.keys.address().viewingPublicKey;
    const routes = new AnonymousTagRoutes();
    for (const tx of transactions) {
      for (const slot of tx.outputSlots) {
        if (isRingAnonymous(slot.payload)) {
          routes.route(slot.viewTag, viewingPublicKey, { kind: "recovered" });
        }
      }
    }
    const sync = await params.wallet._withSyncLock(() =>
      decryptTransactions({
        wallet: params.wallet,
        keys: params.keys,
        transactions,
        anonymous: routes,
        ...(params.depositPayloadDecoder === undefined
          ? {}
          : { config: { depositPayloadDecoder: params.depositPayloadDecoder } }),
        ...(context === undefined ? {} : { context }),
      }),
    );
    return Object.freeze({ head: params.head, scannedTransactions: transactions.length, sync });
  } catch (cause) {
    throw wrapWalletError("WALLET_SYNC", cause);
  }
}

/** Confirmed ring transactions through `head`, in page order. */
async function ringHistory(
  params: AnonymousRingRecoveryParams,
  pageSize: number,
  maxPages: number,
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  let cursor: Uint8Array | undefined;
  for (let page = 0; page < maxPages; page++) {
    const response = await params.client.getShieldedTransactionsByTags(
      {
        tags: [],
        ringProgramId: params.ringProgramId,
        limit: pageSize,
        ...(cursor === undefined ? {} : { cursor }),
      },
      params.indexerConfig,
      context,
    );
    for (const tx of response.transactions) {
      if (tx.proofless || tx.slot > params.head) continue;
      if (tx.txViewingPublicKey === undefined || tx.salt === undefined) continue;
      transactions.push(tx);
    }
    // Photon also returns the last row's cursor on a terminal page, only the
    // scanned-through frontier marks a complete scan.
    if (response.scannedThrough !== undefined) return transactions;
    const next = response.nextCursor;
    if (next === undefined) {
      throw new WalletError("WALLET_RECOVERY_INCOMPLETE", {
        details: { reason: "no scan frontier" },
      });
    }
    if (cursor !== undefined && equalBytes(cursor, next)) {
      throw new WalletError("WALLET_RECOVERY_INCOMPLETE", {
        details: { reason: "cursor did not advance" },
      });
    }
    cursor = next;
  }
  throw new WalletError("WALLET_RECOVERY_INCOMPLETE", {
    details: { reason: "page limit", maxPages },
  });
}

function isRingAnonymous(payload: Uint8Array): boolean {
  try {
    const frame = readOutputData(payload);
    return frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringAnonymous;
  } catch {
    return false;
  }
}
