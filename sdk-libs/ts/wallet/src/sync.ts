import type { ZolanaIndexer } from "@zolana/client";
import type { Bytes32, RequestContext } from "@zolana/interface";
import {
  decryptTransactions,
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "@zolana/transaction";
import type { IndexedShieldedTransaction } from "@zolana/transaction/instructions";

import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey } from "./internal.js";
import type { WalletAuthority } from "./wallet-authority.js";

export interface SyncWalletConfig {
  readonly tagWindow?: bigint;
  readonly tagQueryChunk?: number;
  readonly pageLimit?: number;
  readonly rounds?: number;
  readonly waitForIndexer?: boolean;
}

function positiveInteger(value: number, field: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", {
      details: { field, value, maximum },
    });
  }
  return value;
}

export async function syncWallet(
  input: Readonly<{
    wallet: Wallet;
    authority: WalletAuthority;
    indexer: ZolanaIndexer;
    config?: SyncWalletConfig;
  }>,
  context?: RequestContext,
): Promise<SyncReport> {
  try {
    const tagWindow = input.config?.tagWindow ?? 64n;
    if (tagWindow <= 0n || tagWindow > 10_000n) {
      throw new WalletError("WALLET_INVALID_SYNC_CONFIG", {
        details: { field: "tagWindow", value: tagWindow.toString() },
      });
    }
    const chunkSize = positiveInteger(input.config?.tagQueryChunk ?? 64, "tagQueryChunk", 1_000);
    const pageLimit = positiveInteger(input.config?.pageLimit ?? 1_000, "pageLimit", 1_000);
    const rounds = positiveInteger(input.config?.rounds ?? 6, "rounds", 100);
    const material = await input.authority.syncMaterial();
    const tags = new Map<string, Bytes32>();
    const add = (tag: Bytes32): void => {
      tags.set(bytesKey(tag), tag);
    };
    add(material.identity.signingPublicKey.confidentialViewTag());
    for (const key of material.viewingKeys) {
      add(key.recipientBootstrapViewTag());
      for (let count = 0n; count < tagWindow; count++) {
        add(key.senderViewTag(count));
        add(key.recipientRequestViewTag(count));
      }
    }
    const allTags = [...tags.values()];
    const collected = new Map<string, IndexedShieldedTransaction>();
    for (let round = 0; round < rounds; round++) {
      const before = collected.size;
      for (let offset = 0; offset < allTags.length; offset += chunkSize) {
        const chunk = allTags.slice(offset, offset + chunkSize);
        let cursor: Uint8Array | undefined;
        do {
          const request = {
            tags: chunk,
            limit: pageLimit,
            ...(cursor === undefined ? {} : { cursor }),
          };
          const response = await input.indexer.getShieldedTransactionsByTags(
            request,
            undefined,
            context,
          );
          for (const transaction of response.transactions) {
            const key = `${transaction.txSignature}:${transaction.outputSlots
              .map((slot) => bytesKey(slot.outputContext.hash))
              .join(",")}`;
            collected.set(key, transaction);
          }
          cursor = response.nextCursor;
        } while (cursor !== undefined);

        cursor = undefined;
        do {
          const request = {
            tags: chunk,
            limit: pageLimit,
            ...(cursor === undefined ? {} : { cursor }),
          };
          const response = await input.indexer.getEncryptedUtxosByTags(request, undefined, context);
          for (const match of response.matches) {
            const synthetic: IndexedShieldedTransaction = Object.freeze({
              slot: match.slot,
              txSignature: match.txSignature,
              ...(match.txViewingPk === undefined ? {} : { txViewingPublicKey: match.txViewingPk }),
              ...(match.salt === undefined ? {} : { salt: match.salt }),
              outputSlots: Object.freeze([match.outputSlot]),
              messages: Object.freeze([]),
              nullifiers: Object.freeze([]),
              proofless: true,
            });
            const output = synthetic.outputSlots[0];
            if (output === undefined) {
              throw new WalletError("WALLET_INVALID_INDEXER_RESPONSE");
            }
            collected.set(
              `${synthetic.txSignature}:${bytesKey(output.outputContext.hash)}`,
              synthetic,
            );
          }
          cursor = response.nextCursor;
        } while (cursor !== undefined);
      }
      if (collected.size === before) break;
      if (input.config?.waitForIndexer !== true) continue;
    }
    return await decryptTransactions({
      wallet: input.wallet,
      authority: input.authority,
      transactions: [...collected.values()],
      config: { tagWindow },
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_SYNC", cause);
  }
}

export function getPrivateTokenBalances(wallet: Wallet): readonly AssetBalance[] {
  return wallet.balances();
}

export function getPrivateTransactions(wallet: Wallet): readonly PrivateTransaction[] {
  return wallet.privateTransactions();
}
