import type { ZolanaIndexer } from "@zolana/client";
import type { Bytes16, Bytes32, RequestContext } from "@zolana/interface";
import { P256PublicKey } from "@zolana/keypair";
import {
  decryptTransactions,
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "@zolana/transaction";
import type { IndexedShieldedTransaction } from "@zolana/transaction/instructions";

import { WalletError, wrapWalletError } from "./error.js";
import { base64Bytes, bytesKey, decodeBase58, encodeBase58 } from "./internal.js";
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

function hashBytes(value: string): Bytes32 {
  return decodeBase58(value, 32, "hash") as Bytes32;
}

function convertTransaction(
  transaction: Awaited<
    ReturnType<ZolanaIndexer["getShieldedTransactionsByTags"]>
  >["transactions"][number],
): IndexedShieldedTransaction {
  const txViewingBytes =
    transaction.txViewingPk === undefined ? undefined : base64Bytes(transaction.txViewingPk);
  const salt =
    transaction.salt === undefined ? undefined : (base64Bytes(transaction.salt) as Bytes16);
  return Object.freeze({
    slot: transaction.slot,
    txSignature: transaction.txSignature,
    ...(txViewingBytes === undefined
      ? {}
      : {
          txViewingPublicKey: P256PublicKey.fromBytes(
            txViewingBytes as import("@zolana/interface").Bytes33,
          ),
        }),
    ...(salt === undefined ? {} : { salt }),
    outputSlots: Object.freeze(
      transaction.outputSlots.map((slot) =>
        Object.freeze({
          viewTag: hashBytes(slot.viewTag),
          outputContext: Object.freeze({
            hash: hashBytes(slot.outputContext.hash),
            tree: slot.outputContext.tree,
            leafIndex: slot.outputContext.leafIndex,
          }),
          payload: base64Bytes(slot.payload),
        }),
      ),
    ),
    messages: Object.freeze(
      transaction.messages.map((message) =>
        Object.freeze({
          viewTag: hashBytes(message.viewTag),
          data: base64Bytes(message.payload),
        }),
      ),
    ),
    nullifiers: Object.freeze(transaction.nullifiers.map(hashBytes)),
    proofless: transaction.proofless,
  });
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
        const chunk = allTags.slice(offset, offset + chunkSize).map((tag) => encodeBase58(tag));
        let cursor: string | undefined;
        do {
          const request = {
            tags: chunk,
            limit: BigInt(pageLimit),
            ...(cursor === undefined ? {} : { cursor }),
          } as never;
          const response = await input.indexer.getShieldedTransactionsByTags(request, context);
          for (const transaction of response.transactions) {
            const converted = convertTransaction(transaction);
            const key = `${converted.txSignature}:${converted.outputSlots
              .map((slot) => bytesKey(slot.outputContext.hash))
              .join(",")}`;
            collected.set(key, converted);
          }
          cursor = response.nextCursor;
        } while (cursor !== undefined);

        cursor = undefined;
        do {
          const request = {
            tags: chunk,
            limit: BigInt(pageLimit),
            ...(cursor === undefined ? {} : { cursor }),
          } as never;
          const response = await input.indexer.getEncryptedUtxosByTags(request, context);
          for (const match of response.matches) {
            const synthetic = convertTransaction({
              slot: match.slot,
              txSignature: match.txSignature,
              ...(match.txViewingPk === undefined ? {} : { txViewingPk: match.txViewingPk }),
              ...(match.salt === undefined ? {} : { salt: match.salt }),
              outputSlots: [match.outputSlot],
              messages: [],
              nullifiers: [],
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
