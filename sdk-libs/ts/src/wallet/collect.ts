import type { IndexerReader } from "../client/ports.js";
import type { IndexerRpcConfig } from "../client/retry.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { decodeOutputData } from "../transaction/serialization/codecs.js";

import { bytesKey } from "./internal.js";
import { readChunk } from "./paging.js";

/**
 * Rust admits any payload `decode_output_data` accepts, not only one already
 * flagged proofless: the deposit's own `ProoflessOutput` parse happens later, in
 * the wallet, and screening on the scheme here would drop a deposit the wallet
 * can still read.
 */
function isDecodablePayload(payload: Uint8Array): boolean {
  try {
    decodeOutputData(payload);
    return true;
  } catch {
    return false;
  }
}

/**
 * Photon can emit multiple shielded events in one Solana transaction. The
 * current wire response does not expose its event index, so the committed
 * output contexts (or nullifiers for an outputless event) form the stable
 * event identity instead of collapsing every event under the signature.
 */
export function shieldedTransactionKey(transaction: IndexedShieldedTransaction): string {
  return [
    transaction.txSignature,
    ...transaction.outputSlots.map(
      ({ outputContext }) =>
        `${outputContext.tree}:${String(outputContext.leafIndex)}:${bytesKey(outputContext.hash)}`,
    ),
    ...transaction.nullifiers.map(bytesKey),
  ].join("|");
}

export interface CollectByTagsInput {
  readonly indexer: Pick<
    IndexerReader,
    "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags"
  >;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** Where this group of tags was read to last sync, or undefined for never. */
  readonly from: Uint8Array | undefined;
}

export async function collectShieldedTransactions(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getShieldedTransactionsByTags", input.from, async (cursor) => {
    const response = await input.indexer.getShieldedTransactionsByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.nextRpcConfig(),
      context,
    );
    for (const transaction of response.transactions) {
      // Photon can surface a proofless deposit here before flagging it. Those
      // are collected from the encrypted-utxo endpoint instead, so taking them
      // twice would store the same UTXO under two keys.
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
}

export async function collectProoflessDeposits(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getEncryptedUtxosByTags", input.from, async (cursor) => {
    const response = await input.indexer.getEncryptedUtxosByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.nextRpcConfig(),
      context,
    );
    for (const match of response.matches) {
      if (match.txViewingPk !== undefined || match.salt !== undefined) continue;
      const key = [
        match.txSignature,
        match.outputSlot.outputContext.tree,
        String(match.outputSlot.outputContext.leafIndex),
        bytesKey(match.outputSlot.outputContext.hash),
      ].join("|");
      if (input.out.has(key)) continue;
      if (!isDecodablePayload(match.outputSlot.payload)) continue;
      input.out.set(
        key,
        Object.freeze({
          slot: match.slot,
          txSignature: match.txSignature,
          outputSlots: Object.freeze([match.outputSlot]),
          messages: Object.freeze([]),
          nullifiers: Object.freeze([]),
          proofless: true,
        }),
      );
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
}

export interface CollectByNullifiersInput {
  readonly indexer: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** Where this chunk was read to last time, if it has been read before. */
  readonly start?: Uint8Array;
}

/**
 * Returns how far the scan reached, or `undefined` if the indexer did not say.
 *
 * The position comes from `scannedThrough`, not from the rows: an unspent
 * nullifier matches nothing, so there is no last row to take a position from.
 * An indexer that does not report it leaves the caller starting from zero next
 * time, which is exactly the old behaviour.
 */
export async function collectShieldedTransactionsByNullifiers(
  input: CollectByNullifiersInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getShieldedTransactionsByNullifiers", input.start, async (cursor) => {
    const response = await input.indexer.getShieldedTransactionsByNullifiers(
      {
        nullifiers: input.chunk,
        limit: input.pageLimit,
        ...(cursor === undefined ? {} : { cursor }),
      },
      input.nextRpcConfig(),
      context,
    );
    for (const transaction of response.transactions) {
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
}
