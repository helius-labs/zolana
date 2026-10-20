import type { IndexerReader } from "../client/ports.js";
import type { IndexerRpcConfig } from "../client/retry.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";

import { WalletError } from "./error.js";
import { bytesKey } from "./internal.js";
import { readChunk } from "./paging.js";

/** Indices probed per indexer query. */
export const DEFAULT_TAG_WINDOW = 64n;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export function* windowIndices(start: bigint): Generator<bigint> {
  const end = start + DEFAULT_TAG_WINDOW - 1n;
  for (let index = start; index <= (end > U64_MAX ? U64_MAX : end); index++) yield index;
}

export class TagWindow {
  readonly #byTag = new Map<string, bigint>();
  readonly #tags: Bytes32[] = [];

  /** `tags` in index order from `start`, a short list ends the window early. */
  constructor(start: bigint, tags: Iterable<Bytes32>) {
    const indices = windowIndices(start);
    for (const tag of tags) {
      const index = indices.next();
      if (index.done) break;
      this.#byTag.set(bytesKey(tag), index.value);
      this.#tags.push(tag);
    }
  }

  static derive(start: bigint, tagAt: (index: bigint) => Bytes32): TagWindow {
    return new TagWindow(start, [...windowIndices(start)].map(tagAt));
  }

  tags(): readonly Bytes32[] {
    return this.#tags;
  }

  indexOf(tag: Bytes32): bigint | undefined {
    return this.#byTag.get(bytesKey(tag));
  }

  occupied(transactions: Iterable<IndexedShieldedTransaction>): ReadonlySet<bigint> {
    const occupied = new Set<bigint>();
    for (const tx of transactions) {
      for (const slot of tx.outputSlots) {
        const index = this.indexOf(slot.viewTag);
        if (index !== undefined) occupied.add(index);
      }
    }
    return occupied;
  }

  static firstFree(start: bigint, occupied: ReadonlySet<bigint>): bigint | undefined {
    for (const index of windowIndices(start)) if (!occupied.has(index)) return index;
    return undefined;
  }
}

/** An output nobody can decrypt still occupies its index. */
export class TagStream {
  readonly #indexer: Pick<IndexerReader, "getShieldedTransactionsByTags">;
  readonly #config: IndexerRpcConfig | undefined;
  readonly #pageLimit: number;

  constructor(
    indexer: Pick<IndexerReader, "getShieldedTransactionsByTags">,
    options: Readonly<{ config?: IndexerRpcConfig; pageLimit?: number }> = {},
  ) {
    this.#indexer = indexer;
    this.#config = options.config;
    this.#pageLimit = options.pageLimit ?? 1_000;
  }

  async firstFreeIndex(
    start: bigint,
    tagAt: (index: bigint) => Bytes32,
    context?: RequestContext,
  ): Promise<bigint> {
    let from = start;
    for (;;) {
      const free = TagWindow.firstFree(from, await this.occupiedIndices(from, tagAt, context));
      if (free !== undefined) return free;
      from += DEFAULT_TAG_WINDOW;
      if (from > U64_MAX) throw new WalletError("WALLET_TAG_STREAM_EXHAUSTED");
    }
  }

  async occupiedIndices(
    start: bigint,
    tagAt: (index: bigint) => Bytes32,
    context?: RequestContext,
  ): Promise<ReadonlySet<bigint>> {
    const window = TagWindow.derive(start, tagAt);
    const occupied = new Set<bigint>();
    await readChunk("getShieldedTransactionsByTags", undefined, async (cursor) => {
      const response = await this.#indexer.getShieldedTransactionsByTags(
        {
          tags: window.tags(),
          limit: this.#pageLimit,
          ...(cursor === undefined ? {} : { cursor }),
        },
        this.#config,
        context,
      );
      for (const index of window.occupied(response.transactions)) occupied.add(index);
      return { nextCursor: response.nextCursor, scannedThrough: response.scannedThrough };
    });
    return occupied;
  }
}
