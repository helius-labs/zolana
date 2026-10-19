import type { Bytes32, RequestContext } from "../../interface/types.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";

import { TransactionError } from "../error.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import { deriveAnswers } from "./key-batch.js";
import type { ShieldedKeys, ViewTagRequest } from "./keys.js";
import { hex } from "./state.js";

/** Unused counters after the last one in use that end a sender or request tag stream. */
export const TAG_GAP = 64n;

const U64_END = 1n << 64n;

/** One past the highest counter found in use, per stream of one viewing key. */
export interface ViewTagCounters {
  readonly txCount: bigint;
  readonly requestCount: bigint;
}

/** Tags found in use under one held viewing key, opened under that key alone. */
export interface KeyViewTags {
  readonly viewingPublicKey: X25519PublicKey;
  readonly tags: readonly Bytes32[];
}

type TagKind = "sender" | "request";

interface TagStream {
  readonly kind: TagKind;
  readonly viewingPublicKey: X25519PublicKey;
  /** One past the highest counter in use. */
  next: bigint;
  /** One past the highest counter derived. */
  end: bigint;
  readonly used: Map<string, Bytes32>;
}

function request(stream: TagStream, counter: bigint): ViewTagRequest {
  return stream.kind === "sender"
    ? { kind: "sender", viewingPublicKey: stream.viewingPublicKey, txCount: counter }
    : { kind: "request", viewingPublicKey: stream.viewingPublicKey, requestCount: counter };
}

/**
 * Mirrors Rust `TagStreams`, stateless across syncs, every sync derives from
 * zero and reads the used tags again.
 * @internal
 */
export class TagStreams {
  readonly #streams: readonly TagStream[];
  readonly #derived = new Map<string, Readonly<{ stream: number; counter: bigint }>>();

  constructor(viewingPublicKeys: readonly X25519PublicKey[]) {
    this.#streams = viewingPublicKeys.flatMap((viewingPublicKey) =>
      (["sender", "request"] as const).map((kind): TagStream => ({
        kind,
        viewingPublicKey,
        next: 0n,
        end: 0n,
        used: new Map(),
      })),
    );
  }

  /** Empty once every stream has `TAG_GAP` counters derived past its last use. */
  async nextWindow(keys: ShieldedKeys, context?: RequestContext): Promise<readonly Bytes32[]> {
    const positions: Readonly<{ stream: number; counter: bigint }>[] = [];
    const requests: ViewTagRequest[] = [];
    this.#streams.forEach((stream, index) => {
      const end = stream.next + TAG_GAP < U64_END ? stream.next + TAG_GAP : U64_END;
      for (let counter = stream.end; counter < end; counter++) {
        positions.push({ stream: index, counter });
        requests.push(request(stream, counter));
      }
      stream.end = end;
    });
    if (requests.length === 0) return [];
    const tags = deriveAnswers(
      await keys.viewTags(requests, context),
      requests.length,
      () => new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH"),
    );
    tags.forEach((tag, index) => {
      const position = positions[index];
      if (position !== undefined) this.#derived.set(hex(tag), position);
    });
    return tags;
  }

  record(transactions: Iterable<IndexedShieldedTransaction>): void {
    for (const tx of transactions) {
      const carried = [
        ...tx.outputSlots.map((slot) => slot.viewTag),
        ...tx.messages.map((message) => message.viewTag),
      ];
      for (const tag of carried) {
        const key = hex(tag);
        const position = this.#derived.get(key);
        if (position === undefined) continue;
        const stream = this.#streams[position.stream];
        if (stream === undefined) continue;
        if (position.counter >= stream.next) stream.next = position.counter + 1n;
        stream.used.set(key, tag);
      }
    }
  }

  nextCounters(viewingPublicKey: X25519PublicKey): ViewTagCounters {
    const next = (kind: TagKind): bigint =>
      this.#streams.find(
        (stream) => stream.kind === kind && stream.viewingPublicKey.equals(viewingPublicKey),
      )?.next ?? 0n;
    return Object.freeze({ txCount: next("sender"), requestCount: next("request") });
  }

  usedTags(): readonly KeyViewTags[] {
    return this.#streams
      .filter((stream) => stream.used.size > 0)
      .map((stream) =>
        Object.freeze({
          viewingPublicKey: stream.viewingPublicKey,
          tags: Object.freeze([...stream.used.values()]),
        }),
      );
  }
}
