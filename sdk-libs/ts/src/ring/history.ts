/** A ring's history read in order, each event bound to its confirmed transaction, Rust `pages`. */
import type { Address } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type { RequestContext } from "../interface/types.js";

import { nextScanCursor } from "./audit.js";
import { RingError } from "./error.js";
import type { ConfirmedRingTransaction, TransactionOrigin } from "./origin.js";

export interface ScanLimits {
  readonly pageSize: number;
  readonly maxPages: number;
}

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;

/** A limit outside its range is refused before any read. */
export function scanLimits(
  input: Readonly<{ pageSize?: number | undefined; maxPages?: number | undefined }>,
): ScanLimits {
  const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = input.maxPages ?? DEFAULT_MAX_PAGES;
  for (const [name, value, limit] of [
    ["pageSize", pageSize, Number(PAGE_LIMIT)],
    ["maxPages", maxPages, Number.MAX_SAFE_INTEGER],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > limit)
      throw new RingError("RING_RPC", { details: { reason: "invalid scan limit", name, value } });
  }
  return Object.freeze({ pageSize, maxPages });
}

/** The cursor the page cap stopped at, `undefined` once the read reached the scan frontier. */
export async function readRingHistory(
  input: Readonly<{
    client: Pick<IndexerReader, "getShieldedTransactionsByTags">;
    ringProgramId: Address;
    origin: TransactionOrigin;
    cursor?: Uint8Array;
    limits: ScanLimits;
  }>,
  visit: (confirmed: ConfirmedRingTransaction, eventIndex: number) => void,
  context: RequestContext | undefined,
): Promise<Uint8Array | undefined> {
  const { pageSize, maxPages } = input.limits;
  let cursor = input.cursor;
  for (let page = 0; page < maxPages; page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      {
        tags: [],
        ringProgramId: input.ringProgramId,
        limit: pageSize,
        ...(cursor === undefined ? {} : { cursor }),
      },
      undefined,
      context,
    );
    if (response.transactions.length > pageSize)
      throw new RingError("RING_RPC", {
        details: { reason: "history page exceeds requested limit" },
      });
    for (const indexed of response.transactions) {
      if (indexed.eventIndex === undefined)
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      const confirmed = await input.origin.confirmedTransaction(
        indexed,
        input.ringProgramId,
        context,
      );
      if (confirmed !== undefined) visit(confirmed, indexed.eventIndex);
    }
    const next = nextScanCursor(cursor, response);
    if (next === undefined) return undefined;
    cursor = next;
  }
  return cursor;
}
