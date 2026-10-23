import { wireDecoder } from "./decode.js";
import { PAGE_LIMIT } from "./indexer-limits.js";
import {
  comparePaginationTokens,
  paginationTokenPosition,
  transactionPosition,
} from "./pagination-token.js";
import type { HistoryFilters, PaginationToken, SlotFilter } from "./types.js";

export const SLOT_BOUNDS = ["gt", "gte", "lt", "lte"] as const;

/**
 * Copies caller filters with exact keys and bounds a JSON number carries
 * exactly. `undefined` when no bound is set, so an empty filter is never sent.
 */
export function checkedHistoryFilters(
  value: unknown,
  invalid: (field: string) => Error,
): HistoryFilters | undefined {
  if (value === undefined) return undefined;
  const { record } = wireDecoder(invalid);
  const exact = (candidate: unknown, field: string, keys: readonly string[]) => {
    const entries = record(candidate, field);
    if (Reflect.ownKeys(entries).some((key) => typeof key !== "string" || !keys.includes(key)))
      throw invalid(field);
    return entries;
  };
  const filters = exact(value, "filters", ["slot"]);
  if (filters["slot"] === undefined) return undefined;
  const bounds = exact(filters["slot"], "filters.slot", SLOT_BOUNDS);
  const slot: { -readonly [K in keyof SlotFilter]: SlotFilter[K] } = {};
  for (const bound of SLOT_BOUNDS) {
    const entry = bounds[bound];
    if (entry === undefined) continue;
    if (typeof entry !== "bigint" || entry < 0n || entry > BigInt(Number.MAX_SAFE_INTEGER))
      throw invalid(`filters.slot.${bound}`);
    slot[bound] = entry;
  }
  return Object.keys(slot).length === 0 ? undefined : Object.freeze({ slot: Object.freeze(slot) });
}

/** The controls of a history read that its answer must honour. */
export interface PageRequest {
  readonly paginationToken?: PaginationToken;
  readonly limit?: bigint;
  readonly filters?: HistoryFilters;
  readonly minContextSlot?: bigint;
}

interface ValidatedPage {
  readonly context: { readonly slot: bigint };
  readonly items: readonly { readonly slot: bigint; readonly signature: string }[];
  readonly paginationToken: PaginationToken | null;
}

/**
 * The last slot below the filter's range. An answer from a snapshot short of
 * it would hand back a checkpoint behind the one the caller resumed from.
 */
export function slotFilterFloor(filter: SlotFilter | undefined): bigint | undefined {
  let floor = filter?.gt;
  if (filter?.gte !== undefined && filter.gte > 0n && (floor === undefined || filter.gte > floor))
    floor = filter.gte - 1n;
  return floor;
}

export function slotInFilter(slot: bigint, filter: SlotFilter | undefined): boolean {
  return (
    (filter?.gt === undefined || slot > filter.gt) &&
    (filter?.gte === undefined || slot >= filter.gte) &&
    (filter?.lt === undefined || slot < filter.lt) &&
    (filter?.lte === undefined || slot <= filter.lte)
  );
}

/** The slot the answering snapshot must have reached: freshness, the token and the filter floor. */
export function requiredContextSlot(request: PageRequest): bigint | undefined {
  let minimum = request.minContextSlot;
  const raise = (slot: bigint | undefined): void => {
    if (slot !== undefined && (minimum === undefined || slot > minimum)) minimum = slot;
  };
  if (request.paginationToken !== undefined)
    raise(paginationTokenPosition(request.paginationToken).slot);
  raise(slotFilterFloor(request.filters?.slot));
  return minimum;
}

/** `null` ends the history; a token must move past the one the page was requested with. */
export function nextPageToken(
  page: { readonly paginationToken: PaginationToken | null },
  previous?: PaginationToken,
  invalid: () => Error = () => new Error("invalid pagination response"),
): PaginationToken | null {
  const token = page.paginationToken;
  if (token === null) return null;
  try {
    paginationTokenPosition(token);
    if (previous !== undefined && comparePaginationTokens(token, previous) <= 0) throw invalid();
  } catch {
    throw invalid();
  }
  return token;
}

/** Correlates a decoded page with its request before callers act on it. */
export function validatePage(page: ValidatedPage, request: PageRequest = {}): void {
  const fail = (): never => {
    throw new Error("invalid pagination response");
  };
  const minimum = requiredContextSlot(request);
  if (
    BigInt(page.items.length) > (request.limit ?? PAGE_LIMIT) ||
    (minimum !== undefined && page.context.slot < minimum)
  )
    fail();
  let previous = request.paginationToken;
  for (const item of page.items) {
    const position = transactionPosition(item.slot, item.signature);
    if (
      item.slot > page.context.slot ||
      !slotInFilter(item.slot, request.filters?.slot) ||
      (previous !== undefined && comparePaginationTokens(position, previous) <= 0)
    )
      fail();
    previous = position;
  }
  const token = nextPageToken(page, request.paginationToken);
  if (
    token !== null &&
    (paginationTokenPosition(token).slot > page.context.slot ||
      (previous !== undefined && comparePaginationTokens(token, previous) < 0))
  )
    fail();
}

/** An indexer page stops at its last transaction, so a token names it and never ends an empty page. */
export function validateIndexedPage(page: ValidatedPage, request: PageRequest = {}): void {
  validatePage(page, request);
  const last = page.items.at(-1);
  if (
    page.paginationToken !== null &&
    (last === undefined ||
      comparePaginationTokens(
        page.paginationToken,
        transactionPosition(last.slot, last.signature),
      ) !== 0)
  )
    throw new Error("invalid pagination response");
}
