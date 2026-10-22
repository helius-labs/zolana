import { compareCursors, cursorPosition } from "./cursor.js";
import { PAGE_LIMIT } from "./indexer-limits.js";

/** A continuation must exist and advance whenever the server reports more history. */
export function nextPageCursor(
  page: { readonly cursor: string | null; readonly hasMore: boolean },
  after?: string,
  invalid: () => Error = () => new Error("invalid pagination response"),
): string | null {
  try {
    if (typeof page.hasMore !== "boolean") throw invalid();
    if (page.cursor !== null) cursorPosition(page.cursor);
    if (
      page.hasMore &&
      (page.cursor === null || (after !== undefined && compareCursors(page.cursor, after) <= 0))
    )
      throw invalid();
  } catch {
    throw invalid();
  }
  return page.hasMore ? page.cursor : null;
}

/** Correlates a decoded page with its request before callers can advance a checkpoint. */
export function validatePage(
  page: {
    readonly context: { readonly slot: bigint };
    readonly items: readonly { readonly slot: bigint; readonly signature: string }[];
    readonly cursor: string | null;
    readonly hasMore: boolean;
  },
  options: {
    readonly after?: string;
    readonly limit?: bigint;
    readonly minContextSlot?: bigint;
  } = {},
): void {
  const fail = (): never => {
    throw new Error("invalid pagination response");
  };
  if (
    BigInt(page.items.length) > (options.limit ?? PAGE_LIMIT) ||
    (options.minContextSlot !== undefined && page.context.slot < options.minContextSlot)
  )
    fail();
  let previous = options.after;
  for (const item of page.items) {
    const position = `1:${item.slot}:${item.signature}`;
    if (
      item.slot > page.context.slot ||
      (previous !== undefined && compareCursors(position, previous) <= 0)
    )
      fail();
    previous = position;
  }
  if (page.cursor !== null && cursorPosition(page.cursor).slot > page.context.slot) fail();
  if (previous !== undefined && (page.cursor === null || compareCursors(page.cursor, previous) < 0))
    fail();
  nextPageCursor(page, options.after);
}

export function validateIndexedPage(
  page: Parameters<typeof validatePage>[0],
  options: Parameters<typeof validatePage>[1] = {},
): void {
  validatePage(page, options);
  const last = page.items.at(-1);
  if (page.hasMore && (last === undefined || page.cursor !== `1:${last.slot}:${last.signature}`))
    throw new Error("invalid pagination response");
}
