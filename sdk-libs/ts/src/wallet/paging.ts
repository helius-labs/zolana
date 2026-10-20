import { ClientError } from "../client/error.js";

import { bytesKey } from "./internal.js";

/** One page of a cursor-ordered stream, reduced to what paging needs. */
export interface Page {
  readonly nextCursor?: Uint8Array | undefined;
  /** Where the server says its scan reached on a terminal page. */
  readonly scannedThrough?: Uint8Array | undefined;
}

function checkedNextCursor(
  method: string,
  cursor: Uint8Array | undefined,
  seen: Set<string>,
): Uint8Array | undefined {
  if (cursor === undefined) return undefined;
  const key = bytesKey(cursor);
  if (seen.has(key)) {
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method, path: "$.nextCursor" },
    });
  }
  seen.add(key);
  return cursor;
}

/**
 * Reads one chunk until the stream offers no further cursor.
 *
 * A cursor means there may be more, whatever the page size. Stopping on a short
 * page would make the non-advancing-cursor guard unreachable. Mirrors the Rust
 * SDK, which must agree or the two clients read different amounts.
 */
export async function readChunk(
  method: string,
  start: Uint8Array | undefined,
  request: (cursor: Uint8Array | undefined) => Promise<Page>,
): Promise<Uint8Array | undefined> {
  let cursor = start;
  let furthest = start;
  // Seeded with the resume point, so an indexer handing back the cursor it was
  // given trips the guard immediately rather than after a wasted round trip.
  const seenCursors = new Set<string>(start === undefined ? [] : [bytesKey(start)]);
  for (;;) {
    const page = await request(cursor);
    furthest = page.scannedThrough ?? page.nextCursor ?? furthest;
    const next = checkedNextCursor(method, page.nextCursor, seenCursors);
    if (next === undefined) return furthest;
    cursor = next;
  }
}
