import { getBase58Decoder, getBase58Encoder } from "@solana/kit";

import type { PaginationToken } from "./types.js";

const encoder = getBase58Encoder();
const decoder = getBase58Decoder();

/** Internal codec. Public callers carry the returned string unchanged. */
export function paginationTokenPosition(value: unknown): {
  readonly slot: bigint;
  readonly signature: Uint8Array;
} {
  if (typeof value !== "string" || value.length > 112) throw new Error("invalid pagination token");
  const parts = /^1:(0|[1-9][0-9]{0,19}):([1-9A-HJ-NP-Za-km-z]{64,88})$/.exec(value);
  const slotText = parts?.[1];
  const signatureText = parts?.[2];
  if (slotText === undefined || signatureText === undefined)
    throw new Error("invalid pagination token");
  const slot = BigInt(slotText);
  const signature = Uint8Array.from(encoder.encode(signatureText));
  if (
    slot > 0xffff_ffff_ffff_ffffn ||
    signature.length !== 64 ||
    decoder.decode(signature) !== signatureText
  ) {
    throw new Error("invalid pagination token");
  }
  return { slot, signature };
}

export function checkedPaginationToken(value: unknown): PaginationToken {
  paginationTokenPosition(value);
  if (typeof value !== "string") throw new Error("invalid pagination token");
  return value;
}

/** Slot first, then raw signature bytes, the order Photon pages in. */
export function comparePaginationTokens(left: PaginationToken, right: PaginationToken): number {
  const a = paginationTokenPosition(left);
  const b = paginationTokenPosition(right);
  if (a.slot !== b.slot) return a.slot < b.slot ? -1 : 1;
  for (let i = 0; i < 64; i++) {
    const difference = a.signature[i]! - b.signature[i]!;
    if (difference !== 0) return difference;
  }
  return 0;
}

/** The token naming one transaction's position. */
export function transactionPosition(slot: bigint, signature: string): PaginationToken {
  return `1:${slot}:${signature}`;
}
