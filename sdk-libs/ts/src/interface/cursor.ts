import { getBase58Decoder, getBase58Encoder } from "@solana/kit";

const encoder = getBase58Encoder();
const decoder = getBase58Decoder();

/** Internal codec. Public callers carry the returned string unchanged. */
export function cursorPosition(value: unknown): {
  readonly slot: bigint;
  readonly signature: Uint8Array;
} {
  if (typeof value !== "string" || value.length > 112) throw new Error("invalid pagination cursor");
  const parts = /^1:(0|[1-9][0-9]{0,19}):([1-9A-HJ-NP-Za-km-z]{64,88})$/.exec(value);
  const slotText = parts?.[1];
  const signatureText = parts?.[2];
  if (slotText === undefined || signatureText === undefined)
    throw new Error("invalid pagination cursor");
  const slot = BigInt(slotText);
  const signature = Uint8Array.from(encoder.encode(signatureText));
  if (
    slot > 0xffff_ffff_ffff_ffffn ||
    signature.length !== 64 ||
    decoder.decode(signature) !== signatureText
  ) {
    throw new Error("invalid pagination cursor");
  }
  return { slot, signature };
}

export function checkedCursor(value: unknown): string {
  cursorPosition(value);
  if (typeof value !== "string") throw new Error("invalid pagination cursor");
  return value;
}

export function compareCursors(left: string, right: string): number {
  const a = cursorPosition(left);
  const b = cursorPosition(right);
  if (a.slot !== b.slot) return a.slot < b.slot ? -1 : 1;
  for (let i = 0; i < 64; i++) {
    const difference = a.signature[i]! - b.signature[i]!;
    if (difference !== 0) return difference;
  }
  return 0;
}
