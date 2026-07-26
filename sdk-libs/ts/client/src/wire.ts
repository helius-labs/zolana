import type { Transaction } from "@zolana/interface";

import { ClientError } from "./error.js";

/** The largest transaction a Solana node accepts, in bytes. */
export const MAX_TRANSACTION_SIZE = 1232;

/**
 * Serialized byte length of `transaction`, counting the compact-u16 signature
 * count, one 64-byte slot per signature, and the compiled message.
 *
 * This measures rather than refuses. Rust compiles an oversized transaction and
 * lets the node reject it, so a local refusal here would turn a shape the Rust
 * client accepts into a TypeScript error.
 */
export function transactionSize(transaction: Transaction): number {
  return (
    compactU16(transaction.signatures.length).length +
    64 * transaction.signatures.length +
    transaction.messageBytes.length
  );
}

/** Solana's compact-u16: seven bits per byte, high bit marking continuation. */
export function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER");
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}
