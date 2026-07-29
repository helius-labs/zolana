import { getTransactionSize } from "@solana/kit";

import { InterfaceError } from "./errors.js";
import type { Transaction } from "./types.js";
import type { Shape } from "./shape.js";

/** Solana's `PACKET_DATA_SIZE`: the serialized transaction a validator accepts. */
export const TRANSACTION_SIZE_LIMIT = 1232;

export function transactionSize(transaction: Transaction): number {
  return getTransactionSize(transaction);
}

/**
 * Refuse a transaction the network cannot accept, naming the proof shape that
 * produced it when the caller chose one.
 *
 * A serialized transaction over `TRANSACTION_SIZE_LIMIT` is dropped before
 * execution, and confirmation cannot tell a dropped transaction from a slow
 * one, so a caller that sends one waits out the confirmation and is told it
 * timed out. Measuring at compile time reports the size instead, while the
 * caller can still send to fewer recipients.
 */
export function checkedTransactionSize(transaction: Transaction, shape?: Shape): Transaction {
  const size = transactionSize(transaction);
  if (size > TRANSACTION_SIZE_LIMIT) {
    throw new InterfaceError("INTERFACE_TRANSACTION_TOO_LARGE", {
      size,
      limit: TRANSACTION_SIZE_LIMIT,
      ...(shape === undefined ? {} : { inputs: shape.inputs, outputs: shape.outputs }),
    });
  }
  return transaction;
}
