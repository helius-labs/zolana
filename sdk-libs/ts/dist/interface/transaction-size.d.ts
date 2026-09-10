import type { Transaction } from "./types.js";
import type { Shape } from "./shape.js";
/** Solana's `PACKET_DATA_SIZE`: the serialized transaction a validator accepts. */
export declare const TRANSACTION_SIZE_LIMIT = 1232;
export declare function transactionSize(transaction: Transaction): number;
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
export declare function checkedTransactionSize(transaction: Transaction, shape?: Shape): Transaction;
