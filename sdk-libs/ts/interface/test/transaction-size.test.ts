import { describe, expect, it } from "vitest";

import {
  TRANSACTION_SIZE_LIMIT,
  checkedTransactionSize,
  transactionSize,
  type Signature,
  type Transaction,
} from "../src/index.js";

function transaction(messageLength: number, signatureCount = 1): Transaction {
  return Object.freeze({
    messageBytes: new Uint8Array(messageLength),
    signatures: Object.freeze(
      Array.from({ length: signatureCount }, (): Signature | undefined => undefined),
    ),
  });
}

describe("transaction size", () => {
  it("counts the signature prefix, the signatures, and the message", () => {
    expect(TRANSACTION_SIZE_LIMIT).toBe(1232);
    expect(transactionSize(transaction(100))).toBe(1 + 64 + 100);
    expect(transactionSize(transaction(100, 3))).toBe(1 + 192 + 100);
    expect(transactionSize(transaction(0, 0))).toBe(1);
  });

  it("passes a transaction of exactly the limit through unchanged", () => {
    const exact = transaction(TRANSACTION_SIZE_LIMIT - 65);
    expect(transactionSize(exact)).toBe(TRANSACTION_SIZE_LIMIT);
    expect(checkedTransactionSize(exact)).toBe(exact);
  });

  it("refuses one byte over the limit and reports the two numbers", () => {
    expect(() => checkedTransactionSize(transaction(TRANSACTION_SIZE_LIMIT - 64))).toThrow(
      expect.objectContaining({
        code: "INTERFACE_TRANSACTION_TOO_LARGE",
        details: { size: TRANSACTION_SIZE_LIMIT + 1, limit: TRANSACTION_SIZE_LIMIT },
      }),
    );
  });

  it("names the proof shape when the caller chose one", () => {
    expect(() => checkedTransactionSize(transaction(2000), { inputs: 1, outputs: 8 })).toThrow(
      expect.objectContaining({
        code: "INTERFACE_TRANSACTION_TOO_LARGE",
        details: { size: 2065, limit: 1232, inputs: 1, outputs: 8 },
      }),
    );
  });
});
