import { describe, expect, it } from "vitest";

import { formatAmount, parseAmount } from "../src/transaction/amount.js";

describe("asset amounts", () => {
  it("formats raw units without losing precision", () => {
    expect(formatAmount(0n, 6)).toBe("0");
    expect(formatAmount(1n, 6)).toBe("0.000001");
    expect(formatAmount(1_230_000n, 6)).toBe("1.23");
    expect(formatAmount(0xffff_ffff_ffff_ffffn, 0)).toBe("18446744073709551615");
  });

  it("parses canonical decimal amounts into raw units", () => {
    expect(parseAmount("0", 6)).toBe(0n);
    expect(parseAmount("0.000001", 6)).toBe(1n);
    expect(parseAmount("1.23", 6)).toBe(1_230_000n);
  });

  it.each(["01", ".1", "1.", "1e3", "1.0000001", "-1", "+1", "1,000"])(
    "rejects noncanonical amount %s",
    (value) => {
      expect(() => parseAmount(value, 6)).toThrow("TRANSACTION_INVALID_DISPLAY_AMOUNT");
    },
  );

  it("rejects invalid decimal precision and u64 overflow", () => {
    expect(() => formatAmount(1n, -1)).toThrow("TRANSACTION_INVALID_DECIMALS");
    expect(() => parseAmount("18446744073709551616", 0)).toThrow("TRANSACTION_INVALID_AMOUNT");
  });
});
