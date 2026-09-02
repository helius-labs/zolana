import { TransactionError } from "./error.js";

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export function formatAmount(amount: bigint, decimals: number): string {
  checkRawAmount(amount);
  checkDecimals(decimals);
  if (decimals === 0) return amount.toString();
  const scale = 10n ** BigInt(decimals);
  const whole = amount / scale;
  const fraction = (amount % scale).toString().padStart(decimals, "0").replace(/0+$/u, "");
  return fraction.length === 0 ? whole.toString() : `${String(whole)}.${fraction}`;
}

export function parseAmount(value: string, decimals: number): bigint {
  checkDecimals(decimals);
  if (
    typeof value !== "string" ||
    value.length > decimals + 21 ||
    !/^(0|[1-9]\d*)(?:\.(\d+))?$/u.test(value)
  ) {
    throw new TransactionError("TRANSACTION_INVALID_DISPLAY_AMOUNT");
  }
  const [whole = "", fraction = ""] = value.split(".");
  if (fraction.length > decimals) {
    throw new TransactionError("TRANSACTION_INVALID_DISPLAY_AMOUNT");
  }
  const scale = 10n ** BigInt(decimals);
  const amount = BigInt(whole) * scale + BigInt(fraction.padEnd(decimals, "0") || "0");
  checkRawAmount(amount);
  return amount;
}

function checkRawAmount(amount: bigint): void {
  if (typeof amount !== "bigint" || amount < 0n || amount > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT");
  }
}

function checkDecimals(decimals: number): void {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new TransactionError("TRANSACTION_INVALID_DECIMALS");
  }
}
