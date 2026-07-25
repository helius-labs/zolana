import type { Address } from "@zolana/interface";

import { TestKitError } from "./error.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function encodeBase58(value: Uint8Array): string {
  let encoded = 0n;
  for (const byte of value) encoded = encoded * 256n + BigInt(byte);
  let result = "";
  while (encoded > 0n) {
    result = (ALPHABET[Number(encoded % 58n)] ?? "") + result;
    encoded /= 58n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) zeros++;
  return "1".repeat(zeros) + result;
}

/**
 * Decodes to a fixed width because every caller here holds a 32-byte account
 * key or blockhash: a short decode would otherwise be padded silently into the
 * wrong account.
 */
export function decodeBase58(value: string, field: string, length = 32): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field } });
  }
  let decoded = 0n;
  for (const character of value) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", { details: { field } });
    }
    decoded = decoded * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.push(Number(decoded & 255n));
    decoded >>= 8n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros++;
  const result = Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
  if (result.length !== length) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field, expected: length, actual: result.length },
    });
  }
  return result;
}

export function decodeAddress(value: Address, field: string): Uint8Array {
  return decodeBase58(value, field);
}
