import type { Address, Bytes32 } from "@zolana/interface";

import { WalletError } from "./error.js";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function copy32(value: Uint8Array, field: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: {
        field,
        expected: 32,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  }
  return new Uint8Array(value) as Bytes32;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function bytesKey(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function decodeBase58(value: string, length: number, field: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
  }
  const bytes = [0];
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) {
      throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
    }
    let carry = digit;
    for (let index = 0; index < bytes.length; index++) {
      const next = (bytes[index] ?? 0) * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let index = 0; index < value.length - 1 && value[index] === "1"; index++) bytes.push(0);
  const result = Uint8Array.from(bytes.reverse());
  if (result.length !== length) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: { field, expected: length, actual: result.length },
    });
  }
  return result;
}

export function encodeBase58(value: Uint8Array): string {
  if (value.length === 0) return "";
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let prefix = "";
  for (let index = 0; index < value.length - 1 && value[index] === 0; index++) prefix += "1";
  return (
    prefix +
    digits
      .reverse()
      .map((digit) => BASE58[digit])
      .join("")
  );
}

export function checkedAddress(value: Address, field: string): Address {
  decodeBase58(value, 32, field);
  return value;
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function base64Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = value.endsWith("==")
    ? value.slice(0, -2)
    : value.endsWith("=")
      ? value.slice(0, -1)
      : value;
  if (clean.length % 4 === 1) throw new WalletError("WALLET_INVALID_BASE64");
  let bits = 0;
  let bitCount = 0;
  const output: number[] = [];
  for (const character of clean) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new WalletError("WALLET_INVALID_BASE64");
    bits = bits * 64 + digit;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      output.push((bits >> bitCount) & 0xff);
      bits &= (1 << bitCount) - 1;
    }
  }
  return Uint8Array.from(output);
}
