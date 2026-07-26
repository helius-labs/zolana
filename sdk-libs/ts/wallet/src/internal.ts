import type { Address, Bytes32 } from "@zolana/interface";
import {
  decodeBase58 as decodeBase58Canonical,
  decodeBase64 as decodeBase64Canonical,
  encodeBase58 as encodeBase58Canonical,
} from "@zolana/interface";

import { WalletError } from "./error.js";

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
  let result: Uint8Array;
  try {
    result = decodeBase58Canonical(value);
  } catch {
    throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
  }
  if (encodeBase58Canonical(result) !== value) {
    throw new WalletError("WALLET_INVALID_ADDRESS", { details: { field } });
  }
  if (result.length !== length) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: { field, expected: length, actual: result.length },
    });
  }
  return result;
}

export function encodeBase58(value: Uint8Array): string {
  return encodeBase58Canonical(value);
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
  try {
    return decodeBase64Canonical(value);
  } catch {
    throw new WalletError("WALLET_INVALID_BASE64");
  }
}
