import type { Bytes32 } from "./types.js";

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bytesKey(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

// Reads every byte instead of returning at the first difference, so the time
// taken does not reveal where secret-derived bytes diverge.
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

export function rightAlign(bytes: Uint8Array): Bytes32 {
  const result = new Uint8Array(32);
  result.set(bytes, 32 - bytes.length);
  return result as Bytes32;
}
