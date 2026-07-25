import { MerkleTreeError } from "./errors.js";

import type { Bytes32 } from "@zolana/interface";

export type { Bytes32 };

export function bytes32(value: Uint8Array, field: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new MerkleTreeError("MERKLE_TREE_INVALID_BYTES", `${field} must contain 32 bytes`, {
      details: { field, actualLength: value instanceof Uint8Array ? value.length : undefined },
    });
  }
  return value.slice() as Bytes32;
}

export function copyBytes(value: Bytes32): Bytes32 {
  return value.slice() as Bytes32;
}

export function compareBytes(left: Bytes32, right: Bytes32): number {
  for (let index = 0; index < 32; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return 0;
}

export function equalBytes(left: Bytes32, right: Bytes32): boolean {
  return compareBytes(left, right) === 0;
}

const TWO_POW_256 = 1n << 256n;

export function bigintToBytes(value: bigint): Bytes32 {
  // `bigint_to_be_bytes_array::<32>` refuses anything wider than the array and
  // takes a `BigUint`, so neither a negative nor an oversized value has a
  // big-endian 32-byte form. Truncating silently would hand a caller a
  // different value than it asked to encode.
  if (value < 0n || value >= TWO_POW_256) {
    throw new MerkleTreeError(
      "MERKLE_TREE_INVALID_BYTES",
      "value does not fit in 32 big-endian bytes",
      { details: { value: value.toString() } },
    );
  }
  const result = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result as Bytes32;
}
