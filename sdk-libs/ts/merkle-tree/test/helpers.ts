import type { Bytes32 } from "@zolana/interface";

import type { Hasher32 } from "../src/index.js";

export function required<T>(value: T | undefined, message = "missing test value"): T {
  if (value === undefined) {
    throw new Error(message);
  }
  return value;
}

export const modelHasher: Hasher32 = {
  hash(left, right) {
    const result = new Uint8Array(32);
    for (let index = 0; index < result.length; index += 1) {
      const leftByte = required(left[index]);
      const rightByte = required(right[(index + 1) % result.length]);
      result[index] = (leftByte * 31 + rightByte * 17 + index) & 0xff;
    }
    return result as Bytes32;
  },
};

export function leaf(value: number): Bytes32 {
  const result = new Uint8Array(32);
  result[31] = value;
  return result as Bytes32;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.every((value, index) => value === right[index]);
}

export function verifyPath(
  value: Uint8Array,
  index: bigint,
  path: readonly Uint8Array[],
): Uint8Array {
  let hash = value;
  let current = index;
  for (const sibling of path) {
    hash =
      (current & 1n) === 0n ? modelHasher.hash(hash, sibling) : modelHasher.hash(sibling, hash);
    current >>= 1n;
  }
  return hash;
}

export function modelRoot(height: number, leaves: readonly Uint8Array[]): Uint8Array {
  const capacity = 1 << height;
  let level = Array.from({ length: capacity }, (_, index) => leaves[index] ?? new Uint8Array(32));
  for (let depth = 0; depth < height; depth += 1) {
    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(modelHasher.hash(required(level[index]), required(level[index + 1])));
    }
    level = next;
  }
  return required(level[0]);
}
