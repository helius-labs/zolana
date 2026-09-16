import { BN254_SCALAR_ORDER } from "../hasher/index.js";

const ORDER = Uint8Array.from(
  BN254_SCALAR_ORDER.toString(16).padStart(64, "0").match(/../gu) ?? [],
  (byte) => Number.parseInt(byte, 16),
);

export function isCanonicalField(value: Uint8Array): boolean {
  if (!(value instanceof Uint8Array) || value.length !== 32) return false;
  let borrow = 0;
  for (let index = 31; index >= 0; index--) {
    const byte = value[index];
    const order = ORDER[index];
    if (byte === undefined || order === undefined) return false;
    borrow = ((byte - order - borrow) >> 8) & 1;
  }
  return borrow === 1;
}
