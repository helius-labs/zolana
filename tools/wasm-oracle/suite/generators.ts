import fc from "fast-check";

export const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;

/**
 * Values that sit on a boundary the implementations could disagree about: the
 * ends of the field, the ends of the 32-byte range, and the small values a
 * bit-shift mistake would produce.
 */
const FIELD_EDGES: readonly bigint[] = Object.freeze([
  0n,
  1n,
  2n,
  BN254_MODULUS - 2n,
  BN254_MODULUS - 1n,
  BN254_MODULUS,
  BN254_MODULUS + 1n,
  (1n << 128n) - 1n,
  1n << 128n,
  (1n << 255n) - 1n,
  (1n << 256n) - 1n,
]);

export function bigintTo32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

/**
 * 32-byte leaves weighted towards the values Poseidon accepts.
 *
 * A uniform 32-byte array lands below the BN254 modulus about one time in eight,
 * so a uniform generator spends most of its budget on cases where both sides
 * reject and never compares a root. Masking the top byte keeps the value inside
 * the field; the edge list and the uniform branch keep the rejection boundary in
 * the sample.
 */
export const fieldLeaf: fc.Arbitrary<Uint8Array> = fc.oneof(
  { arbitrary: fc.uint8Array({ minLength: 32, maxLength: 32 }).map(insideField), weight: 8 },
  { arbitrary: fc.constantFrom(...FIELD_EDGES).map(bigintTo32), weight: 3 },
  { arbitrary: fc.uint8Array({ minLength: 32, maxLength: 32 }), weight: 1 },
);

/** Field-sized integers, weighted the same way as `fieldLeaf`. */
export const fieldInteger: fc.Arbitrary<bigint> = fc.oneof(
  { arbitrary: fc.bigInt({ min: 0n, max: BN254_MODULUS - 1n }), weight: 8 },
  { arbitrary: fc.constantFrom(...FIELD_EDGES), weight: 3 },
  { arbitrary: fc.bigInt({ min: 0n, max: (1n << 256n) - 1n }), weight: 1 },
);

function insideField(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes);
  // The modulus starts with 0x30, so a first byte below it bounds the value.
  copy[0] = (copy[0] ?? 0) % 0x30;
  return copy;
}
