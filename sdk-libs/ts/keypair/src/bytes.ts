import { KeypairError, invalidLength } from "./error.js";

type FixedBytes<Length extends number> = Uint8Array & {
  readonly __fixedBytesLength: Length;
};

export type Address = string & { readonly __address: unique symbol };
export type Bytes16 = FixedBytes<16>;
export type Bytes31 = FixedBytes<31>;
export type Bytes32 = FixedBytes<32>;
export type Bytes33 = FixedBytes<33>;
export type Bytes34 = FixedBytes<34>;
export type Bytes64 = FixedBytes<64>;

export function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export function checkedBytes<T extends Uint8Array>(
  bytes: Uint8Array | T,
  length: number,
  name: string,
): T {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw invalidLength(name, length, bytes instanceof Uint8Array ? bytes.length : -1);
  }
  return new Uint8Array(bytes) as T;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  // `bigint_to_be_bytes_array` takes a `BigUint` and returns
  // `InvalidInputLength` when the value needs more bytes than the array holds,
  // so neither a negative nor an oversized value has a big-endian form. Writing
  // the low bytes anyway would hand the caller a different value than it asked
  // to encode, and for a negative it would be an all-ones prefix.
  if (value < 0n) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name: "bigIntToBytes",
      reason: "negative",
    });
  }
  const width = byteWidth(value);
  if (width > length) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name: "bigIntToBytes",
      expected: length,
      actual: width,
    });
  }
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index--) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

/** Significant bytes in the big-endian form; zero needs none. */
function byteWidth(value: bigint): number {
  let width = 0;
  for (let remaining = value; remaining > 0n; remaining >>= 8n) width++;
  return width;
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

export function u32be(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

export function u64be(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
