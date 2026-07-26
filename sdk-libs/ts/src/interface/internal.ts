import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { address, getAddressDecoder, getAddressEncoder, type Address } from "@solana/kit";

import { InterfaceError } from "./errors.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();

export function fail(
  code: InterfaceError["code"],
  details?: Readonly<Record<string, unknown>>,
  cause?: unknown,
): never {
  throw new InterfaceError(code, details, cause);
}

export function copyBytes(value: Uint8Array, length?: number, name = "bytes"): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: "non-bytes" });
  }
  if (length !== undefined && value.length !== length) {
    fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: value.length });
  }
  return value.slice();
}

export function unsigned(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", { name, minimum: 0, maximum, actual: value });
  }
  return value;
}

export function unsignedBigint(value: bigint, maximum: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", {
      name,
      minimum: "0",
      maximum: maximum.toString(),
      actual: String(value),
    });
  }
  return value;
}

export function signedBigint(
  value: bigint,
  minimum: bigint,
  maximum: bigint,
  name: string,
): bigint {
  if (typeof value !== "bigint" || value < minimum || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", {
      name,
      minimum: minimum.toString(),
      maximum: maximum.toString(),
      actual: String(value),
    });
  }
  return value;
}

export function addressBytes(value: Address, name = "address"): Uint8Array {
  try {
    return new Uint8Array(addressEncoder.encode(value));
  } catch (cause) {
    fail("INTERFACE_INVALID_ADDRESS", { name, actual: value }, cause);
  }
}

export function checkedAddress(value: string, name = "address"): Address {
  try {
    return address(value);
  } catch (cause) {
    fail("INTERFACE_INVALID_ADDRESS", { name, actual: value }, cause);
  }
}

export function encodeBase58(bytes: Uint8Array): Address {
  try {
    return addressDecoder.decode(bytes);
  } catch (cause) {
    fail("INTERFACE_INVALID_ADDRESS", { actual: "invalid address bytes" }, cause);
  }
}

export function sha256(input: Uint8Array): Uint8Array {
  return nobleSha256(input);
}

export class Writer {
  readonly #bytes: number[] = [];

  bytes(value: Uint8Array, length?: number, name?: string): this {
    this.#bytes.push(...copyBytes(value, length, name));
    return this;
  }

  u8(value: number, name: string): this {
    this.#bytes.push(unsigned(value, 0xff, name));
    return this;
  }

  bool(value: boolean, name: string): this {
    if (typeof value !== "boolean") fail("INTERFACE_CODEC", { name, actual: value });
    this.#bytes.push(value ? 1 : 0);
    return this;
  }

  u16(value: number, name: string): this {
    const checked = unsigned(value, 0xffff, name);
    this.#bytes.push(checked & 255, checked >>> 8);
    return this;
  }

  u32(value: number, name: string): this {
    const checked = unsigned(value, 0xffffffff, name);
    this.#bytes.push(checked & 255, (checked >>> 8) & 255, (checked >>> 16) & 255, checked >>> 24);
    return this;
  }

  u64(value: bigint, name: string): this {
    return this.integer(unsignedBigint(value, (1n << 64n) - 1n, name), 8);
  }

  i64(value: bigint, name: string): this {
    const checked = signedBigint(value, -(1n << 63n), (1n << 63n) - 1n, name);
    return this.integer(checked < 0n ? checked + (1n << 64n) : checked, 8);
  }

  option<T>(value: T | undefined, write: (writer: Writer, value: T) => void): this {
    this.bool(value !== undefined, "option");
    if (value !== undefined) write(this, value);
    return this;
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }

  private integer(value: bigint, length: number): this {
    for (let index = 0; index < length; index += 1) {
      this.#bytes.push(Number((value >> BigInt(index * 8)) & 255n));
    }
    return this;
  }
}

export class Reader {
  #offset = 0;

  constructor(private readonly input: Uint8Array) {
    copyBytes(input);
  }

  bytes(length: number, name: string): Uint8Array {
    const end = this.#offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.input.length) {
      fail("INTERFACE_CODEC", {
        name,
        offset: this.#offset,
        expected: length,
        remaining: this.input.length - this.#offset,
      });
    }
    const value = this.input.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  u8(name: string): number {
    return arrayValue(this.bytes(1, name), 0);
  }

  bool(name: string): boolean {
    const value = this.u8(name);
    if (value !== 0 && value !== 1) fail("INTERFACE_CODEC", { name, actual: value });
    return value === 1;
  }

  nonzeroBool(name: string): boolean {
    return this.u8(name) !== 0;
  }

  u16(name: string): number {
    const value = this.bytes(2, name);
    return arrayValue(value, 0) | (arrayValue(value, 1) << 8);
  }

  u32(name: string): number {
    const value = this.bytes(4, name);
    return (
      arrayValue(value, 0) +
      arrayValue(value, 1) * 0x100 +
      arrayValue(value, 2) * 0x10000 +
      arrayValue(value, 3) * 0x1000000
    );
  }

  u64(name: string): bigint {
    return this.integer(8, name);
  }

  i64(name: string): bigint {
    const value = this.integer(8, name);
    return value >= 1n << 63n ? value - (1n << 64n) : value;
  }

  option<T>(name: string, read: (reader: Reader) => T): T | undefined {
    return this.bool(name) ? read(this) : undefined;
  }

  done(): void {
    if (this.#offset !== this.input.length) {
      fail("INTERFACE_CODEC", {
        reason: "trailing bytes",
        offset: this.#offset,
        length: this.input.length,
      });
    }
  }

  private integer(length: number, name: string): bigint {
    const value = this.bytes(length, name);
    let result = 0n;
    for (let index = value.length - 1; index >= 0; index -= 1) {
      result = (result << 8n) | BigInt(arrayValue(value, index));
    }
    return result;
  }
}

function arrayValue<T>(values: ArrayLike<T>, index: number): T {
  const value = values[index];
  if (value === undefined) {
    fail("INTERFACE_CODEC", { reason: "internal index out of bounds", index });
  }
  return value;
}
