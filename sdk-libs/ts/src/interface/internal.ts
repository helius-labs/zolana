import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { address, getAddressDecoder, getAddressEncoder, type Address } from "@solana/kit";

import { InterfaceError } from "./errors.js";

/** The largest `u64`. */
export const U64_MAX = 0xffff_ffff_ffff_ffffn;

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

/**
 * What a `Reader` or `Writer` refused. The owning layer turns it into its own
 * error through a `CodecErrorFactory`; the default is the interface taxonomy.
 */
export type CodecFailure =
  | Readonly<{ kind: "notBytes"; name: string; expected?: number | undefined }>
  | Readonly<{ kind: "length"; name: string; expected: number; actual: number }>
  | Readonly<{
      kind: "integer";
      name: string;
      bits: number;
      minimum: number | string;
      maximum: number | string;
      actual: unknown;
    }>
  | Readonly<{ kind: "bool"; name: string; actual: unknown }>
  | Readonly<{
      kind: "truncated";
      name: string;
      offset: number;
      expected: number;
      remaining: number;
    }>
  | Readonly<{ kind: "trailing"; offset: number; length: number }>;

export type CodecErrorFactory = (failure: CodecFailure) => Error;

/** The interface taxonomy for a `CodecFailure`. */
export function interfaceCodecError(failure: CodecFailure): InterfaceError {
  switch (failure.kind) {
    case "notBytes":
      return new InterfaceError("INTERFACE_INVALID_LENGTH", {
        name: failure.name,
        expected: failure.expected,
        actual: "non-bytes",
      });
    case "length":
      return new InterfaceError("INTERFACE_INVALID_LENGTH", {
        name: failure.name,
        expected: failure.expected,
        actual: failure.actual,
      });
    case "integer":
      return new InterfaceError("INTERFACE_INVALID_INTEGER", {
        name: failure.name,
        minimum: failure.minimum,
        maximum: failure.maximum,
        actual: failure.actual,
      });
    case "bool":
      return new InterfaceError("INTERFACE_CODEC", { name: failure.name, actual: failure.actual });
    case "truncated":
      return new InterfaceError("INTERFACE_CODEC", {
        name: failure.name,
        offset: failure.offset,
        expected: failure.expected,
        remaining: failure.remaining,
      });
    case "trailing":
      return new InterfaceError("INTERFACE_CODEC", {
        reason: "trailing bytes",
        offset: failure.offset,
        length: failure.length,
      });
  }
}

/** Little-endian Borsh-style writer; every rejection goes through `fail`. */
export class Writer {
  readonly #parts: Uint8Array[] = [];
  readonly #fail: CodecErrorFactory;

  constructor(fail: CodecErrorFactory = interfaceCodecError) {
    this.#fail = fail;
  }

  bytes(value: Uint8Array, length?: number, name = "bytes"): this {
    if (!(value instanceof Uint8Array)) {
      throw this.#fail({ kind: "notBytes", name, expected: length });
    }
    if (length !== undefined && value.length !== length) {
      throw this.#fail({ kind: "length", name, expected: length, actual: value.length });
    }
    this.#parts.push(value.slice());
    return this;
  }

  u8(value: number, name = "u8"): this {
    return this.#unsigned(value, 8, name);
  }

  bool(value: boolean, name = "bool"): this {
    if (typeof value !== "boolean") throw this.#fail({ kind: "bool", name, actual: value });
    this.#parts.push(Uint8Array.of(value ? 1 : 0));
    return this;
  }

  u16(value: number, name = "u16"): this {
    return this.#unsigned(value, 16, name);
  }

  u32(value: number, name = "u32"): this {
    return this.#unsigned(value, 32, name);
  }

  u64(value: bigint, name = "u64"): this {
    if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
      throw this.#fail({
        kind: "integer",
        name,
        bits: 64,
        minimum: "0",
        maximum: U64_MAX.toString(),
        actual: String(value),
      });
    }
    return this.#integer(value, 8);
  }

  i64(value: bigint, name = "i64"): this {
    const minimum = -(1n << 63n);
    const maximum = (1n << 63n) - 1n;
    if (typeof value !== "bigint" || value < minimum || value > maximum) {
      throw this.#fail({
        kind: "integer",
        name,
        bits: 64,
        minimum: minimum.toString(),
        maximum: maximum.toString(),
        actual: String(value),
      });
    }
    return this.#integer(value < 0n ? value + (1n << 64n) : value, 8);
  }

  option<T>(value: T | undefined, write: (writer: Writer, value: T) => void): this {
    this.bool(value !== undefined, "option");
    if (value !== undefined) write(this, value);
    return this;
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.#parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of this.#parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  }

  #unsigned(value: number, bits: 8 | 16 | 32, name: string): this {
    const maximum = 2 ** bits - 1;
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
      throw this.#fail({ kind: "integer", name, bits, minimum: 0, maximum, actual: value });
    }
    return this.#integer(BigInt(value), bits / 8);
  }

  #integer(value: bigint, length: number): this {
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      bytes[index] = Number((value >> BigInt(index * 8)) & 255n);
    }
    this.#parts.push(bytes);
    return this;
  }
}

export function byteVector(writer: Writer, value: Uint8Array, name: string): void {
  writer.u16(value.length, `${name}.length`).bytes(value);
}

/** Little-endian Borsh-style reader over a copy-free view; every rejection goes through `fail`. */
export class Reader {
  readonly #input: Uint8Array;
  readonly #fail: CodecErrorFactory;
  #offset = 0;

  constructor(input: Uint8Array, fail: CodecErrorFactory = interfaceCodecError) {
    if (!(input instanceof Uint8Array)) throw fail({ kind: "notBytes", name: "bytes" });
    this.#input = input;
    this.#fail = fail;
  }

  bytes(length: number, name = "bytes"): Uint8Array {
    const end = this.#offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.#input.length) {
      throw this.#fail({
        kind: "truncated",
        name,
        offset: this.#offset,
        expected: length,
        remaining: this.#input.length - this.#offset,
      });
    }
    const value = this.#input.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  u8(name = "u8"): number {
    return Number(this.#integer(1, name));
  }

  bool(name = "bool"): boolean {
    const value = this.u8(name);
    if (value !== 0 && value !== 1) throw this.#fail({ kind: "bool", name, actual: value });
    return value === 1;
  }

  nonzeroBool(name = "bool"): boolean {
    return this.u8(name) !== 0;
  }

  u16(name = "u16"): number {
    return Number(this.#integer(2, name));
  }

  u32(name = "u32"): number {
    return Number(this.#integer(4, name));
  }

  u64(name = "u64"): bigint {
    return this.#integer(8, name);
  }

  i64(name = "i64"): bigint {
    const value = this.#integer(8, name);
    return value >= 1n << 63n ? value - (1n << 64n) : value;
  }

  option<T>(name: string, read: (reader: Reader) => T): T | undefined {
    return this.bool(name) ? read(this) : undefined;
  }

  done(): void {
    if (this.#offset !== this.#input.length) {
      throw this.#fail({ kind: "trailing", offset: this.#offset, length: this.#input.length });
    }
  }

  #integer(length: number, name: string): bigint {
    const value = this.bytes(length, name);
    let result = 0n;
    for (let index = value.length - 1; index >= 0; index -= 1) {
      result = (result << 8n) | BigInt(value[index] ?? 0);
    }
    return result;
  }
}
