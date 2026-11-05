import {
  getBase58Decoder,
  getBase58Encoder,
  getBase64Decoder,
  getBase64Encoder,
  isAddress,
  isSignature,
} from "@solana/kit";

import type { Address, Signature } from "./types.js";

const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
/** No leading zero, no sign on zero, no exponent: the spelling of a JSON integer literal. */
const INTEGER_LITERAL = /^(?:0|-?[1-9][0-9]*)$/u;

/**
 * The one wire integer rule. Photon, the prover and the Rust SDK write every
 * integer as a bare JSON number, the only form serde reads, and the transport
 * quotes a literal past `Number.MAX_SAFE_INTEGER` before `JSON.parse` could round
 * it (`httpJson`). So an integer is a safe JSON number, or the exact literal of
 * a larger one as a string. A rounded number, a quoted safe value and a leading
 * zero are refused. Callers bound the range of their field.
 */
export function jsonInteger(value: unknown): bigint | undefined {
  if (typeof value === "number") return Number.isSafeInteger(value) ? BigInt(value) : undefined;
  if (typeof value !== "string" || !INTEGER_LITERAL.test(value)) return undefined;
  const integer = BigInt(value);
  return integer > MAX_SAFE || integer < -MAX_SAFE ? integer : undefined;
}

/** Exact positional batch decoding; sparse arrays must not hide missing answers. */
export function decodeBatch<T>(
  value: unknown,
  count: number,
  decode: (entry: unknown) => T | undefined,
  invalid: () => Error,
): readonly T[] {
  const values = wireDecoder(invalid).list(value, "batch");
  if (values.length !== count) throw invalid();
  return Array.from({ length: count }, (_, index) => {
    const decoded = decode(values[index]);
    if (decoded === undefined) throw invalid();
    return decoded;
  });
}

/** Decoders over `unknown` wire values, every failure throws the boundary's own error. */
export interface WireDecoder {
  record(value: unknown, path: string): Record<string, unknown>;
  list(value: unknown, path: string): readonly unknown[];
  string(value: unknown, path: string): string;
  boolean(value: unknown, path: string): boolean;
  address(value: unknown, path: string): Address;
  signature(value: unknown, path: string): Signature;
  /** `jsonInteger`, any sign. */
  signedInteger(value: unknown, path: string): bigint;
  /** `signedInteger`, rejected below zero. */
  integer(value: unknown, path: string): bigint;
  /** Canonical base64, a string that does not round-trip is rejected. */
  base64(value: unknown, path: string): Uint8Array;
  /** Canonical base58, a string that does not round-trip is rejected. */
  base58(value: unknown, path: string): Uint8Array;
  /** `base64` pinned to an exact byte length. */
  fixedBytes(value: unknown, length: number, path: string): Uint8Array;
}

export function wireDecoder(invalid: (path: string) => Error): WireDecoder {
  const string = (value: unknown, path: string): string => {
    if (typeof value !== "string") throw invalid(path);
    return value;
  };
  const signedInteger = (value: unknown, path: string): bigint => {
    const integer = jsonInteger(value);
    if (integer === undefined) throw invalid(path);
    return integer;
  };
  const base64 = (value: unknown, path: string): Uint8Array => {
    const text = string(value, path);
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(base64Encoder.encode(text));
    } catch {
      throw invalid(path);
    }
    if (base64Decoder.decode(bytes) !== text) throw invalid(path);
    return bytes;
  };
  return Object.freeze({
    record(value: unknown, path: string): Record<string, unknown> {
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(path);
      return value as Record<string, unknown>;
    },
    list(value: unknown, path: string): readonly unknown[] {
      if (!Array.isArray(value)) throw invalid(path);
      return value;
    },
    string,
    boolean(value: unknown, path: string): boolean {
      if (typeof value !== "boolean") throw invalid(path);
      return value;
    },
    address(value: unknown, path: string): Address {
      const text = string(value, path);
      if (!isAddress(text)) throw invalid(path);
      return text;
    },
    signature(value: unknown, path: string): Signature {
      const text = string(value, path);
      if (!isSignature(text)) throw invalid(path);
      return text;
    },
    signedInteger,
    integer(value: unknown, path: string): bigint {
      const result = signedInteger(value, path);
      if (result < 0n) throw invalid(path);
      return result;
    },
    base64,
    base58(value: unknown, path: string): Uint8Array {
      const text = string(value, path);
      let bytes: Uint8Array;
      try {
        bytes = new Uint8Array(base58Encoder.encode(text));
      } catch {
        throw invalid(path);
      }
      if (base58Decoder.decode(bytes) !== text) throw invalid(path);
      return bytes;
    },
    fixedBytes(value: unknown, length: number, path: string): Uint8Array {
      const bytes = base64(value, path);
      if (bytes.length !== length) throw invalid(path);
      return bytes;
    },
  });
}
