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

/** Decoders over `unknown` wire values, every failure throws the boundary's own error. */
export interface WireDecoder {
  record(value: unknown, path: string): Record<string, unknown>;
  list(value: unknown, path: string): readonly unknown[];
  string(value: unknown, path: string): string;
  boolean(value: unknown, path: string): boolean;
  address(value: unknown, path: string): Address;
  signature(value: unknown, path: string): Signature;
  /** Safe integer number or a decimal string, any sign. */
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
    if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === "string" && /^-?\d+$/u.test(value)) return BigInt(value);
    throw invalid(path);
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
