import { getBase64Encoder } from "@solana/kit";

import { reserveEntries } from "../flows/reserve.js";
import type { Bytes32 } from "../interface/types.js";
import { TransactionError } from "../transaction/error.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { WalletError } from "./error.js";

/** @internal Named-input conflicts surface as `WALLET_NOTE_RESERVED`. */
export function reserveWalletEntries(
  wallet: Wallet,
  entries: readonly WalletUtxo[],
): UtxoReservation {
  try {
    return reserveEntries(wallet, entries);
  } catch (cause) {
    if (cause instanceof TransactionError && cause.code === "TRANSACTION_NOTE_RESERVED") {
      throw new WalletError("WALLET_NOTE_RESERVED", {
        ...(cause.details === undefined ? {} : { details: cause.details }),
        cause,
      });
    }
    throw cause;
  }
}

const base64Encoder = getBase64Encoder();

export function copy32(value: Uint8Array, field: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new WalletError("WALLET_INVALID_LENGTH", {
      details: {
        field,
        expected: 32,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  }
  return new Uint8Array(value) as Bytes32;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function bytesKey(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function base64Bytes(value: string): Uint8Array {
  if (typeof value !== "string") throw new WalletError("WALLET_INVALID_BASE64");
  const clean = value.endsWith("==")
    ? value.slice(0, -2)
    : value.endsWith("=")
      ? value.slice(0, -1)
      : value;
  if (clean.length % 4 === 1 || !/^[A-Za-z0-9+/]*$/u.test(clean)) {
    throw new WalletError("WALLET_INVALID_BASE64");
  }
  try {
    return new Uint8Array(base64Encoder.encode(clean));
  } catch {
    throw new WalletError("WALLET_INVALID_BASE64");
  }
}
