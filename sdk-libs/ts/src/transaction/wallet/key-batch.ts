import { decodeBatch } from "../../interface/decode.js";
import type { Bytes32 } from "../../interface/types.js";
import { ViewingKey } from "../../keypair/viewing-key.js";
import { X25519PublicKey } from "../../keypair/x25519.js";

/** Validates owned derivation buffers without making additional secret copies. */
export function deriveAnswers(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly Bytes32[] {
  return decodeBatch(
    value,
    count,
    (entry) =>
      entry instanceof Uint8Array && entry.length === 32 ? (entry as Bytes32) : undefined,
    invalid,
  );
}

export function transactionKeyAnswers(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly ViewingKey[] {
  return decodeBatch(
    value,
    count,
    (entry) => (entry instanceof ViewingKey ? entry : undefined),
    invalid,
  );
}

/** Plaintexts of any length, the caller owns and wipes them. */
export function byteAnswers(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly Uint8Array[] {
  return decodeBatch(
    value,
    count,
    (entry) => (entry instanceof Uint8Array ? entry : undefined),
    invalid,
  );
}

export function publicKeyAnswers(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly X25519PublicKey[] {
  return decodeBatch(
    value,
    count,
    (entry) => (entry instanceof X25519PublicKey ? entry : undefined),
    invalid,
  );
}

/** `deriveAnswers` that wipes every returned buffer of a refused batch. */
export function ownedDerivations(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly Bytes32[] {
  try {
    return deriveAnswers(value, count, invalid);
  } catch (cause) {
    wipeByteAnswers(value);
    throw cause;
  }
}

/** Malformed entries must not prevent destruction of the valid keys beside them. */
export function destroyTransactionKeys(value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    if (entry instanceof ViewingKey) entry.destroy();
  }
}

/** Wipe every returned byte buffer, including valid entries beside a malformed one. */
export function wipeByteAnswers(value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    if (entry instanceof Uint8Array) entry.fill(0);
  }
}
