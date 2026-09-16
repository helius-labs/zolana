import { decodeBatch } from "../../interface/decode.js";
import type { Bytes32 } from "../../interface/types.js";
import { ViewingKey } from "../../keypair/viewing-key.js";
import { checked } from "../internal.js";

/** Shared validation for derivations returned by a local or remote key holder. */
export function deriveAnswers(
  value: unknown,
  count: number,
  invalid: () => Error,
): readonly Bytes32[] {
  return decodeBatch(
    value,
    count,
    (entry) =>
      entry instanceof Uint8Array && entry.length === 32
        ? checked<Bytes32>(entry, 32, "derived value")
        : undefined,
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

/** Malformed entries must not prevent destruction of the valid keys beside them. */
export function destroyTransactionKeys(value: unknown): void {
  if (!Array.isArray(value)) return;
  for (const entry of value) {
    if (entry instanceof ViewingKey) entry.destroy();
  }
}
