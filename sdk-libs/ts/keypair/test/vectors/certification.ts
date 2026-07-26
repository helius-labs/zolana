import { expect } from "vitest";

import certification from "../../../vectors/key-certification-v1.json" with { type: "json" };
import type { KeypairErrorCode } from "../../src/error.js";

export { certification };

/** A recorded Rust outcome: the call succeeded, or it failed with this variant. */
export type Disposition = { accepted: boolean; variant?: string };

export function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

export function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function expectHex(actual: Uint8Array, expected: string): void {
  expect(toHex(actual)).toBe(expected);
}

/**
 * The code each Rust variant must surface as. `keypair-parity.test.ts` proves
 * the map is total over the Rust enum; this copy is what the adversarial
 * dispositions are compared against.
 */
const RUST_VARIANT_TO_CODE: Readonly<Record<string, KeypairErrorCode>> = {
  InvalidPublicKey: "KEYPAIR_INVALID_PUBLIC_KEY",
  InvalidSecretKey: "KEYPAIR_INVALID_SECRET_KEY",
  ZeroScalar: "KEYPAIR_ZERO_SCALAR",
  InvalidSignatureType: "KEYPAIR_INVALID_SIGNATURE_TYPE",
  NotEd25519: "KEYPAIR_NOT_ED25519",
  Hkdf: "KEYPAIR_HKDF",
  Poseidon: "KEYPAIR_POSEIDON",
  FieldElementTooLong: "KEYPAIR_FIELD_ELEMENT_TOO_LONG",
  InvalidPrehashLength: "KEYPAIR_INVALID_PREHASH_LENGTH",
  InfoTooLong: "KEYPAIR_INFO_TOO_LONG",
};

/**
 * Replays one recorded Rust disposition against the TypeScript call. An
 * accepted input must not throw; a refused one must throw the code that mirrors
 * the Rust variant, so a port that refuses for a different reason fails here
 * rather than counting as agreement.
 */
export function expectDisposition(
  operation: () => unknown,
  recorded: Disposition,
  label: string,
): void {
  if (recorded.accepted) {
    expect(operation, `${label}: Rust accepted this input`).not.toThrow();
    return;
  }
  const expected = RUST_VARIANT_TO_CODE[recorded.variant ?? ""];
  expect(expected, `${label}: no TypeScript code mirrors Rust ${recorded.variant}`).toBeDefined();
  expect(operation, `${label}: Rust refused with ${recorded.variant}`).toThrow(
    expect.objectContaining({ code: expected }),
  );
}
