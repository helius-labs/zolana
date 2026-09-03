import type { Address } from "@solana/kit";
import type { Bytes32 } from "./types.js";
import type { TransactBoundFields } from "./codecs/index.js";
import { encodeTransactBoundRegion } from "./codecs/index.js";
import { addressBytes, copyBytes, sha256, unsigned } from "./internal.js";

export interface ExternalDataHashInput {
  readonly instructionDiscriminator: number;
  /** The proof-bound fields of the instruction being hashed. */
  readonly bound: TransactBoundFields;
  /**
   * Addresses the proof binds, in protocol order: each interface transfer's
   * settlement accounts in leg order (the user account for a SOL leg, the user
   * token account then the per-mint interface vault for an SPL leg), followed by
   * the resolved owner of every output whose owner tag names an account, in
   * output order.
   */
  readonly boundAddresses: readonly (Address | Bytes32)[];
}

/**
 * `external_data_hash` public input: SHA-256 over the instruction
 * discriminator, the contiguous proof-bound region of the instruction data, and
 * a digest of the bound account addresses.
 *
 * The addresses fold into one digest first, so the preimage is three fixed
 * segments regardless of how many legs and outputs the transaction carries. The
 * result's first byte is zeroed for BN254 field compatibility, matching
 * `Sha256BE` on the Rust side.
 */
export function externalDataHash(input: ExternalDataHashInput): Bytes32 {
  let addressDigest: Uint8Array = new Uint8Array(32);
  input.boundAddresses.forEach((address, index) => {
    const label = `boundAddresses[${String(index)}]`;
    const bytes =
      typeof address === "string" ? addressBytes(address, label) : copyBytes(address, 32, label);
    addressDigest = sha256BE(concat([addressDigest, bytes]));
  });

  const discriminator = Uint8Array.of(
    unsigned(input.instructionDiscriminator, 0xff, "instructionDiscriminator"),
  );
  const bound = encodeTransactBoundRegion(input.bound);
  return sha256BE(concat([discriminator, bound, addressDigest])) as Bytes32;
}

function sha256BE(bytes: Uint8Array): Uint8Array {
  const digest = copyBytes(sha256(bytes), 32, "digest");
  digest[0] = 0;
  return digest;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
