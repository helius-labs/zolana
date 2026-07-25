import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { ShieldedKeypairLike, ViewingKeyLike } from "../../src/traits/index.js";

/**
 * The two capability traits are the one part of the keypair surface with no
 * generated fixture behind it, because a trait declares no values for a Rust
 * oracle to emit. Scraping the declarations instead keeps the comparison
 * against the Rust source rather than against a transcription of it, which is
 * the same technique the interface package uses for its re-export ledgers.
 *
 * The name maps are explicit because the port renames deliberately: Rust's
 * `get_` accessor prefix is dropped and `pubkey` is spelled out. A mechanical
 * snake-to-camel rule would hide a rename behind a passing test.
 */
const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;

function traitMethods(file: string, trait: string): readonly string[] {
  const source = readText(new URL(`../../../../keypair/src/traits/${file}`, import.meta.url), "utf8");
  const start = source.indexOf(`pub trait ${trait} {`);
  if (start < 0) throw new Error(`trait ${trait} not found in ${file}`);
  // The declaration block ends at the first line that closes it at column zero,
  // which is what separates it from the `impl` blocks below.
  const end = source.indexOf("\n}\n", start);
  if (end < 0) throw new Error(`unterminated trait ${trait} in ${file}`);
  return [...source.slice(start, end).matchAll(/^\s{4}fn (\w+)/gm)].map((match) => match[1] ?? "");
}

/**
 * Exhaustive by construction: a method added to or removed from the TypeScript
 * interface fails to typecheck here before it can fail an assertion.
 */
const shieldedKeypairNames: Record<keyof ShieldedKeypairLike, string> = {
  signingPublicKey: "signing_pubkey",
  viewingPublicKey: "viewing_pubkey",
  curve: "curve",
  shieldedAddress: "shielded_address",
  ownerHash: "owner_hash",
  compressedAddress: "compressed_address",
  sign: "sign",
  nullifier: "nullifier",
  nullifierPublicKey: "nullifier_pubkey",
};

const viewingKeyNames: Record<keyof ViewingKeyLike, string> = {
  publicKey: "pubkey",
  ecdh: "ecdh",
  senderViewTag: "get_sender_view_tag",
  recipientRequestViewTag: "get_recipient_request_view_tag",
  mergeViewTag: "get_merge_view_tag",
  sendSharedViewTag: "get_send_shared_view_tag",
  recipientSharedViewTag: "get_recipient_shared_view_tag",
  recipientBootstrapViewTag: "recipient_bootstrap_view_tag",
  transactionViewingKey: "get_transaction_viewing_key",
  encryptSlot: "encrypt_slot",
  decryptUtxo: "decrypt_utxo",
  decryptSlotEphemeral: "decrypt_slot_ephemeral",
  encryptVerifiable: "encrypt_verifiable",
  decryptVerifiable: "decrypt_verifiable",
};

/**
 * `try_sign` is Rust's non-panicking `sign`. TypeScript has one throwing
 * `sign`, because the language draws no panic-versus-`Result` distinction for
 * a caller to choose between, so the pair is one capability in one language and
 * two spellings of it in the other.
 */
const rustOnly = ["try_sign"];

describe("capability trait surface", () => {
  it("declares every ShieldedKeypairTrait capability", () => {
    const rust = traitMethods("shielded_keypair.rs", "ShieldedKeypairTrait");
    expect([...rust].sort()).toEqual(
      [...Object.values(shieldedKeypairNames), ...rustOnly].sort(),
    );
  });

  it("declares every ViewingKeyTrait capability", () => {
    const rust = traitMethods("view_key.rs", "ViewingKeyTrait");
    expect([...rust].sort()).toEqual([...Object.values(viewingKeyNames)].sort());
  });

  /**
   * The custody ruling requires a backend to hold nullifier key material, so
   * the trait asks for the public key rather than the key. Rust's
   * `nullifier_key()` handed the secret back, and its one generic caller,
   * `validate_merge_inputs`, used it only to take `.pubkey()`.
   *
   * `get_transaction_viewing_key` is not covered by this: it derives a
   * per-transaction key rather than exporting the long-term one, and both
   * languages expose it.
   */
  it("asks for the nullifier public key rather than the nullifier key", () => {
    const rust = traitMethods("shielded_keypair.rs", "ShieldedKeypairTrait");
    expect(rust).toContain("nullifier_pubkey");
    expect(rust).not.toContain("nullifier_key");
    expect(shieldedKeypairNames.nullifierPublicKey).toBe("nullifier_pubkey");
  });
});
