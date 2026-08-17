import { readFileSync } from "node:fs";

import { p256_hasher } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import {
  DST_DERIVE_P_DERIVE,
  DST_PDA_ROOT_P_PDA,
  DST_VIEW_ROOT_P_CONST,
  ED25519_DERIVATION_MSG,
  P_CONST_SEC1,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
  TSPP_APPLICATION_DOMAIN,
  ed25519DerivationMessage,
  isDerivationInput,
} from "../src/keypair/derivation.js";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  symmetricApply,
  type Bytes16,
  type Bytes31,
  type Bytes32,
} from "../src/keypair/index.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../src/keypair/merge/index.js";

type RailVectors = Readonly<{
  signing_secret: string;
  signer_pubkey?: string;
  derivation_message?: string;
  derivation_seed: string;
  nullifier_secret: string;
  nullifier_pubkey: string;
  viewing_secret: string;
  viewing_pubkey: string;
}>;

type KeyDerivationVectors = Readonly<{
  ed25519_rail: RailVectors;
  p256_rail: RailVectors;
  viewing_from_seed: readonly Readonly<{
    wallet_seed: string;
    account: number;
    viewing_secret: string;
    viewing_pubkey: string;
  }>[];
  tx_viewing: Readonly<{
    viewing_secret: string;
    first_nullifier: string;
    tx_viewing_secret: string;
    tx_viewing_pubkey: string;
  }>;
  hpke_utxo: Readonly<{
    recipient_secret: string;
    ephemeral_secret: string;
    salt: string;
    slot_index: number;
    plaintext: string;
    ciphertext: string;
  }>;
  owner: Readonly<{
    signing_secret: string;
    owner_proof_input_hash: string;
    nullifier_pubkey: string;
    viewing_pubkey: string;
    owner_hash: string;
    compressed_address_hash: string;
  }>;
  key_schedule: Readonly<{
    shared_secret: string;
    info: string;
    plaintext: string;
    ciphertext: string;
  }>;
  merge_recovery: Readonly<{
    nullifier_secret: string;
    first_nullifier: string;
    output_blinding: string;
    dummy_slot_index: number;
    dummy_nullifier: string;
  }>;
  derivation_input_guard: readonly Readonly<{
    name: string;
    message: string;
    is_derivation_input: boolean;
  }>[];
}>;

const vectors = JSON.parse(
  readFileSync(new URL("../../../test-vectors/key_derivation.json", import.meta.url), "utf8"),
) as KeyDerivationVectors;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertRail(section: RailVectors, signing: SigningKey): void {
  expect(hex(signing.derivationSeed())).toBe(section.derivation_seed);
  const keypair = ShieldedKeypair.fromKeypair(signing);
  expect(hex(keypair.nullifierKey().secretBytes())).toBe(section.nullifier_secret);
  expect(hex(keypair.nullifierPublicKey())).toBe(section.nullifier_pubkey);
  expect(hex(keypair.viewingKey().secretBytes())).toBe(section.viewing_secret);
  expect(hex(keypair.viewingPublicKey().toBytes())).toBe(section.viewing_pubkey);
}

describe("shared key-derivation vectors (test-vectors/key_derivation.json)", () => {
  it("pins the application domain to the payload hash", () => {
    expect(hex(TSPP_APPLICATION_DOMAIN)).toBe(
      hex(sha256(new TextEncoder().encode(ED25519_DERIVATION_MSG))),
    );
  });

  it("pins each committed point to hash_to_curve of its DST", () => {
    const cases: readonly [string, Uint8Array][] = [
      [DST_VIEW_ROOT_P_CONST, P_CONST_SEC1],
      [DST_DERIVE_P_DERIVE, P_DERIVE_SEC1],
      [DST_PDA_ROOT_P_PDA, P_PDA_SEC1],
    ];
    for (const [dst, committed] of cases) {
      const point = p256_hasher.hashToCurve(new Uint8Array(0), { DST: dst });
      expect(hex(point.toBytes(true)), dst).toBe(hex(committed));
    }
  });

  it("derives the ed25519 rail", () => {
    const section = vectors.ed25519_rail;
    const signing = SigningKey.fromEd25519Bytes(bytes(section.signing_secret) as Bytes32);
    const signerPubkey = signing.publicKey().ed25519();
    expect(hex(signerPubkey)).toBe(section.signer_pubkey);
    expect(hex(ed25519DerivationMessage(signerPubkey))).toBe(section.derivation_message);
    assertRail(section, signing);
  });

  it("derives the p256 rail", () => {
    const section = vectors.p256_rail;
    assertRail(section, SigningKey.fromBytes(bytes(section.signing_secret) as Bytes32));
  });

  it("derives viewing keys from a wallet seed per account", () => {
    for (const section of vectors.viewing_from_seed) {
      const viewing = ViewingKey.fromSeed(bytes(section.wallet_seed) as Bytes32, section.account);
      expect(hex(viewing.secretBytes())).toBe(section.viewing_secret);
      expect(hex(viewing.publicKey().toBytes())).toBe(section.viewing_pubkey);
    }
  });

  it("derives the transaction viewing key", () => {
    const section = vectors.tx_viewing;
    const viewing = ViewingKey.fromBytes(bytes(section.viewing_secret) as Bytes32);
    const txViewing = viewing.transactionViewingKey(bytes(section.first_nullifier) as Bytes32);
    expect(hex(txViewing.secretBytes())).toBe(section.tx_viewing_secret);
    expect(hex(txViewing.publicKey().toBytes())).toBe(section.tx_viewing_pubkey);
  });

  it("encrypts and decrypts the HPKE UTXO golden", () => {
    const section = vectors.hpke_utxo;
    const recipient = ViewingKey.fromBytes(bytes(section.recipient_secret) as Bytes32);
    const ephemeral = ViewingKey.fromBytes(bytes(section.ephemeral_secret) as Bytes32);
    const salt = bytes(section.salt) as Bytes16;
    const ciphertext = ephemeral.encryptSlot(
      recipient.publicKey(),
      bytes(section.plaintext),
      salt,
      section.slot_index,
    );
    expect(hex(ciphertext)).toBe(section.ciphertext);
    expect(
      hex(recipient.decryptUtxo(ciphertext, ephemeral.publicKey(), salt, section.slot_index)),
    ).toBe(section.plaintext);
  });

  it("derives owner hashes and the compressed address hash", () => {
    const section = vectors.owner;
    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromBytes(bytes(section.signing_secret) as Bytes32),
    );
    expect(hex(keypair.signingPublicKey().ownerProofInputHash())).toBe(
      section.owner_proof_input_hash,
    );
    expect(hex(keypair.nullifierPublicKey())).toBe(section.nullifier_pubkey);
    expect(hex(keypair.viewingPublicKey().toBytes())).toBe(section.viewing_pubkey);
    expect(hex(keypair.ownerHash())).toBe(section.owner_hash);
    expect(hex(keypair.compressedAddress().hash())).toBe(section.compressed_address_hash);
  });

  it("applies the Poseidon key schedule", () => {
    const section = vectors.key_schedule;
    const ciphertext = symmetricApply(
      bytes(section.shared_secret),
      bytes(section.info),
      bytes(section.plaintext),
    );
    expect(hex(ciphertext)).toBe(section.ciphertext);
    expect(hex(symmetricApply(bytes(section.shared_secret), bytes(section.info), ciphertext))).toBe(
      section.plaintext,
    );
  });

  it("derives the merge recovery values", () => {
    const section = vectors.merge_recovery;
    const nullifierKey = NullifierKey.fromSecret(bytes(section.nullifier_secret) as Bytes31);
    const firstNullifier = bytes(section.first_nullifier) as Bytes32;
    expect(hex(mergeOutputBlinding(nullifierKey, firstNullifier))).toBe(section.output_blinding);
    expect(hex(mergeDummyNullifier(nullifierKey, firstNullifier, section.dummy_slot_index))).toBe(
      section.dummy_nullifier,
    );
  });

  it("detects derivation inputs exactly like Rust", () => {
    for (const guardCase of vectors.derivation_input_guard) {
      expect(isDerivationInput(bytes(guardCase.message)), guardCase.name).toBe(
        guardCase.is_derivation_input,
      );
    }
  });
});
