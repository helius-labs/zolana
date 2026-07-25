import { describe, expect, it } from "vitest";

import type { Bytes31, Bytes32, Bytes64 } from "../src/bytes.js";
import * as hashEntry from "../src/hash/index.js";
import * as rootEntry from "../src/index.js";
import {
  CompressedShieldedAddress,
  KEYPAIR_ERROR_RUST_VARIANT,
  type KeypairErrorCode,
  NullifierKey,
  P256PublicKey,
  ShieldedAddress,
  type ShieldedKeypairLike,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  type ViewingKeyLike,
} from "../src/index.js";
import * as mergeEntry from "../src/merge/index.js";
import * as traitsEntry from "../src/traits/index.js";

/**
 * The exact runtime surface of every entry point. A new export has to be added
 * here deliberately, and a removed one fails loudly instead of silently
 * shrinking a published package.
 */
const ROOT_EXPORTS = [
  "BLINDING_LENGTH",
  "CompressedShieldedAddress",
  "DST_VIEW_ROOT",
  "KEYPAIR_ERROR_RUST_VARIANT",
  "KeypairError",
  "NullifierKey",
  "P256PublicKey",
  "P256_PUBLIC_KEY_LENGTH",
  "P_CONST_SEC1",
  "SALT_LENGTH",
  "SHIELDED_PUBLIC_KEY_LENGTH",
  "ShieldedAddress",
  "ShieldedKeypair",
  "ShieldedPublicKey",
  "SigningKey",
  "VIEW_TAG_LENGTH",
  "ViewingKey",
  "hashField",
  "initializePoseidon",
  "isPoseidonInitialized",
  "ownerHash",
  "poseidon",
  "randomBlinding",
  "randomSalt",
  "sha256Be",
  "sha256Bytes",
  "splitBigEndian128",
];

const MERGE_EXPORTS = [
  "MAX_INFO_LENGTH",
  "MERGE_INFO",
  "decryptVerifiable",
  "encryptVerifiable",
  "mergeCiphertextHash",
  "mergePublicContribution",
  "symmetricApply",
];

const HASH_EXPORTS = [
  "hashField",
  "ownerHash",
  "poseidon",
  "sha256Be",
  "sha256Bytes",
  "splitBigEndian128",
];

describe("package entry points", () => {
  it("exports exactly the declared root surface", () => {
    expect(Object.keys(rootEntry).sort()).toEqual(ROOT_EXPORTS);
  });

  it("exports exactly the declared merge surface", () => {
    expect(Object.keys(mergeEntry).sort()).toEqual(MERGE_EXPORTS);
  });

  it("exports the Rust-public hash surface and nothing unchecked", () => {
    expect(Object.keys(hashEntry).sort()).toEqual(HASH_EXPORTS);
    // `hashPublicKeyX` and `fieldFromBytes` had no Rust counterpart and were
    // removed rather than published as unchecked field helpers.
    expect(Object.keys(hashEntry)).not.toContain("hashPublicKeyX");
    expect(Object.keys(hashEntry)).not.toContain("fieldFromBytes");
    // `pack33`, `feRightAlign`, and `boolFe` are `pub(crate)` in Rust.
    expect(Object.keys(hashEntry)).not.toContain("pack33");
  });

  it("keeps the traits subpath type-only, mirroring traits/mod.rs", () => {
    expect(Object.keys(traitsEntry)).toEqual([]);
  });

  it("keeps the crate-internal HKDF labels out of the published surface", () => {
    for (const name of Object.keys(rootEntry)) {
      expect(name.startsWith("INFO_")).toBe(false);
      expect(name).not.toBe("HPKE_PREFIX");
      expect(name).not.toBe("ENC_INFO_TRANSFER");
    }
  });

  it("indexes every error code by its Rust variant", () => {
    const codes = Object.keys(KEYPAIR_ERROR_RUST_VARIANT) as KeypairErrorCode[];
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) expect(code.startsWith("KEYPAIR_")).toBe(true);
    expect(Object.isFrozen(KEYPAIR_ERROR_RUST_VARIANT)).toBe(true);
  });
});

const SECRET = Uint8Array.from({ length: 32 }, (_, index) => index + 1) as Bytes32;
const VIEWING_SECRET = Uint8Array.from({ length: 32 }, (_, index) => index + 40) as Bytes32;

function keypair(): ShieldedKeypair {
  return ShieldedKeypair.fromSigningAndViewingKeys(
    SigningKey.fromBytes(SECRET),
    ViewingKey.fromBytes(VIEWING_SECRET),
  );
}

/**
 * A backend that keeps its key material behind an async boundary, standing in
 * for an HSM or a remote signer. It exists to prove the published interfaces
 * are satisfiable without the concrete in-memory classes -- the point of the
 * Rust traits.
 */
class RemoteBackend implements ShieldedKeypairLike, ViewingKeyLike {
  readonly #inner = keypair();

  signingPublicKey(): Promise<ShieldedPublicKey> {
    return Promise.resolve(this.#inner.signingPublicKey());
  }
  viewingPublicKey(): Promise<P256PublicKey> {
    return Promise.resolve(this.#inner.viewingPublicKey());
  }
  curve(): Promise<"p256" | "ed25519"> {
    return Promise.resolve(this.#inner.curve());
  }
  shieldedAddress(): Promise<ShieldedAddress> {
    return Promise.resolve(this.#inner.shieldedAddress());
  }
  ownerHash(): Promise<Bytes32> {
    return Promise.resolve(this.#inner.ownerHash());
  }
  compressedAddress(): Promise<CompressedShieldedAddress> {
    return Promise.resolve(this.#inner.compressedAddress());
  }
  sign(message: Uint8Array): Promise<Bytes64> {
    return Promise.resolve(this.#inner.sign(message));
  }
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Promise<Bytes32> {
    return Promise.resolve(this.#inner.nullifier(utxoHash, blinding));
  }
  nullifierPublicKey(): Promise<Bytes32> {
    return Promise.resolve(this.#inner.nullifierPublicKey());
  }
  publicKey(): Promise<P256PublicKey> {
    return Promise.resolve(this.#inner.publicKey());
  }
  ecdh(counterparty: P256PublicKey): Promise<Bytes32> {
    return Promise.resolve(this.#inner.ecdh(counterparty));
  }
  senderViewTag(txCount: bigint): Promise<Bytes32> {
    return Promise.resolve(this.#inner.senderViewTag(txCount));
  }
  recipientRequestViewTag(requestCount: bigint): Promise<Bytes32> {
    return Promise.resolve(this.#inner.recipientRequestViewTag(requestCount));
  }
  mergeViewTag(mergeCount: bigint): Promise<Bytes32> {
    return Promise.resolve(this.#inner.mergeViewTag(mergeCount));
  }
  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): Promise<Bytes32> {
    return Promise.resolve(this.#inner.sendSharedViewTag(counterparty, index));
  }
  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): Promise<Bytes32> {
    return Promise.resolve(this.#inner.recipientSharedViewTag(counterparty, index));
  }
  recipientBootstrapViewTag(): Promise<Bytes32> {
    return Promise.resolve(this.#inner.recipientBootstrapViewTag());
  }
  transactionViewingKey(firstNullifier: Bytes32): Promise<ViewingKey> {
    return Promise.resolve(this.#inner.transactionViewingKey(firstNullifier));
  }
  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: rootEntry.Salt,
    slotIndex: number,
  ): Promise<Uint8Array> {
    return Promise.resolve(this.#inner.encryptSlot(recipientPublicKey, plaintext, salt, slotIndex));
  }
  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: rootEntry.Salt,
    slotIndex: number,
  ): Promise<Uint8Array> {
    return Promise.resolve(this.#inner.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex));
  }
  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: rootEntry.Salt,
    slotIndex: number,
  ): Promise<Uint8Array> {
    return Promise.resolve(this.#inner.decryptSlotEphemeral(recipientPublicKey, ciphertext, salt, slotIndex));
  }
  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Promise<Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }>> {
    return Promise.resolve(this.#inner.encryptVerifiable(userViewingPublicKey, plaintext));
  }
  decryptVerifiable(
    txViewingPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array> {
    return Promise.resolve(this.#inner.decryptVerifiable(txViewingPublicKey, ciphertext));
  }
}

describe("capability interfaces", () => {
  it("is satisfied by the concrete keys and by an async backend alike", async () => {
    const concreteKeypair: ShieldedKeypairLike = keypair();
    const concreteViewing: ViewingKeyLike = ViewingKey.fromBytes(VIEWING_SECRET);
    const remote: ShieldedKeypairLike & ViewingKeyLike = new RemoteBackend();

    expect(await remote.curve()).toBe(await concreteKeypair.curve());
    expect(await remote.ownerHash()).toEqual(await concreteKeypair.ownerHash());
    expect(await remote.nullifierPublicKey()).toEqual(
      await concreteKeypair.nullifierPublicKey(),
    );
    expect((await remote.publicKey()).toBytes()).toEqual(
      (await concreteViewing.publicKey()).toBytes(),
    );
    expect(await remote.senderViewTag(9n)).toEqual(await concreteViewing.senderViewTag(9n));
    expect((await remote.compressedAddress()).hash()).toEqual(
      (await concreteKeypair.compressedAddress()).hash(),
    );
  });

  it("round-trips a slot ciphertext through the interface alone", async () => {
    const remote: ViewingKeyLike = new RemoteBackend();
    const recipient = ViewingKey.fromBytes(SECRET);
    const salt = new Uint8Array(16).fill(9) as rootEntry.Salt;
    const plaintext = Uint8Array.from({ length: 40 }, (_, index) => index);
    const ciphertext = await remote.encryptSlot(recipient.publicKey(), plaintext, salt, 2);
    expect(
      recipient.decryptUtxo(ciphertext, await remote.publicKey(), salt, 2),
    ).toEqual(plaintext);
  });

  it("a shielded keypair stands in for a viewing-key backend", () => {
    const backend: ViewingKeyLike = keypair();
    const viewing = ViewingKey.fromBytes(VIEWING_SECRET);
    expect(backend.recipientBootstrapViewTag()).toEqual(viewing.recipientBootstrapViewTag());
  });
});

describe("public key and address surface", () => {
  it("reports the tagged key as 34 bytes at runtime and in its type", () => {
    const tagged = keypair().signingPublicKey().toBytes();
    expect(tagged).toHaveLength(34);
    // The compile-time width is checked by this assignment: a `Bytes33` target
    // would fail to typecheck.
    const asBytes34: rootEntry.Bytes34 = tagged;
    expect(asBytes34).toBe(tagged);
    const roundTrip = ShieldedPublicKey.fromBytes(asBytes34);
    expect(roundTrip.equals(keypair().signingPublicKey())).toBe(true);
  });

  it("rejects a 33-byte value where a tagged key is required", () => {
    const compressed = keypair().viewingPublicKey().toBytes() as unknown as rootEntry.Bytes34;
    expect(() => ShieldedPublicKey.fromBytes(compressed)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }),
    );
  });

  it("exposes the compressed address parts and its Poseidon hash", () => {
    const compressed = keypair().compressedAddress();
    expect(compressed.bytes).toHaveLength(65);
    expect(compressed.ownerHash).toHaveLength(32);
    expect(compressed.hash()).toHaveLength(32);
    expect(Object.isFrozen(compressed)).toBe(true);
    const rebuilt = CompressedShieldedAddress.fromParts(
      compressed.ownerHash,
      compressed.viewingPublicKey,
    );
    expect(rebuilt.hash()).toEqual(compressed.hash());
    // The getter hands back a fresh buffer, so a caller cannot edit the address.
    compressed.bytes.fill(0);
    expect(compressed.bytes.subarray(0, 32)).toEqual(compressed.ownerHash);
  });

  it("keeps the nullifier key out of the signing key it derives from", () => {
    const signing = SigningKey.fromBytes(SECRET);
    const nullifier = NullifierKey.fromSigningKey(signing);
    expect(signing.secretBytes()).toEqual(SECRET);
    expect(nullifier.secretBytes()).toHaveLength(31);
    expect(signing.isEd25519()).toBe(false);
    expect(SigningKey.fromEd25519Bytes(SECRET).isEd25519()).toBe(true);
  });

  it("compares P256 keys by their compressed bytes", () => {
    const left = P256PublicKey.fromBytes(keypair().viewingPublicKey().toBytes());
    expect(left.equals(keypair().viewingPublicKey())).toBe(true);
    expect(left.equals(ViewingKey.fromBytes(SECRET).publicKey())).toBe(false);
  });
});
