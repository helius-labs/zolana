import { p256 } from "@noble/curves/nist.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { type Bytes16, type Bytes32, checkedBytes, copyBytes, randomBytes } from "./bytes.js";
import {
  ENC_INFO_RING_DEPOSIT,
  INFO_TX_VIEWING,
  ecdhX,
  hkdfExpand,
  isDerivationPoint,
  roleExpansion,
  scalarFromOkm,
  viewRoot,
} from "./derivation.js";
import { applyTransferCipher } from "./encryption.js";
import { KeypairError } from "./error.js";
import { P256PublicKey, type ViewTag } from "./public-key.js";
import type { ViewingKeyLike } from "./shielded.js";

export type Salt = Bytes16;

const encoder = new TextEncoder();

function checkSlotIndex(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name: "slotIndex",
      minimum: 0,
      maximum: 0xffff_ffff,
    });
  }
  return value;
}

export class ViewingKey implements ViewingKeyLike {
  #secret: Uint8Array;
  #viewRoot: Uint8Array | undefined;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
  }

  static generate(): ViewingKey {
    let secret: Uint8Array;
    do secret = randomBytes(32);
    while (!p256.utils.isValidSecretKey(secret));
    return new ViewingKey(secret);
  }

  static fromBytes(bytes: Bytes32): ViewingKey {
    const secret = checkedBytes<Bytes32>(bytes, 32, "viewing secret");
    if (!p256.utils.isValidSecretKey(secret)) {
      secret.fill(0);
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { type: "p256" });
    }
    return new ViewingKey(secret);
  }

  /**
   * The viewing key of the wallet whose ed25519 `derivationSeed` is the
   * signature over `ed25519DerivationMessage(publicKey)`. Same key as
   * `LocalShieldedKeys.fromDerivationSeed` holds, without the nullifier key,
   * so nothing here hashes.
   */
  static fromDerivationSeed(derivationSeed: Uint8Array): ViewingKey {
    return roleExpansion(derivationSeed, "ed25519", (roles) =>
      ViewingKey.fromBytes(roles.viewingSecret),
    );
  }

  publicKey(): P256PublicKey {
    this.#assertUsable();
    return P256PublicKey.fromSecret(this.#secret);
  }

  /** An independent copy of the key; destroying either leaves the other usable. */
  clone(): ViewingKey {
    this.#assertUsable();
    return new ViewingKey(copyBytes(this.#secret));
  }

  secretBytes(): Bytes32 {
    this.#assertUsable();
    return copyBytes(this.#secret) as Bytes32;
  }

  ecdh(counterparty: P256PublicKey): Bytes32 {
    this.#assertUsable();
    if (isDerivationPoint(counterparty)) {
      throw new KeypairError("KEYPAIR_DERIVATION_INPUT");
    }
    // The view aliases the shared point buffer, not a copy.
    const shared = ecdhX(this.#secret, counterparty);
    try {
      return copyBytes(shared) as Bytes32;
    } finally {
      shared.fill(0);
    }
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.publicKey().x();
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    this.#assertUsable();
    const nullifier = checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier");
    const txViewingSecret = this.#viewSecret(INFO_TX_VIEWING);
    let salted: Uint8Array | undefined;
    let scalar: Uint8Array | undefined;
    try {
      salted = hkdfExpand(nullifier, txViewingSecret, encoder.encode(INFO_TX_VIEWING), 48);
      scalar = scalarFromOkm(salted);
      return ViewingKey.fromBytes(scalar as Bytes32);
    } finally {
      txViewingSecret.fill(0);
      salted?.fill(0);
      scalar?.fill(0);
    }
  }

  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      recipientPublicKey,
      this.publicKey(),
      recipientPublicKey,
      plaintext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      checkSlotIndex(slotIndex),
    );
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      txViewingPublicKey,
      txViewingPublicKey,
      this.publicKey(),
      ciphertext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      checkSlotIndex(slotIndex),
    );
  }

  /** Mirrors Rust `ViewingKey::encrypt_ring_deposit`. This key is the ephemeral one. The ring deposit label keeps the ciphertext closed under the transfer label. */
  encryptRingDeposit(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      recipientPublicKey,
      this.publicKey(),
      recipientPublicKey,
      plaintext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      0,
      ENC_INFO_RING_DEPOSIT,
    );
  }

  decryptRingDeposit(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      txViewingPublicKey,
      txViewingPublicKey,
      this.publicKey(),
      ciphertext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      0,
      ENC_INFO_RING_DEPOSIT,
    );
  }

  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.encryptSlot(recipientPublicKey, ciphertext, salt, slotIndex);
  }

  destroy(): void {
    this.#secret.fill(0);
    this.#viewRoot?.fill(0);
    this.#destroyed = true;
  }

  // Resolved on first use like Rust's `OnceLock`: the single-use keys
  // `transactionViewingKey` returns never pay for the view-root ECDH.
  #viewSecret(info: string): Uint8Array {
    this.#assertUsable();
    this.#viewRoot ??= viewRoot(this.#secret);
    try {
      return expand(sha256, this.#viewRoot, encoder.encode(info), 32);
    } catch (error) {
      throw new KeypairError("KEYPAIR_HKDF", { name: info }, error);
    }
  }

  #assertUsable(): void {
    if (this.#destroyed) {
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
    }
  }
}
