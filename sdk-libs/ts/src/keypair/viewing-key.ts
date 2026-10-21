import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { getAddressEncoder, type Address } from "@solana/kit";

import {
  type Bytes16,
  type Bytes32,
  checkedBytes,
  checkedU32,
  concatBytes,
  copyBytes,
  randomBytes,
  u32be,
} from "./bytes.js";
import {
  ENC_INFO_RING_DEPOSIT,
  INFO_RING_ADDRESS_KEY_PREFIX,
  INFO_RING_CHANGE_KEY_PREFIX,
  INFO_SENDER_VIEW_TAG_SECRET,
  INFO_TX_VIEWING_X25519,
  checkedCounter,
  clampViewingSecret,
  hkdfExpand,
  roleExpansion,
  senderViewTag,
  viewRoot,
  x25519Ecdh,
} from "./derivation.js";
import { applyTransferCipher } from "./encryption.js";
import { KeypairError } from "./error.js";
import { type ViewTag } from "./public-key.js";
import type { ViewingKeyLike } from "./shielded.js";
import { X25519PublicKey, X25519Keypair } from "./x25519.js";

export type Salt = Bytes16;

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();

function checkSlotIndex(value: number): number {
  return checkedU32(value, "slotIndex");
}

export class ViewingKey implements ViewingKeyLike {
  #secret: Uint8Array;
  #viewRoot: Uint8Array | undefined;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
  }

  static generate(): ViewingKey {
    const secret = randomBytes(32);
    try {
      return ViewingKey.fromBytes(secret as Bytes32);
    } finally {
      secret.fill(0);
    }
  }

  static fromBytes(bytes: Bytes32): ViewingKey {
    return new ViewingKey(clampViewingSecret(bytes));
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

  publicKey(): X25519PublicKey {
    this.#assertUsable();
    const secret = X25519Keypair.fromBytes(this.#secret);
    try {
      return secret.publicKey();
    } finally {
      secret.destroy();
    }
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

  ecdh(counterparty: X25519PublicKey): Bytes32 {
    this.#assertUsable();
    const shared = x25519Ecdh(this.#secret, counterparty);
    try {
      return copyBytes(shared) as Bytes32;
    } finally {
      shared.fill(0);
    }
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.publicKey().u();
  }

  /** Mirrors Rust `get_sender_view_tag`, the spender's own output at `txCount`. */
  senderViewTag(txCount: bigint | number): ViewTag {
    const secret = this.#viewSecret(INFO_SENDER_VIEW_TAG_SECRET);
    try {
      return senderViewTag(secret, checkedCounter(txCount, "txCount"));
    } finally {
      secret.fill(0);
    }
  }

  /** The key of ring address `index` in `ring`, the recipient key its inbox stream derives from. */
  ringAddressKey(ring: Address, index: number): ViewingKey {
    return this.#derivedKey(
      concatBytes(
        encoder.encode(INFO_RING_ADDRESS_KEY_PREFIX),
        new Uint8Array(addressEncoder.encode(ring)),
        u32be(checkedU32(index, "index")),
      ),
    );
  }

  /** The key a sender's change in `ring` is delivered to, found from the sender's own spends. */
  ringChangeKey(ring: Address): ViewingKey {
    return this.#derivedKey(
      concatBytes(
        encoder.encode(INFO_RING_CHANGE_KEY_PREFIX),
        new Uint8Array(addressEncoder.encode(ring)),
      ),
    );
  }

  #derivedKey(info: Uint8Array): ViewingKey {
    const secret = this.#viewSecret(info);
    try {
      return ViewingKey.fromBytes(secret as Bytes32);
    } finally {
      secret.fill(0);
    }
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    this.#assertUsable();
    const nullifier = checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier");
    const txViewingSecret = this.#viewSecret(INFO_TX_VIEWING_X25519);
    let salted: Uint8Array | undefined;
    try {
      salted = hkdfExpand(nullifier, txViewingSecret, encoder.encode(INFO_TX_VIEWING_X25519), 32);
      return ViewingKey.fromBytes(salted as Bytes32);
    } finally {
      txViewingSecret.fill(0);
      salted?.fill(0);
    }
  }

  encryptSlot(
    recipientPublicKey: X25519PublicKey,
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
    txViewingPublicKey: X25519PublicKey,
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
    recipientPublicKey: X25519PublicKey,
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
    txViewingPublicKey: X25519PublicKey,
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
    recipientPublicKey: X25519PublicKey,
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

  // Cache the role root on first use. Encryption does not need this root.
  #viewSecret(info: string | Uint8Array): Uint8Array {
    this.#assertUsable();
    this.#viewRoot ??= viewRoot(this.#secret);
    const infoBytes = typeof info === "string" ? encoder.encode(info) : info;
    try {
      return expand(sha256, this.#viewRoot, infoBytes, 32);
    } catch (error) {
      throw new KeypairError(
        "KEYPAIR_HKDF",
        { name: typeof info === "string" ? info : "ring derivation" },
        error,
      );
    }
  }

  #assertUsable(): void {
    if (this.#destroyed) {
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
    }
  }
}
