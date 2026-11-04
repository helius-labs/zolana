import type { Address } from "@solana/kit";

import { bytes32, type Bytes32, type Bytes64 } from "./bytes.js";
import { KeypairError } from "./error.js";
import { ownerHash } from "./hash.js";
import { NullifierKey } from "./nullifier-key.js";
import { ShieldedPublicKey, type ViewTag } from "./public-key.js";
import {
  CompressedShieldedAddress,
  ShieldedAddress,
  type ShieldedKeypairLike,
  type ViewingKeyLike,
} from "./shielded.js";
import { ViewingKey, type Salt } from "./viewing-key.js";
import type { X25519PublicKey } from "./x25519.js";

/** A PDA signing identity with supplied privacy roles and no signing secret. */
export class ShieldedPda implements ShieldedKeypairLike, ViewingKeyLike {
  readonly #signing: ShieldedPublicKey;
  readonly #nullifier: NullifierKey;
  readonly #viewing: ViewingKey;

  private constructor(signing: ShieldedPublicKey, nullifier: NullifierKey, viewing: ViewingKey) {
    this.#signing = signing;
    this.#nullifier = nullifier;
    this.#viewing = viewing;
  }

  /**
   * Takes ownership of both supplied role keys, including on failure.
   * Destroy the PDA when finished; pass clones to retain the original keys.
   */
  static withViewingKey(
    pda: Address | Bytes32,
    nullifierKey: NullifierKey,
    viewingKey: ViewingKey,
  ): ShieldedPda {
    if (!(nullifierKey instanceof NullifierKey) || !(viewingKey instanceof ViewingKey)) {
      if (nullifierKey instanceof NullifierKey) nullifierKey.destroy();
      if (viewingKey instanceof ViewingKey) viewingKey.destroy();
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY");
    }
    try {
      const signing = ShieldedPublicKey.fromPda(pda);
      nullifierKey.publicKey();
      viewingKey.publicKey();
      return new ShieldedPda(signing, nullifierKey, viewingKey);
    } catch (cause) {
      nullifierKey.destroy();
      viewingKey.destroy();
      throw cause;
    }
  }

  signingPublicKey(): ShieldedPublicKey {
    return ShieldedPublicKey.fromBytes(this.#signing.toBytes());
  }

  curve(): "pda" {
    return "pda";
  }

  viewingPublicKey(): X25519PublicKey {
    return this.#viewing.publicKey();
  }

  viewingKey(): ViewingKey {
    return this.#viewing.clone();
  }

  nullifierPublicKey(): Bytes32 {
    return this.#nullifier.publicKey();
  }

  nullifierKey(): NullifierKey {
    return this.#nullifier.clone();
  }

  shieldedAddress(): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
      this.signingPublicKey(),
      this.nullifierPublicKey(),
      this.viewingPublicKey(),
    );
  }

  ownerHash(): Bytes32 {
    return bytes32(ownerHash(this.#signing.ownerProofInputHash(), this.nullifierPublicKey()));
  }

  compressedAddress(): CompressedShieldedAddress {
    return CompressedShieldedAddress.fromAddress(this.shieldedAddress());
  }

  sign(_message: Uint8Array): Bytes64 {
    throw new KeypairError("KEYPAIR_PDA_CANNOT_SIGN");
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
    return this.#nullifier.nullifier(utxoHash, blinding);
  }

  publicKey(): X25519PublicKey {
    return this.viewingPublicKey();
  }

  ecdh(counterparty: X25519PublicKey): Bytes32 {
    return this.#viewing.ecdh(counterparty);
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.#viewing.recipientBootstrapViewTag();
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    return this.#viewing.transactionViewingKey(firstNullifier);
  }

  encryptSlot(
    recipient: X25519PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.encryptSlot(recipient, plaintext, salt, slotIndex);
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: X25519PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex);
  }

  decryptSlotEphemeral(
    recipient: X25519PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.decryptSlotEphemeral(recipient, ciphertext, salt, slotIndex);
  }

  decryptRingDeposit(
    ciphertext: Uint8Array,
    txViewingPublicKey: X25519PublicKey,
    salt: Salt,
  ): Uint8Array {
    return this.#viewing.decryptRingDeposit(ciphertext, txViewingPublicKey, salt);
  }

  destroy(): void {
    this.#nullifier.destroy();
    this.#viewing.destroy();
  }
}
