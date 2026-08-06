import { getAddressEncoder, type Address } from "@solana/kit";

import { type Bytes32, type Bytes64 } from "./bytes.js";
import { P_PDA, PdaRoleExpansion } from "./derivation.js";
import { KeypairError } from "./error.js";
import { NullifierKey } from "./nullifier-key.js";
import { P256PublicKey, ShieldedPublicKey, type Curve, type ViewTag } from "./public-key.js";
import {
  CompressedShieldedAddress,
  ShieldedAddress,
  type ShieldedKeypairLike,
  type ViewingKeyLike,
} from "./shielded.js";
import { type Salt, VIEWING_KEY_ECDH_RAW, ViewingKey } from "./viewing-key.js";

const addressEncoder = getAddressEncoder();

/** A shielded identity owned by a program-derived address. */
export class ShieldedPda implements ShieldedKeypairLike, ViewingKeyLike {
  readonly #pda: Address;
  readonly #nullifier: NullifierKey;
  readonly #viewing: ViewingKey;

  private constructor(pda: Address, nullifier: NullifierKey, viewing: ViewingKey) {
    this.#pda = pda;
    this.#nullifier = nullifier;
    this.#viewing = viewing;
  }

  static fromKeyExchange(pda: Address, own: ViewingKey, counterparty: P256PublicKey): ShieldedPda {
    return ShieldedPda.#expand(pda, own.ecdh(counterparty));
  }

  static fromViewingKey(pda: Address, own: ViewingKey): ShieldedPda {
    return ShieldedPda.#expand(pda, own[VIEWING_KEY_ECDH_RAW](P_PDA));
  }

  static fromParts(pda: Address, nullifier: NullifierKey, viewing: ViewingKey): ShieldedPda {
    return new ShieldedPda(pda, nullifier, viewing);
  }

  static #expand(pda: Address, shared: Bytes32): ShieldedPda {
    const pdaBytes = new Uint8Array(addressEncoder.encode(pda)) as Bytes32;
    const expansion = new PdaRoleExpansion(shared, pdaBytes);
    try {
      return new ShieldedPda(pda, expansion.nullifierKey(), expansion.viewingKey());
    } finally {
      shared.fill(0);
      expansion.destroy();
    }
  }

  pda(): Address {
    return this.#pda;
  }

  signingPublicKey(): ShieldedPublicKey {
    return ShieldedPublicKey.fromPda(new Uint8Array(addressEncoder.encode(this.#pda)) as Bytes32);
  }

  viewingPublicKey(): P256PublicKey {
    return this.#viewing.publicKey();
  }

  viewingKey(): ViewingKey {
    const secret = this.#viewing.secretBytes();
    try {
      return ViewingKey.fromBytes(secret);
    } finally {
      secret.fill(0);
    }
  }

  nullifierKey(): NullifierKey {
    const secret = this.#nullifier.secretBytes();
    try {
      return NullifierKey.fromSecret(secret);
    } finally {
      secret.fill(0);
    }
  }

  curve(): Curve {
    return "pda";
  }

  shieldedAddress(): ShieldedAddress {
    return ShieldedAddress.forPda(this.#pda, this.#nullifier.publicKey(), this.viewingPublicKey());
  }

  nullifierPublicKey(): Bytes32 {
    return this.#nullifier.publicKey();
  }

  ownerHash(): Bytes32 {
    return this.shieldedAddress().ownerHash();
  }

  compressedAddress(): CompressedShieldedAddress {
    return CompressedShieldedAddress.fromParts(this.ownerHash(), this.viewingPublicKey());
  }

  sign(_message: Uint8Array): Bytes64 {
    throw new KeypairError("KEYPAIR_PDA_CANNOT_SIGN");
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
    return this.#nullifier.nullifier(utxoHash, blinding);
  }

  publicKey(): P256PublicKey {
    return this.viewingPublicKey();
  }

  ecdh(counterparty: P256PublicKey): Bytes32 {
    return this.#viewing.ecdh(counterparty);
  }

  mergeViewTag(mergeCount: bigint): ViewTag {
    return this.#viewing.mergeViewTag(mergeCount);
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.#viewing.recipientBootstrapViewTag();
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    return this.#viewing.transactionViewingKey(firstNullifier);
  }

  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.encryptSlot(recipientPublicKey, plaintext, salt, slotIndex);
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex);
  }

  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.#viewing.decryptSlotEphemeral(recipientPublicKey, ciphertext, salt, slotIndex);
  }

  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }> {
    return this.#viewing.encryptVerifiable(userViewingPublicKey, plaintext);
  }

  decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array {
    return this.#viewing.decryptVerifiable(txViewingPublicKey, ciphertext);
  }

  destroy(): void {
    this.#nullifier.destroy();
    this.#viewing.destroy();
  }
}
