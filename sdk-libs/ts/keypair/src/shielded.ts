import bs58 from "bs58";

import {
  type Address,
  type Bytes31,
  type Bytes32,
  type Bytes64,
  checkedBytes,
  concatBytes,
  copyBytes,
} from "./bytes.js";
import { ownerHash, pack33 } from "./hash.js";
import { NullifierKey } from "./nullifier-key.js";
import { poseidon } from "./poseidon.js";
import {
  P256PublicKey,
  ShieldedPublicKey,
  type SignatureType,
  type ViewTag,
} from "./public-key.js";
import { SigningKey } from "./signing-key.js";
import { type Salt, ViewingKey } from "./viewing-key.js";

export class ShieldedAddress {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;

  readonly #nullifierPublicKey: Bytes32;

  private constructor(
    signingPublicKey: ShieldedPublicKey,
    nullifierPublicKey: Bytes32,
    viewingPublicKey: P256PublicKey,
  ) {
    this.signingPublicKey = signingPublicKey;
    this.#nullifierPublicKey = nullifierPublicKey;
    this.viewingPublicKey = viewingPublicKey;
    Object.freeze(this);
  }

  static fromPublicKeys(
    signingPublicKey: ShieldedPublicKey,
    nullifierPublicKey: Bytes32,
    viewingPublicKey: P256PublicKey,
  ): ShieldedAddress {
    return new ShieldedAddress(
      ShieldedPublicKey.fromBytes(signingPublicKey.toBytes()),
      checkedBytes<Bytes32>(nullifierPublicKey, 32, "nullifier public key"),
      P256PublicKey.fromBytes(viewingPublicKey.toBytes()),
    );
  }

  get nullifierPublicKey(): Bytes32 {
    return copyBytes(this.#nullifierPublicKey) as Bytes32;
  }

  ownerHash(): Bytes32 {
    return ownerHash(
      this.signingPublicKey.ownerPublicKeyField(),
      this.#nullifierPublicKey,
    ) as Bytes32;
  }

  solanaAddress(): Address {
    return bs58.encode(this.signingPublicKey.ed25519()) as Address;
  }

  confidentialViewTag(): ViewTag {
    return this.signingPublicKey.confidentialViewTag();
  }
}

/**
 * Mirrors Rust's `CompressedShieldedAddress`: the owner hash plus the viewing
 * key, with the same Poseidon compression the circuit applies. `bytes` is the
 * 65-byte wire form (`owner_hash || viewing_pk`).
 */
export class CompressedShieldedAddress {
  readonly ownerHash: Bytes32;
  readonly viewingPublicKey: P256PublicKey;

  private constructor(ownerHash: Bytes32, viewingPublicKey: P256PublicKey) {
    this.ownerHash = ownerHash;
    this.viewingPublicKey = viewingPublicKey;
    Object.freeze(this);
  }

  static fromParts(ownerHash: Bytes32, viewingPublicKey: P256PublicKey): CompressedShieldedAddress {
    return new CompressedShieldedAddress(
      checkedBytes<Bytes32>(ownerHash, 32, "owner hash"),
      P256PublicKey.fromBytes(viewingPublicKey.toBytes()),
    );
  }

  static fromAddress(address: ShieldedAddress): CompressedShieldedAddress {
    return CompressedShieldedAddress.fromParts(address.ownerHash(), address.viewingPublicKey);
  }

  get bytes(): Uint8Array {
    return concatBytes(this.ownerHash, this.viewingPublicKey.toBytes());
  }

  hash(): Bytes32 {
    const [low, high] = pack33(this.viewingPublicKey.toBytes());
    return poseidon([this.ownerHash, low, high]) as Bytes32;
  }
}

export interface P256Signature {
  readonly publicKey: P256PublicKey;
  readonly r: Bytes32;
  readonly s: Bytes32;
}

/**
 * The `ShieldedKeypairTrait` surface: signing identity, address derivation,
 * spend signing, and nullifier derivation. Every operation may be asynchronous
 * so an HSM- or wallet-backed implementer can satisfy it. View-tag derivation
 * and UTXO encryption live on {@link ViewingKeyLike}; a backend exposes both.
 *
 * An implementer must hold nullifier-key material. A custodian that exposes a
 * signing operation alone is not a supported configuration.
 */
export interface ShieldedKeypairLike {
  signingPublicKey(): ShieldedPublicKey | Promise<ShieldedPublicKey>;
  viewingPublicKey(): P256PublicKey | Promise<P256PublicKey>;
  /** The rail this keypair signs on, which selects the transfer circuit. */
  curve(): SignatureType | Promise<SignatureType>;
  shieldedAddress(): ShieldedAddress | Promise<ShieldedAddress>;
  ownerHash(): Bytes32 | Promise<Bytes32>;
  compressedAddress(): CompressedShieldedAddress | Promise<CompressedShieldedAddress>;
  sign(message: Uint8Array): Bytes64 | Promise<Bytes64>;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 | Promise<Bytes32>;
  /** The nullifier public key, so a caller can build inputs without the secret. */
  nullifierPublicKey(): Bytes32 | Promise<Bytes32>;
}

/**
 * The `ViewingKeyTrait` surface. Constructors and `secretBytes` are excluded on
 * purpose: a backend keeps the secret and exposes only operations over it.
 *
 * An implementer must hold viewing-key material. A custodian that exposes a
 * signing operation alone is not a supported configuration.
 */
export interface ViewingKeyLike {
  publicKey(): P256PublicKey | Promise<P256PublicKey>;
  ecdh(counterparty: P256PublicKey): Bytes32 | Promise<Bytes32>;
  senderViewTag(txCount: bigint): ViewTag | Promise<ViewTag>;
  recipientRequestViewTag(requestCount: bigint): ViewTag | Promise<ViewTag>;
  mergeViewTag(mergeCount: bigint): ViewTag | Promise<ViewTag>;
  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag | Promise<ViewTag>;
  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag | Promise<ViewTag>;
  recipientBootstrapViewTag(): ViewTag | Promise<ViewTag>;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey | Promise<ViewingKey>;
  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array | Promise<Uint8Array>;
  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array | Promise<Uint8Array>;
  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array | Promise<Uint8Array>;
  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ):
    | Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }>
    | Promise<Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }>>;
  decryptVerifiable(
    txViewingPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
  ): Uint8Array | Promise<Uint8Array>;
}

export class ShieldedKeypair implements ShieldedKeypairLike, ViewingKeyLike {
  readonly #signing: SigningKey;
  readonly #nullifier: NullifierKey;
  readonly #viewing: ViewingKey;

  private constructor(signing: SigningKey, nullifier: NullifierKey, viewing: ViewingKey) {
    this.#signing = signing;
    this.#nullifier = nullifier;
    this.#viewing = viewing;
  }

  static generate(): ShieldedKeypair {
    return ShieldedKeypair.fromSigningAndViewingKeys(SigningKey.generate(), ViewingKey.generate());
  }

  /**
   * Mirrors Rust's two-argument `ShieldedKeypair::from_keys`: the nullifier key
   * is derived from the signing secret rather than supplied, which is what
   * makes the owner hash reproducible from the signing key alone.
   */
  static fromSigningAndViewingKeys(signing: SigningKey, viewing: ViewingKey): ShieldedKeypair {
    return new ShieldedKeypair(signing, NullifierKey.fromSigningKey(signing), viewing);
  }

  static fromKeys(
    signing: SigningKey,
    nullifier: NullifierKey,
    viewing: ViewingKey,
  ): ShieldedKeypair {
    return new ShieldedKeypair(signing, nullifier, viewing);
  }

  static fromEd25519(secret: Bytes32, account: number): ShieldedKeypair {
    const owned = checkedBytes<Bytes32>(secret, 32, "Ed25519 signing secret");
    const signing = SigningKey.fromEd25519Bytes(owned);
    const nullifier = NullifierKey.fromSigningSecret(owned);
    const viewing = ViewingKey.fromSeed(owned, account);
    owned.fill(0);
    return new ShieldedKeypair(signing, nullifier, viewing);
  }

  signingPublicKey(): ShieldedPublicKey {
    return this.#signing.publicKey();
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

  curve(): SignatureType {
    return this.#signing.signatureType();
  }

  nullifierPublicKey(): Bytes32 {
    return this.#nullifier.publicKey();
  }

  shieldedAddress(): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
      this.signingPublicKey(),
      this.#nullifier.publicKey(),
      this.viewingPublicKey(),
    );
  }

  ownerHash(): Bytes32 {
    return ownerHash(
      this.signingPublicKey().ownerPublicKeyField(),
      this.#nullifier.publicKey(),
    ) as Bytes32;
  }

  compressedAddress(): CompressedShieldedAddress {
    return CompressedShieldedAddress.fromParts(this.ownerHash(), this.viewingPublicKey());
  }

  // --- ViewingKeyLike: forwards to the inner viewing key, so a full keypair
  // stands in wherever a viewing-key backend is required (Rust does the same
  // with its `ViewingKeyTrait for ShieldedKeypair` impl).

  /**
   * The viewing public key, matching `ViewingKeyTrait::pubkey` for Rust's
   * `ShieldedKeypair`. Prefer {@link ShieldedKeypair.viewingPublicKey} when the
   * call site is not going through {@link ViewingKeyLike}.
   */
  publicKey(): P256PublicKey {
    return this.viewingPublicKey();
  }

  ecdh(counterparty: P256PublicKey): Bytes32 {
    return this.#viewing.ecdh(counterparty);
  }

  senderViewTag(txCount: bigint): ViewTag {
    return this.#viewing.senderViewTag(txCount);
  }

  recipientRequestViewTag(requestCount: bigint): ViewTag {
    return this.#viewing.recipientRequestViewTag(requestCount);
  }

  mergeViewTag(mergeCount: bigint): ViewTag {
    return this.#viewing.mergeViewTag(mergeCount);
  }

  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#viewing.sendSharedViewTag(counterparty, index);
  }

  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#viewing.recipientSharedViewTag(counterparty, index);
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

  sign(message: Uint8Array): Bytes64 {
    return this.#signing.sign(message);
  }

  signP256(messageHash: Bytes32): P256Signature {
    const publicKey = this.#signing.publicKey().p256();
    const signature = this.#signing.sign(
      checkedBytes<Bytes32>(messageHash, 32, "P256 message hash"),
    );
    return Object.freeze({
      publicKey,
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 {
    return this.#nullifier.nullifier(utxoHash, blinding);
  }

  destroy(): void {
    this.#signing.destroy();
    this.#nullifier.destroy();
    this.#viewing.destroy();
  }
}
