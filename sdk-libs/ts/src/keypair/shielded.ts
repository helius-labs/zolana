import {
  getAddressDecoder,
  getAddressEncoder,
  type Address,
  type SignatureBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import { type Bytes32, type Bytes64, checkedBytes, concatBytes, copyBytes } from "./bytes.js";
import { RoleExpansion } from "./derivation.js";
import { KeypairError } from "./error.js";
import { ownerHash, pack33 } from "./hash.js";
import { NullifierKey } from "./nullifier-key.js";
import { poseidon } from "./poseidon.js";
import {
  P256PublicKey,
  ShieldedPublicKey,
  type Curve,
  type SigningCurve,
  type ViewTag,
} from "./public-key.js";
import { SigningKey } from "./signing-key.js";
import { type Salt, ViewingKey } from "./viewing-key.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();

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

  static forPda(
    pda: Address,
    nullifierPublicKey: Bytes32,
    viewingPublicKey: P256PublicKey,
  ): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromPda(new Uint8Array(addressEncoder.encode(pda)) as Bytes32),
      nullifierPublicKey,
      viewingPublicKey,
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
    switch (this.signingPublicKey.curve()) {
      case "ed25519":
        return addressDecoder.decode(this.signingPublicKey.ed25519());
      case "pda":
        return addressDecoder.decode(this.signingPublicKey.pda());
      case "p256":
        throw new KeypairError("KEYPAIR_NO_SOLANA_ADDRESS");
    }
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
  curve(): Curve | Promise<Curve>;
  shieldedAddress(): ShieldedAddress | Promise<ShieldedAddress>;
  ownerHash(): Bytes32 | Promise<Bytes32>;
  compressedAddress(): CompressedShieldedAddress | Promise<CompressedShieldedAddress>;
  sign(message: Uint8Array): Bytes64 | Promise<Bytes64>;
  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 | Promise<Bytes32>;
  /** The nullifier public key, so a caller can build inputs without the secret. */
  nullifierPublicKey(): Bytes32 | Promise<Bytes32>;
}

/**
 * The `ViewingKeyTrait` surface. Constructors and `secretBytes` are excluded on
 * purpose: a backend keeps the secret and exposes only operations over it.
 *
 * An implementer must hold viewing-key material in memory. Every operation
 * returns synchronously, as Rust's `ViewingKeyTrait` does: a backend answering
 * viewing-key operations over a wire is not a supported deployment.
 */
export interface ViewingKeyLike {
  publicKey(): P256PublicKey;
  ecdh(counterparty: P256PublicKey): Bytes32;
  mergeViewTag(mergeCount: bigint): ViewTag;
  recipientBootstrapViewTag(): ViewTag;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey;
  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }>;
  decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
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

  /**
   * Generates an Ed25519 signing identity by default, the rail supported by
   * the lean SDK's registration and ordinary transaction builders. Viewing
   * keys remain P256 on both signing rails.
   */
  static generate(curve: SigningCurve = "ed25519"): ShieldedKeypair {
    return ShieldedKeypair.fromKeypair(SigningKey.generate(curve));
  }

  static fromKeypair(signing: SigningKey): ShieldedKeypair {
    const seed = signing.derivationSeed();
    const expansion = new RoleExpansion(seed, signing.curve());
    try {
      return new ShieldedKeypair(signing, expansion.nullifierKey(), expansion.viewingKey());
    } finally {
      seed.fill(0);
      expansion.destroy();
    }
  }

  static fromParts(signing: SigningKey, viewing: ViewingKey): ShieldedKeypair {
    const seed = signing.derivationSeed();
    const expansion = new RoleExpansion(seed, signing.curve());
    try {
      return new ShieldedKeypair(signing, expansion.nullifierKey(), viewing);
    } finally {
      seed.fill(0);
      expansion.destroy();
    }
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

  curve(): Curve {
    return this.#signing.curve();
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

  /**
   * The Solana signer for this identity, so one seed pays fees and owns the
   * private balance. Mirrors Rust's `to_solana_keypair`.
   *
   * Kit builds its own signers through WebCrypto and can only do so
   * asynchronously. This one signs with the same Ed25519 the shielded keys
   * already use, which keeps construction synchronous; `signTransactions` still
   * returns a promise because Kit's interface demands one.
   *
   * Only the Ed25519 rail has a Solana identity: a P256 signing key has no
   * Solana address to sign for.
   */
  toSolanaSigner(): TransactionPartialSigner {
    if (this.#signing.curve() !== "ed25519") {
      throw new KeypairError("KEYPAIR_NOT_ED25519");
    }
    const address = addressDecoder.decode(this.signingPublicKey().ed25519());
    const signing = this.#signing;
    return Object.freeze({
      address,
      signTransactions: (transactions) =>
        Promise.resolve(
          transactions.map((transaction) => {
            // Both sides are 64-byte brands over the same bytes, and Kit's
            // message bytes are a readonly view of a plain Uint8Array.
            const signature = signing.sign(
              new Uint8Array(transaction.messageBytes),
            ) as unknown as SignatureBytes;
            return Object.freeze({ [address]: signature });
          }),
        ),
    });
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

  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
    return this.#nullifier.nullifier(utxoHash, blinding);
  }

  destroy(): void {
    this.#signing.destroy();
    this.#nullifier.destroy();
    this.#viewing.destroy();
  }
}
