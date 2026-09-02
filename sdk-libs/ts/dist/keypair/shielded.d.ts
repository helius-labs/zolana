import { type Address } from "@solana/kit";
import { type Bytes32, type Bytes64 } from "./bytes.js";
import { NullifierKey } from "./nullifier-key.js";
import { P256PublicKey, ShieldedPublicKey, type SignatureType, type ViewTag } from "./public-key.js";
import { SigningKey } from "./signing-key.js";
import { type Salt, ViewingKey } from "./viewing-key.js";
export declare class ShieldedAddress {
    #private;
    readonly signingPublicKey: ShieldedPublicKey;
    readonly viewingPublicKey: P256PublicKey;
    private constructor();
    static fromPublicKeys(signingPublicKey: ShieldedPublicKey, nullifierPublicKey: Bytes32, viewingPublicKey: P256PublicKey): ShieldedAddress;
    get nullifierPublicKey(): Bytes32;
    ownerHash(): Bytes32;
    solanaAddress(): Address;
    confidentialViewTag(): ViewTag;
}
/**
 * Mirrors Rust's `CompressedShieldedAddress`: the owner hash plus the viewing
 * key, with the same Poseidon compression the circuit applies. `bytes` is the
 * 65-byte wire form (`owner_hash || viewing_pk`).
 */
export declare class CompressedShieldedAddress {
    readonly ownerHash: Bytes32;
    readonly viewingPublicKey: P256PublicKey;
    private constructor();
    static fromParts(ownerHash: Bytes32, viewingPublicKey: P256PublicKey): CompressedShieldedAddress;
    static fromAddress(address: ShieldedAddress): CompressedShieldedAddress;
    get bytes(): Uint8Array;
    hash(): Bytes32;
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
    encryptSlot(recipientPublicKey: P256PublicKey, plaintext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    decryptUtxo(ciphertext: Uint8Array, txViewingPublicKey: P256PublicKey, salt: Salt, slotIndex: number): Uint8Array;
    decryptSlotEphemeral(recipientPublicKey: P256PublicKey, ciphertext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    encryptVerifiable(userViewingPublicKey: P256PublicKey, plaintext: Uint8Array): Readonly<{
        ciphertext: Uint8Array;
        txViewingPublicKey: P256PublicKey;
    }>;
    decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
}
export declare class ShieldedKeypair implements ShieldedKeypairLike, ViewingKeyLike {
    #private;
    private constructor();
    /**
     * Generates an Ed25519 signing identity by default, the rail supported by
     * the lean SDK's registration and ordinary transaction builders. Viewing
     * keys remain P256 on both signing rails.
     */
    static generate(type?: SignatureType): ShieldedKeypair;
    /**
     * Mirrors Rust's two-argument `ShieldedKeypair::from_keys`: the nullifier key
     * is derived from the signing secret rather than supplied, which is what
     * makes the owner hash reproducible from the signing key alone.
     */
    static fromSigningAndViewingKeys(signing: SigningKey, viewing: ViewingKey): ShieldedKeypair;
    static fromKeys(signing: SigningKey, nullifier: NullifierKey, viewing: ViewingKey): ShieldedKeypair;
    static fromEd25519(secret: Bytes32, account: number): ShieldedKeypair;
    signingPublicKey(): ShieldedPublicKey;
    viewingPublicKey(): P256PublicKey;
    viewingKey(): ViewingKey;
    nullifierKey(): NullifierKey;
    curve(): SignatureType;
    nullifierPublicKey(): Bytes32;
    shieldedAddress(): ShieldedAddress;
    ownerHash(): Bytes32;
    compressedAddress(): CompressedShieldedAddress;
    /**
     * The viewing public key, matching `ViewingKeyTrait::pubkey` for Rust's
     * `ShieldedKeypair`. Prefer {@link ShieldedKeypair.viewingPublicKey} when the
     * call site is not going through {@link ViewingKeyLike}.
     */
    publicKey(): P256PublicKey;
    ecdh(counterparty: P256PublicKey): Bytes32;
    mergeViewTag(mergeCount: bigint): ViewTag;
    recipientBootstrapViewTag(): ViewTag;
    transactionViewingKey(firstNullifier: Bytes32): ViewingKey;
    encryptSlot(recipientPublicKey: P256PublicKey, plaintext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    decryptUtxo(ciphertext: Uint8Array, txViewingPublicKey: P256PublicKey, salt: Salt, slotIndex: number): Uint8Array;
    decryptSlotEphemeral(recipientPublicKey: P256PublicKey, ciphertext: Uint8Array, salt: Salt, slotIndex: number): Uint8Array;
    encryptVerifiable(userViewingPublicKey: P256PublicKey, plaintext: Uint8Array): Readonly<{
        ciphertext: Uint8Array;
        txViewingPublicKey: P256PublicKey;
    }>;
    decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
    sign(message: Uint8Array): Bytes64;
    signP256(messageHash: Bytes32): P256Signature;
    nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32;
    destroy(): void;
}
