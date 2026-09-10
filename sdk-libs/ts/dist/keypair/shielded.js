import { getAddressDecoder } from "@solana/kit";
import { checkedBytes, concatBytes, copyBytes } from "./bytes.js";
import { ownerHash, pack33 } from "./hash.js";
import { NullifierKey } from "./nullifier-key.js";
import { poseidon } from "./poseidon.js";
import { P256PublicKey, ShieldedPublicKey, } from "./public-key.js";
import { SigningKey } from "./signing-key.js";
import { ViewingKey } from "./viewing-key.js";
const addressDecoder = getAddressDecoder();
export class ShieldedAddress {
    signingPublicKey;
    viewingPublicKey;
    #nullifierPublicKey;
    constructor(signingPublicKey, nullifierPublicKey, viewingPublicKey) {
        this.signingPublicKey = signingPublicKey;
        this.#nullifierPublicKey = nullifierPublicKey;
        this.viewingPublicKey = viewingPublicKey;
        Object.freeze(this);
    }
    static fromPublicKeys(signingPublicKey, nullifierPublicKey, viewingPublicKey) {
        return new ShieldedAddress(ShieldedPublicKey.fromBytes(signingPublicKey.toBytes()), checkedBytes(nullifierPublicKey, 32, "nullifier public key"), P256PublicKey.fromBytes(viewingPublicKey.toBytes()));
    }
    get nullifierPublicKey() {
        return copyBytes(this.#nullifierPublicKey);
    }
    ownerHash() {
        return ownerHash(this.signingPublicKey.ownerPublicKeyField(), this.#nullifierPublicKey);
    }
    solanaAddress() {
        return addressDecoder.decode(this.signingPublicKey.ed25519());
    }
    confidentialViewTag() {
        return this.signingPublicKey.confidentialViewTag();
    }
}
/**
 * Mirrors Rust's `CompressedShieldedAddress`: the owner hash plus the viewing
 * key, with the same Poseidon compression the circuit applies. `bytes` is the
 * 65-byte wire form (`owner_hash || viewing_pk`).
 */
export class CompressedShieldedAddress {
    ownerHash;
    viewingPublicKey;
    constructor(ownerHash, viewingPublicKey) {
        this.ownerHash = ownerHash;
        this.viewingPublicKey = viewingPublicKey;
        Object.freeze(this);
    }
    static fromParts(ownerHash, viewingPublicKey) {
        return new CompressedShieldedAddress(checkedBytes(ownerHash, 32, "owner hash"), P256PublicKey.fromBytes(viewingPublicKey.toBytes()));
    }
    static fromAddress(address) {
        return CompressedShieldedAddress.fromParts(address.ownerHash(), address.viewingPublicKey);
    }
    get bytes() {
        return concatBytes(this.ownerHash, this.viewingPublicKey.toBytes());
    }
    hash() {
        const [low, high] = pack33(this.viewingPublicKey.toBytes());
        return poseidon([this.ownerHash, low, high]);
    }
}
export class ShieldedKeypair {
    #signing;
    #nullifier;
    #viewing;
    constructor(signing, nullifier, viewing) {
        this.#signing = signing;
        this.#nullifier = nullifier;
        this.#viewing = viewing;
    }
    /**
     * Generates an Ed25519 signing identity by default, the rail supported by
     * the lean SDK's registration and ordinary transaction builders. Viewing
     * keys remain P256 on both signing rails.
     */
    static generate(type = "ed25519") {
        return ShieldedKeypair.fromSigningAndViewingKeys(SigningKey.generate(type), ViewingKey.generate());
    }
    /**
     * Mirrors Rust's two-argument `ShieldedKeypair::from_keys`: the nullifier key
     * is derived from the signing secret rather than supplied, which is what
     * makes the owner hash reproducible from the signing key alone.
     */
    static fromSigningAndViewingKeys(signing, viewing) {
        return new ShieldedKeypair(signing, NullifierKey.fromSigningKey(signing), viewing);
    }
    static fromKeys(signing, nullifier, viewing) {
        return new ShieldedKeypair(signing, nullifier, viewing);
    }
    static fromEd25519(secret, account) {
        const owned = checkedBytes(secret, 32, "Ed25519 signing secret");
        const signing = SigningKey.fromEd25519Bytes(owned);
        const nullifier = NullifierKey.fromSigningSecret(owned);
        const viewing = ViewingKey.fromSeed(owned, account);
        owned.fill(0);
        return new ShieldedKeypair(signing, nullifier, viewing);
    }
    signingPublicKey() {
        return this.#signing.publicKey();
    }
    viewingPublicKey() {
        return this.#viewing.publicKey();
    }
    viewingKey() {
        const secret = this.#viewing.secretBytes();
        try {
            return ViewingKey.fromBytes(secret);
        }
        finally {
            secret.fill(0);
        }
    }
    nullifierKey() {
        const secret = this.#nullifier.secretBytes();
        try {
            return NullifierKey.fromSecret(secret);
        }
        finally {
            secret.fill(0);
        }
    }
    curve() {
        return this.#signing.signatureType();
    }
    nullifierPublicKey() {
        return this.#nullifier.publicKey();
    }
    shieldedAddress() {
        return ShieldedAddress.fromPublicKeys(this.signingPublicKey(), this.#nullifier.publicKey(), this.viewingPublicKey());
    }
    ownerHash() {
        return ownerHash(this.signingPublicKey().ownerPublicKeyField(), this.#nullifier.publicKey());
    }
    compressedAddress() {
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
    publicKey() {
        return this.viewingPublicKey();
    }
    ecdh(counterparty) {
        return this.#viewing.ecdh(counterparty);
    }
    mergeViewTag(mergeCount) {
        return this.#viewing.mergeViewTag(mergeCount);
    }
    recipientBootstrapViewTag() {
        return this.#viewing.recipientBootstrapViewTag();
    }
    transactionViewingKey(firstNullifier) {
        return this.#viewing.transactionViewingKey(firstNullifier);
    }
    encryptSlot(recipientPublicKey, plaintext, salt, slotIndex) {
        return this.#viewing.encryptSlot(recipientPublicKey, plaintext, salt, slotIndex);
    }
    decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex) {
        return this.#viewing.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex);
    }
    decryptSlotEphemeral(recipientPublicKey, ciphertext, salt, slotIndex) {
        return this.#viewing.decryptSlotEphemeral(recipientPublicKey, ciphertext, salt, slotIndex);
    }
    encryptVerifiable(userViewingPublicKey, plaintext) {
        return this.#viewing.encryptVerifiable(userViewingPublicKey, plaintext);
    }
    decryptVerifiable(txViewingPublicKey, ciphertext) {
        return this.#viewing.decryptVerifiable(txViewingPublicKey, ciphertext);
    }
    sign(message) {
        return this.#signing.sign(message);
    }
    signP256(messageHash) {
        const publicKey = this.#signing.publicKey().p256();
        const signature = this.#signing.sign(checkedBytes(messageHash, 32, "P256 message hash"));
        return Object.freeze({
            publicKey,
            r: signature.slice(0, 32),
            s: signature.slice(32),
        });
    }
    nullifier(utxoHash, blinding) {
        return this.#nullifier.nullifier(utxoHash, blinding);
    }
    destroy() {
        this.#signing.destroy();
        this.#nullifier.destroy();
        this.#viewing.destroy();
    }
}
