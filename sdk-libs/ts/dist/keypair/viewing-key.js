import { p256 } from "@noble/curves/nist.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBigInt, checkedBytes, concatBytes, copyBytes, randomBytes, u32be, u64be, } from "./bytes.js";
import { INFO_MERGE_VIEW_TAG_PREFIX, INFO_MERGE_VIEW_TAG_SECRET, INFO_TX_VIEWING, P_CONST_SEC1, } from "./constants.js";
import { applyTransferCipher, ecdhX } from "./encryption.js";
import { KeypairError } from "./error.js";
import { decryptVerifiableSecret, encryptVerifiableSecret } from "./merge/core.js";
import { P256PublicKey } from "./public-key.js";
const encoder = new TextEncoder();
const P256_ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369n;
const P_CONST = P256PublicKey.fromBytes(P_CONST_SEC1);
// Rust separates `ZeroScalar` from `InvalidSecretKey`: the first says the
// derivation landed on zero, the second says the caller supplied an out-of-range
// secret. Collapsing them would hide which one a wallet hit.
function scalarFromOkm(okm) {
    const scalar = bytesToBigInt(okm) % P256_ORDER;
    if (scalar === 0n) {
        throw new KeypairError("KEYPAIR_ZERO_SCALAR");
    }
    const bytes = new Uint8Array(32);
    let value = scalar;
    for (let index = 31; index >= 0; index--) {
        bytes[index] = Number(value & 0xffn);
        value >>= 8n;
    }
    return bytes;
}
/** Every HKDF failure surfaces as Rust's `Hkdf`, not as a generic key error. */
function expandOrThrow(ikm, info, length, salt) {
    try {
        return hkdf(sha256, ikm, salt, info, length);
    }
    catch (error) {
        throw new KeypairError("KEYPAIR_HKDF", { actual: length }, error);
    }
}
function checkCounter(value, name) {
    if (value < 0n || value > 0xffffffffffffffffn) {
        throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
            name,
            minimum: "0",
            maximum: "18446744073709551615",
        });
    }
    return u64be(value);
}
function checkSlotIndex(value) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
            name: "slotIndex",
            minimum: 0,
            maximum: 0xffff_ffff,
        });
    }
    return value;
}
export class ViewingKey {
    #secret;
    #viewRoot;
    #destroyed = false;
    constructor(secret) {
        this.#secret = secret;
        const shared = ecdhX(secret, P_CONST);
        this.#viewRoot = extract(sha256, shared);
        shared.fill(0);
    }
    static generate() {
        let secret;
        do
            secret = randomBytes(32);
        while (!p256.utils.isValidSecretKey(secret));
        return new ViewingKey(secret);
    }
    static fromBytes(bytes) {
        const secret = checkedBytes(bytes, 32, "viewing secret");
        if (!p256.utils.isValidSecretKey(secret)) {
            secret.fill(0);
            throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { type: "p256" });
        }
        return new ViewingKey(secret);
    }
    static fromSeed(walletSeed, account) {
        if (!Number.isInteger(account) || account < 0 || account > 0xffff_ffff) {
            throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
                name: "account",
                minimum: 0,
                maximum: 0xffff_ffff,
            });
        }
        const seed = checkedBytes(walletSeed, 32, "wallet seed");
        const info = concatBytes(encoder.encode("TSPP/seed/p256_viewing"), u32be(account));
        return ViewingKey.fromBytes(scalarFromOkm(expandOrThrow(seed, info, 48)));
    }
    publicKey() {
        this.#assertUsable();
        return P256PublicKey.fromSecret(this.#secret);
    }
    secretBytes() {
        this.#assertUsable();
        return copyBytes(this.#secret);
    }
    ecdh(counterparty) {
        this.#assertUsable();
        return copyBytes(ecdhX(this.#secret, counterparty));
    }
    mergeViewTag(mergeCount) {
        return this.#viewTag(INFO_MERGE_VIEW_TAG_SECRET, INFO_MERGE_VIEW_TAG_PREFIX, checkCounter(mergeCount, "mergeCount"));
    }
    recipientBootstrapViewTag() {
        return this.publicKey().x();
    }
    transactionViewingKey(firstNullifier) {
        this.#assertUsable();
        const nullifier = checkedBytes(firstNullifier, 32, "first nullifier");
        const txViewingSecret = this.#viewSecret(INFO_TX_VIEWING);
        try {
            const salted = expandOrThrow(txViewingSecret, encoder.encode(INFO_TX_VIEWING), 48, nullifier);
            return ViewingKey.fromBytes(scalarFromOkm(salted));
        }
        finally {
            txViewingSecret.fill(0);
        }
    }
    encryptSlot(recipientPublicKey, plaintext, salt, slotIndex) {
        this.#assertUsable();
        return applyTransferCipher(this.#secret, recipientPublicKey, this.publicKey(), recipientPublicKey, plaintext, checkedBytes(salt, 16, "salt"), checkSlotIndex(slotIndex));
    }
    decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex) {
        this.#assertUsable();
        return applyTransferCipher(this.#secret, txViewingPublicKey, txViewingPublicKey, this.publicKey(), ciphertext, checkedBytes(salt, 16, "salt"), checkSlotIndex(slotIndex));
    }
    decryptSlotEphemeral(recipientPublicKey, ciphertext, salt, slotIndex) {
        return this.encryptSlot(recipientPublicKey, ciphertext, salt, slotIndex);
    }
    encryptVerifiable(userViewingPublicKey, plaintext) {
        this.#assertUsable();
        return encryptVerifiableSecret(this.#secret, userViewingPublicKey, plaintext);
    }
    decryptVerifiable(txViewingPublicKey, ciphertext) {
        this.#assertUsable();
        return decryptVerifiableSecret(this.#secret, txViewingPublicKey, ciphertext);
    }
    destroy() {
        this.#secret.fill(0);
        this.#viewRoot.fill(0);
        this.#destroyed = true;
    }
    #viewSecret(info) {
        this.#assertUsable();
        try {
            return expand(sha256, this.#viewRoot, encoder.encode(info), 32);
        }
        catch (error) {
            throw new KeypairError("KEYPAIR_HKDF", { name: info }, error);
        }
    }
    #viewTag(secretInfo, prefix, counter) {
        const secret = this.#viewSecret(secretInfo);
        try {
            const tag = new Uint8Array(32);
            tag.set(expandOrThrow(secret, concatBytes(encoder.encode(prefix), counter), 31), 1);
            return tag;
        }
        finally {
            secret.fill(0);
        }
    }
    #assertUsable() {
        if (this.#destroyed) {
            throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
        }
    }
}
