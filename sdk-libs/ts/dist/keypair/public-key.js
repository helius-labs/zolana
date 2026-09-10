import { p256 } from "@noble/curves/nist.js";
import { checkedBytes, copyBytes } from "./bytes.js";
import { P256_PUBLIC_KEY_LENGTH, SHIELDED_PUBLIC_KEY_LENGTH } from "./constants.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { hashField } from "./hash.js";
export class P256PublicKey {
    #bytes;
    constructor(bytes) {
        this.#bytes = bytes;
    }
    static fromBytes(bytes) {
        const owned = checkedBytes(bytes, P256_PUBLIC_KEY_LENGTH, "P256 public key");
        try {
            p256.Point.fromBytes(owned);
        }
        catch (error) {
            throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
        }
        return new P256PublicKey(owned);
    }
    static fromSecret(secret) {
        return P256PublicKey.fromBytes(p256.getPublicKey(secret, true));
    }
    toBytes() {
        return copyBytes(this.#bytes);
    }
    x() {
        return copyBytes(this.#bytes.subarray(1));
    }
    yIsOdd() {
        return this.#bytes[0] === 3;
    }
    /** Mirrors the derived `PartialEq` on Rust's `P256Pubkey`: compressed bytes. */
    equals(other) {
        const left = this.#bytes;
        const right = other.#bytes;
        return left.length === right.length && left.every((byte, index) => byte === right[index]);
    }
}
export class ShieldedPublicKey {
    #bytes;
    constructor(bytes) {
        this.#bytes = bytes;
    }
    static zeroed() {
        return new ShieldedPublicKey(new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH));
    }
    static fromP256(key) {
        const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
        bytes.set(key.toBytes(), 1);
        return new ShieldedPublicKey(bytes);
    }
    static fromEd25519(publicKey) {
        const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
        bytes[0] = 1;
        bytes.set(checkedBytes(publicKey, 32, "Ed25519 public key"), 1);
        return new ShieldedPublicKey(bytes);
    }
    static fromBytes(bytes) {
        const owned = checkedBytes(bytes, SHIELDED_PUBLIC_KEY_LENGTH, "shielded public key");
        if (owned[0] === 0) {
            P256PublicKey.fromBytes(owned.subarray(1));
        }
        else if (owned[0] === 1) {
            if (owned[SHIELDED_PUBLIC_KEY_LENGTH - 1] !== 0) {
                throw new KeypairError("KEYPAIR_INVALID_PUBLIC_KEY", { reason: "nonzeroPadding" });
            }
        }
        else {
            throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: owned[0] ?? 0 });
        }
        return new ShieldedPublicKey(owned);
    }
    toBytes() {
        return copyBytes(this.#bytes);
    }
    /** Mirrors the derived `PartialEq` on Rust's `PublicKey`: all 34 tagged bytes. */
    equals(other) {
        const left = this.#bytes;
        const right = other.#bytes;
        return left.length === right.length && left.every((byte, index) => byte === right[index]);
    }
    isZero() {
        return this.#bytes.every((byte) => byte === 0);
    }
    signatureType() {
        if (this.#bytes[0] === 0)
            return "p256";
        if (this.#bytes[0] === 1)
            return "ed25519";
        throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: this.#bytes[0] ?? 0 });
    }
    confidentialViewTag() {
        if (this.signatureType() === "p256")
            return this.p256().x();
        return copyBytes(this.#bytes.subarray(1, 33));
    }
    hash() {
        return hashField(this.confidentialViewTag());
    }
    ownerPublicKeyField() {
        return hashField(this.confidentialViewTag());
    }
    ed25519() {
        if (this.signatureType() !== "ed25519") {
            throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "ed25519" });
        }
        return copyBytes(this.#bytes.subarray(1, 33));
    }
    p256() {
        if (this.signatureType() !== "p256") {
            throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "p256" });
        }
        return P256PublicKey.fromBytes(this.#bytes.subarray(1));
    }
}
