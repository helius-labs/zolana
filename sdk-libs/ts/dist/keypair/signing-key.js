import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { checkedBytes, concatBytes, copyBytes, randomBytes, } from "./bytes.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { P256PublicKey, ShieldedPublicKey } from "./public-key.js";
const ED25519_ORDER = ed25519.Point.Fn.ORDER;
function leBytesToBigInt(bytes) {
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index--) {
        value = (value << 8n) | BigInt(bytes[index]);
    }
    return value;
}
function bytesEqual(left, right) {
    if (left.length !== right.length)
        return false;
    return left.every((byte, index) => byte === right[index]);
}
// The Solana runtime accepts an Ed25519 signature exactly when `verify_strict`
// does, so this helper answers the same question the runtime would: the
// cofactorless equation compared over the compressed R bytes, with a
// small-order R or public key refused and an unreduced y decoded, not rejected.
function verifyEd25519Strict(signature, message, publicKey) {
    const r = signature.subarray(0, 32);
    const s = leBytesToBigInt(signature.subarray(32));
    if (s >= ED25519_ORDER)
        return false;
    const a = ed25519.Point.fromBytes(publicKey, true);
    if (a.isSmallOrder() || ed25519.Point.fromBytes(r, true).isSmallOrder())
        return false;
    const k = leBytesToBigInt(sha512(concatBytes(r, publicKey, message))) % ED25519_ORDER;
    const expected = ed25519.Point.BASE.multiplyUnsafe(s).subtract(a.multiplyUnsafe(k));
    return bytesEqual(expected.toBytes(), r);
}
export class SigningKey {
    #secret;
    #type;
    #destroyed = false;
    constructor(secret, type) {
        this.#secret = secret;
        this.#type = type;
    }
    static generate(type = "p256") {
        switch (type) {
            case "ed25519":
                return new SigningKey(randomBytes(32), type);
            case "p256": {
                let secret;
                do
                    secret = randomBytes(32);
                while (!p256.utils.isValidSecretKey(secret));
                return new SigningKey(secret, type);
            }
            default:
                throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { type });
        }
    }
    static fromBytes(bytes) {
        const secret = checkedBytes(bytes, 32, "P256 signing secret");
        if (!p256.utils.isValidSecretKey(secret)) {
            secret.fill(0);
            throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { type: "p256" });
        }
        return new SigningKey(secret, "p256");
    }
    static fromEd25519Bytes(bytes) {
        return new SigningKey(checkedBytes(bytes, 32, "Ed25519 signing secret"), "ed25519");
    }
    /** Mirrors `SigningKey::is_ed25519`: which rail this key signs on. */
    isEd25519() {
        return this.#type === "ed25519";
    }
    signatureType() {
        return this.#type;
    }
    publicKey() {
        this.#assertUsable();
        if (this.#type === "p256") {
            return ShieldedPublicKey.fromP256(P256PublicKey.fromSecret(this.#secret));
        }
        return ShieldedPublicKey.fromEd25519(ed25519.getPublicKey(this.#secret));
    }
    sign(message) {
        this.#assertUsable();
        try {
            if (this.#type === "p256") {
                if (message.length !== 32) {
                    throw new KeypairError("KEYPAIR_INVALID_PREHASH_LENGTH", {
                        expected: 32,
                        actual: message.length,
                    });
                }
                // The circuit range-checks s against the curve order only, so s above
                // n/2 is valid and must not be normalized into the lower half.
                return p256.sign(message, this.#secret, {
                    prehash: false,
                    format: "compact",
                    lowS: false,
                });
            }
            return ed25519.sign(message, this.#secret);
        }
        catch (error) {
            throw wrapKeypairError("KEYPAIR_INVALID_SECRET_KEY", error);
        }
    }
    verify(message, signature) {
        this.#assertUsable();
        if (!(signature instanceof Uint8Array) || signature.length !== 64)
            return false;
        try {
            if (this.#type === "p256") {
                if (message.length !== 32)
                    return false;
                // The circuit accepts s above n/2, so refusing it here would reject
                // signatures the protocol treats as valid.
                return p256.verify(signature, message, this.publicKey().p256().toBytes(), {
                    prehash: false,
                    format: "compact",
                    lowS: false,
                });
            }
            return verifyEd25519Strict(signature, message, this.publicKey().ed25519());
        }
        catch {
            return false;
        }
    }
    secretBytes() {
        this.#assertUsable();
        return copyBytes(this.#secret);
    }
    destroy() {
        this.#secret.fill(0);
        this.#destroyed = true;
    }
    #assertUsable() {
        if (this.#destroyed) {
            throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
        }
    }
}
