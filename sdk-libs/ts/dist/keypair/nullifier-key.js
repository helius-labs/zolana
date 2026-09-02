import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { checkedBytes, copyBytes } from "./bytes.js";
import { BLINDING_LENGTH, INFO_NULLIFIER } from "./constants.js";
import { KeypairError } from "./error.js";
import { poseidon } from "./poseidon.js";
import { SigningKey } from "./signing-key.js";
const encoder = new TextEncoder();
function rightAlign(bytes) {
    const output = new Uint8Array(32);
    output.set(bytes, 32 - bytes.length);
    return output;
}
export class NullifierKey {
    #secret;
    #destroyed = false;
    constructor(secret) {
        this.#secret = secret;
    }
    static fromSigningKey(key) {
        const secret = key.secretBytes();
        try {
            return NullifierKey.fromSigningSecret(secret);
        }
        finally {
            secret.fill(0);
        }
    }
    /**
     * Rust takes `&[u8]`, so the input keying material has no fixed width: an
     * ed25519 seed, a P256 secret, or any other wallet-side secret is legal.
     */
    static fromSigningSecret(bytes) {
        try {
            return new NullifierKey(hkdf(sha256, new Uint8Array(bytes), undefined, encoder.encode(INFO_NULLIFIER), 31));
        }
        catch (error) {
            throw new KeypairError("KEYPAIR_HKDF", { name: INFO_NULLIFIER }, error);
        }
    }
    static fromSecret(bytes) {
        return new NullifierKey(checkedBytes(bytes, BLINDING_LENGTH, "nullifier secret"));
    }
    publicKey() {
        this.#assertUsable();
        return poseidon([rightAlign(this.#secret)]);
    }
    nullifier(utxoHash, blinding) {
        this.#assertUsable();
        const hash = checkedBytes(utxoHash, 32, "UTXO hash");
        const blind = checkedBytes(blinding, 32, "blinding");
        return poseidon([hash, blind, rightAlign(this.#secret)]);
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
