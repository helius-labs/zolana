import { type Bytes31, type Bytes32 } from "./bytes.js";
import { SigningKey } from "./signing-key.js";
export declare class NullifierKey {
    #private;
    private constructor();
    static fromSigningKey(key: SigningKey): NullifierKey;
    /**
     * Rust takes `&[u8]`, so the input keying material has no fixed width: an
     * ed25519 seed, a P256 secret, or any other wallet-side secret is legal.
     */
    static fromSigningSecret(bytes: Uint8Array): NullifierKey;
    static fromSecret(bytes: Bytes31): NullifierKey;
    publicKey(): Bytes32;
    nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32;
    secretBytes(): Bytes31;
    destroy(): void;
}
