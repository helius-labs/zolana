import { type Bytes32, type Bytes64 } from "./bytes.js";
import { ShieldedPublicKey, type SignatureType } from "./public-key.js";
export type EcdsaSignature = Bytes64;
export declare class SigningKey {
    #private;
    private constructor();
    static generate(type?: SignatureType): SigningKey;
    static fromBytes(bytes: Bytes32): SigningKey;
    static fromEd25519Bytes(bytes: Bytes32): SigningKey;
    /** Mirrors `SigningKey::is_ed25519`: which rail this key signs on. */
    isEd25519(): boolean;
    signatureType(): SignatureType;
    publicKey(): ShieldedPublicKey;
    sign(message: Uint8Array): Bytes64;
    verify(message: Uint8Array, signature: Bytes64): boolean;
    secretBytes(): Bytes32;
    destroy(): void;
}
