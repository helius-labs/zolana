import { type Bytes32, type Bytes33, type Bytes34 } from "./bytes.js";
export type SignatureType = "p256" | "ed25519";
export type ViewTag = Bytes32;
export declare class P256PublicKey {
    #private;
    private constructor();
    static fromBytes(bytes: Bytes33): P256PublicKey;
    static fromSecret(secret: Uint8Array): P256PublicKey;
    toBytes(): Bytes33;
    x(): Bytes32;
    yIsOdd(): boolean;
    /** Mirrors the derived `PartialEq` on Rust's `P256Pubkey`: compressed bytes. */
    equals(other: P256PublicKey): boolean;
}
export declare class ShieldedPublicKey {
    #private;
    private constructor();
    static zeroed(): ShieldedPublicKey;
    static fromP256(key: P256PublicKey): ShieldedPublicKey;
    static fromEd25519(publicKey: Bytes32): ShieldedPublicKey;
    static fromBytes(bytes: Bytes34): ShieldedPublicKey;
    toBytes(): Bytes34;
    /** Mirrors the derived `PartialEq` on Rust's `PublicKey`: all 34 tagged bytes. */
    equals(other: ShieldedPublicKey): boolean;
    isZero(): boolean;
    signatureType(): SignatureType;
    confidentialViewTag(): ViewTag;
    hash(): Bytes32;
    ownerPublicKeyField(): Bytes32;
    ed25519(): Bytes32;
    p256(): P256PublicKey;
}
