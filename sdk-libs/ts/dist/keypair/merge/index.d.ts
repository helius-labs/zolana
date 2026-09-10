import { type Bytes32 } from "../bytes.js";
import type { NullifierKey } from "../nullifier-key.js";
import { P256PublicKey } from "../public-key.js";
export { MAX_INFO_LENGTH, symmetricApply } from "./core.js";
export declare const MERGE_INFO: Uint8Array<ArrayBufferLike>;
export interface MergeCiphertextPublicInputs {
    readonly txViewingPublicKeyLow: Bytes32;
    readonly txViewingPublicKeyHigh: Bytes32;
    readonly ciphertextHash: Bytes32;
}
export declare function encryptVerifiable(txViewingSecret: Bytes32, userViewingPublicKey: P256PublicKey, plaintext: Uint8Array): Readonly<{
    ciphertext: Uint8Array;
    txViewingPublicKey: P256PublicKey;
}>;
export declare function decryptVerifiable(userViewingSecret: Bytes32, txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
export declare function mergePublicContribution(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): MergeCiphertextPublicInputs;
export declare function mergeCiphertextHash(ciphertext: Uint8Array): Bytes32;
export declare function mergeOutputBlinding(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32;
export declare function mergeDummyNullifier(nullifierKey: NullifierKey, firstNullifier: Bytes32, slotIndex: number): Bytes32;
