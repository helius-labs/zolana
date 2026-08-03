import { type Bytes32 } from "../bytes.js";
import { P256PublicKey } from "../public-key.js";
export declare const MERGE_INFO: Uint8Array<ArrayBuffer>;
/**
 * `packInfo` writes the label into two field limbs of 31 and 32 bytes, so a
 * longer label has nowhere to go. Rust raises `InfoTooLong` at the same bound
 * instead of indexing past the second limb.
 */
export declare const MAX_INFO_LENGTH = 62;
/**
 * Mirrors `zolana_keypair::merge::symmetric_apply`: the merge key schedule over
 * a pre-shared secret with no ECDH. Encryption and decryption are the same
 * operation, so applying it twice returns the input.
 */
export declare function symmetricApply(sharedSecret: Uint8Array, info: Uint8Array, data: Uint8Array): Uint8Array;
export declare function encryptVerifiableSecret(txViewingSecret: Uint8Array, userViewingPublicKey: P256PublicKey, plaintext: Uint8Array): Readonly<{
    ciphertext: Uint8Array;
    txViewingPublicKey: P256PublicKey;
}>;
export declare function decryptVerifiableSecret(userViewingSecret: Uint8Array, txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array;
export declare function packMergePublicKey(publicKey: P256PublicKey): readonly [Bytes32, Bytes32];
