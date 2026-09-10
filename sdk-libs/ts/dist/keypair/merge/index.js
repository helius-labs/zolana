import { ciphertextHash } from "../../interface/merge-utils.js";
import { checkedBytes, copyBytes } from "../bytes.js";
import { wrapKeypairError } from "../error.js";
import { poseidon } from "../poseidon.js";
import { P256PublicKey } from "../public-key.js";
import { MERGE_INFO as MERGE_INFO_BYTES, decryptVerifiableSecret, encryptVerifiableSecret, packMergePublicKey, } from "./core.js";
export { MAX_INFO_LENGTH, symmetricApply } from "./core.js";
export const MERGE_INFO = copyBytes(MERGE_INFO_BYTES);
const DOMAIN_MERGE_OUTPUT_BLINDING = 0x544d_4f42;
const DOMAIN_MERGE_DUMMY_NULLIFIER = 0x544d_444e;
export function encryptVerifiable(txViewingSecret, userViewingPublicKey, plaintext) {
    return encryptVerifiableSecret(checkedBytes(txViewingSecret, 32, "transaction viewing secret"), userViewingPublicKey, plaintext);
}
export function decryptVerifiable(userViewingSecret, txViewingPublicKey, ciphertext) {
    return decryptVerifiableSecret(checkedBytes(userViewingSecret, 32, "user viewing secret"), txViewingPublicKey, ciphertext);
}
export function mergePublicContribution(txViewingPublicKey, ciphertext) {
    const [txViewingPublicKeyLow, txViewingPublicKeyHigh] = packMergePublicKey(txViewingPublicKey);
    return {
        txViewingPublicKeyLow,
        txViewingPublicKeyHigh,
        ciphertextHash: mergeCiphertextHash(ciphertext),
    };
}
export function mergeCiphertextHash(ciphertext) {
    try {
        return ciphertextHash(ciphertext);
    }
    catch (error) {
        throw wrapKeypairError("KEYPAIR_POSEIDON", error);
    }
}
export function mergeOutputBlinding(nullifierKey, firstNullifier) {
    return poseidon([
        fieldU32(DOMAIN_MERGE_OUTPUT_BLINDING),
        rightAlign(nullifierKey.secretBytes()),
        checkedBytes(firstNullifier, 32, "first nullifier"),
    ]);
}
export function mergeDummyNullifier(nullifierKey, firstNullifier, slotIndex) {
    if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff) {
        throw new RangeError("merge dummy slot index must fit in u8");
    }
    return poseidon([
        fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
        rightAlign(nullifierKey.secretBytes()),
        checkedBytes(firstNullifier, 32, "first nullifier"),
        fieldU32(slotIndex),
    ]);
}
function fieldU32(value) {
    const field = new Uint8Array(32);
    new DataView(field.buffer).setUint32(28, value, false);
    return field;
}
function rightAlign(bytes) {
    const field = new Uint8Array(32);
    field.set(bytes, 32 - bytes.length);
    return field;
}
