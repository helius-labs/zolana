import { ctr } from "@noble/ciphers/aes.js";
import { bigIntToBytes, checkedBytes, concatBytes, copyBytes, } from "../bytes.js";
import { ecdhX } from "../encryption.js";
import { KeypairError } from "../error.js";
import { pack33 } from "../hash.js";
import { poseidon } from "../poseidon.js";
import { P256PublicKey } from "../public-key.js";
export const MERGE_INFO = new TextEncoder().encode("TSPP/merge");
/**
 * `packInfo` writes the label into two field limbs of 31 and 32 bytes, so a
 * longer label has nowhere to go. Rust raises `InfoTooLong` at the same bound
 * instead of indexing past the second limb.
 */
export const MAX_INFO_LENGTH = 62;
const DOM_SEP_SHARED_SECRET = 0x544d5353n;
const DOM_SEP_SILO = 0x544d5349n;
const DOM_SEP_KEY = 0x544d534bn;
const DOM_SEP_NONCE = 0x544d534en;
function pack32(bytes) {
    const low = new Uint8Array(32);
    low.set(bytes.subarray(0, 31), 1);
    const high = new Uint8Array(32);
    high[31] = bytes.at(31) ?? 0;
    return [low, high];
}
function packInfo(info) {
    if (info.length > MAX_INFO_LENGTH) {
        throw new KeypairError("KEYPAIR_INFO_TOO_LONG", {
            maximum: MAX_INFO_LENGTH,
            actual: info.length,
        });
    }
    const split = Math.min(info.length, 31);
    const low = new Uint8Array(32);
    low[0] = info.length;
    low.set(info.subarray(0, split), 32 - split);
    const high = new Uint8Array(32);
    high.set(info.subarray(split), 32 - (info.length - split));
    return [low, high];
}
function deriveSharedSecret(dh, ephemeralPublicKey, recipientPublicKey) {
    const [dhLow, dhHigh] = pack32(dh);
    const [ephemeralLow, ephemeralHigh] = pack33(ephemeralPublicKey.toBytes());
    const [recipientLow, recipientHigh] = pack33(recipientPublicKey.toBytes());
    return poseidon([
        bigIntToBytes(DOM_SEP_SHARED_SECRET),
        dhLow,
        dhHigh,
        ephemeralLow,
        ephemeralHigh,
        recipientLow,
        recipientHigh,
    ]);
}
function keySchedule(sharedSecret, info) {
    const [infoLow, infoHigh] = packInfo(info);
    const siloed = poseidon([bigIntToBytes(DOM_SEP_SILO), sharedSecret, infoLow, infoHigh]);
    const keyLow = poseidon([bigIntToBytes(DOM_SEP_KEY), siloed]);
    const keyHigh = poseidon([bigIntToBytes(DOM_SEP_KEY + 1n), siloed]);
    const key = concatBytes(keyHigh.subarray(16), keyLow.subarray(16));
    const nonce = poseidon([bigIntToBytes(DOM_SEP_NONCE), siloed]).subarray(20);
    siloed.fill(0);
    return [key, nonce];
}
function applyMergeCipher(secret, counterparty, ephemeralPublicKey, recipientPublicKey, input) {
    const dh = ecdhX(secret, counterparty);
    let sharedSecret;
    try {
        sharedSecret = deriveSharedSecret(dh, ephemeralPublicKey, recipientPublicKey);
        return applyKeySchedule(sharedSecret, MERGE_INFO, input);
    }
    finally {
        dh.fill(0);
        sharedSecret?.fill(0);
    }
}
function applyKeySchedule(sharedSecret, info, input) {
    let key;
    try {
        let nonce;
        [key, nonce] = keySchedule(sharedSecret, info);
        const counter = new Uint8Array(16);
        counter.set(nonce);
        counter[15] = 2;
        return ctr(key, counter).encrypt(copyBytes(input));
    }
    finally {
        key?.fill(0);
    }
}
/**
 * Mirrors `zolana_keypair::merge::symmetric_apply`: the merge key schedule over
 * a pre-shared secret with no ECDH. Encryption and decryption are the same
 * operation, so applying it twice returns the input.
 */
export function symmetricApply(sharedSecret, info, data) {
    return applyKeySchedule(checkedBytes(sharedSecret, 32, "shared secret"), info, data);
}
export function encryptVerifiableSecret(txViewingSecret, userViewingPublicKey, plaintext) {
    const secret = checkedBytes(txViewingSecret, 32, "transaction viewing secret");
    const txViewingPublicKey = P256PublicKey.fromSecret(secret);
    return {
        ciphertext: applyMergeCipher(secret, userViewingPublicKey, txViewingPublicKey, userViewingPublicKey, plaintext),
        txViewingPublicKey,
    };
}
export function decryptVerifiableSecret(userViewingSecret, txViewingPublicKey, ciphertext) {
    const secret = checkedBytes(userViewingSecret, 32, "user viewing secret");
    return applyMergeCipher(secret, txViewingPublicKey, txViewingPublicKey, P256PublicKey.fromSecret(secret), ciphertext);
}
export function packMergePublicKey(publicKey) {
    const bytes = checkedBytes(publicKey.toBytes(), 33, "transaction viewing public key");
    const [low, high] = pack33(bytes);
    return [low, high];
}
