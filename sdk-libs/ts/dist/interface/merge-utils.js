import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/index.js";
import { InterfaceError } from "./errors.js";
import { copyBytes } from "./internal.js";
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes)
        value = (value << 8n) | BigInt(byte);
    return value;
}
// The bounds are checked here rather than left to the module so a rejection
// still arrives as the `INTERFACE_HASH` its callers catch, with the detail that
// says which input was wrong.
function poseidon(inputs) {
    if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
        throw new InterfaceError("INTERFACE_HASH", {
            inputCount: inputs.length,
            minimum: 1,
            maximum: MAX_POSEIDON_INPUTS,
        });
    }
    inputs.forEach((input, index) => {
        if (input.length > 32 || bytesToBigInt(input) >= BN254_MODULUS) {
            throw new InterfaceError("INTERFACE_HASH", { index, length: input.length });
        }
    });
    return hash(inputs);
}
function rightAlign(bytes) {
    const result = new Uint8Array(32);
    result.set(bytes, 32 - bytes.length);
    return result;
}
function checkedCompressedKey(compressed) {
    const key = copyBytes(compressed, 33, "compressedPublicKey");
    if (key[0] !== 0x02 && key[0] !== 0x03) {
        throw new InterfaceError("INTERFACE_CODEC", {
            name: "compressedPublicKeyPrefix",
            actual: key[0],
        });
    }
    return key;
}
function xHash(compressed) {
    const x = compressed.subarray(1);
    return poseidon([rightAlign(x.subarray(16)), rightAlign(x.subarray(0, 16))]);
}
export function pkFieldCompressed(compressed) {
    const key = checkedCompressedKey(compressed);
    return poseidon([rightAlign(Uint8Array.of(key[0] === 0x03 ? 1 : 0)), xHash(key)]);
}
export function ownerPkFieldCompressed(compressed) {
    return xHash(checkedCompressedKey(compressed));
}
export function pack33(bytes) {
    const input = copyBytes(bytes, 33, "bytes");
    const low = new Uint8Array(32);
    low.set(input.subarray(0, 31), 1);
    const high = new Uint8Array(32);
    high.set(input.subarray(31), 30);
    return Object.freeze([low, high]);
}
export function ciphertextHash(ciphertext) {
    const bytes = copyBytes(ciphertext);
    const chunks = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
        chunks.push(rightAlign(bytes.subarray(offset, offset + 16)));
    }
    return poseidon(chunks);
}
