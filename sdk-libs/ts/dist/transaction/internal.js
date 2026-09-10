import { sha256 } from "@noble/hashes/sha2.js";
import { getAddressDecoder, getAddressEncoder, getBase58Encoder } from "@solana/kit";
import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/index.js";
export { hashField, sha256Be } from "../keypair/hash.js";
import { TransactionError } from "./error.js";
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Encoder = getBase58Encoder();
export const ZERO_32 = new Uint8Array(32);
export const U64_MAX = 0xffffffffffffffffn;
export function copy(bytes) {
    return new Uint8Array(bytes);
}
export function equal(left, right) {
    if (left.length !== right.length)
        return false;
    let difference = 0;
    for (let index = 0; index < left.length; index++) {
        difference |= (left.at(index) ?? 0) ^ (right.at(index) ?? 0);
    }
    return difference === 0;
}
export function checked(bytes, length, name) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
        throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
            name,
            expected: length,
            actual: bytes instanceof Uint8Array ? bytes.length : -1,
        });
    }
    return new Uint8Array(bytes);
}
export function checkU64(value, name) {
    if (value < 0n || value > U64_MAX) {
        throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
            name,
            minimum: "0",
            maximum: U64_MAX.toString(),
            actual: value.toString(),
        });
    }
    return value;
}
export function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes)
        value = (value << 8n) | BigInt(byte);
    return value;
}
export function bigIntBytes(value, length = 32) {
    const output = new Uint8Array(length);
    let remaining = value;
    for (let index = length - 1; index >= 0; index--) {
        output[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return output;
}
export function rightAlign(bytes) {
    if (bytes.length > 32) {
        throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
            expectedMaximum: 32,
            actual: bytes.length,
        });
    }
    const output = new Uint8Array(32);
    output.set(bytes, 32 - bytes.length);
    return output;
}
function hashFields(inputs, code) {
    if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
        throw new TransactionError(code, { inputCount: inputs.length });
    }
    inputs.forEach((input, index) => {
        if (input.length > 32 || bytesToBigInt(input) >= BN254_MODULUS) {
            throw new TransactionError(code, { index, reason: "invalidField" });
        }
    });
    return hash(inputs);
}
export function poseidon(inputs) {
    return hashFields(inputs, "TRANSACTION_KEYPAIR");
}
export function commitmentPoseidon(inputs) {
    return hashFields(inputs, "TRANSACTION_POSEIDON");
}
export function hashChain(values) {
    const [first, ...remaining] = values;
    if (!first)
        return copy(ZERO_32);
    let hash = copy(first);
    for (const value of remaining)
        hash = poseidon([hash, value]);
    return hash;
}
export function rightHashChain(values) {
    const last = values.at(-1);
    if (!last)
        return copy(ZERO_32);
    let hash = copy(last);
    for (let index = values.length - 2; index >= 0; index -= 1) {
        hash = poseidon([values[index], hash]);
    }
    return hash;
}
export function sha256Bytes(bytes) {
    return sha256(bytes);
}
export function concat(...parts) {
    const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}
export function random16() {
    const output = new Uint8Array(16);
    globalThis.crypto.getRandomValues(output);
    return output;
}
export function decodeAddress(address) {
    try {
        return new Uint8Array(addressEncoder.encode(address));
    }
    catch (cause) {
        try {
            return checked(new Uint8Array(base58Encoder.encode(address)), 32, "address");
        }
        catch (fallbackCause) {
            if (fallbackCause instanceof TransactionError)
                throw fallbackCause;
            throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { address }, cause);
        }
    }
}
export function encodeAddress(bytes) {
    const input = checked(bytes, 32, "address");
    return addressDecoder.decode(input);
}
export function checked33(bytes) {
    return checked(bytes, 33, "public key");
}
