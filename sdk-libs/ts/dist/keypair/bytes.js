import { invalidLength } from "./error.js";
export function copyBytes(bytes) {
    return new Uint8Array(bytes);
}
export function checkedBytes(bytes, length, name) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
        throw invalidLength(name, length, bytes instanceof Uint8Array ? bytes.length : -1);
    }
    return new Uint8Array(bytes);
}
export function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes)
        value = (value << 8n) | BigInt(byte);
    return value;
}
/**
 * The Rust counterpart is `bigint_to_be_bytes_array`, which takes a `BigUint`
 * and returns `HasherError::InvalidInputLength` when the value needs more bytes
 * than the array holds. A negative value cannot be handed to it at all. Both
 * cases were silently absorbed here: truncation dropped the high bytes and a
 * negative value wrapped to its two's complement, either of which feeds Poseidon
 * a field element the caller never asked for.
 */
export function bigIntToBytes(value, length = 32) {
    if (value < 0n || value >= 1n << BigInt(length * 8)) {
        throw invalidLength("bigIntToBytes", length, bigIntByteWidth(value));
    }
    const bytes = new Uint8Array(length);
    let remaining = value;
    for (let index = length - 1; index >= 0; index--) {
        bytes[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return bytes;
}
/// Width in bytes of an unsigned value. A negative one has none, so it reports
/// the `-1` that `checkedBytes` uses for an input with no readable length.
function bigIntByteWidth(value) {
    if (value < 0n)
        return -1;
    let width = 0;
    for (let remaining = value; remaining > 0n; remaining >>= 8n)
        width += 1;
    return width;
}
export function concatBytes(...parts) {
    const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
}
export function u32be(value) {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    return bytes;
}
export function u64be(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}
export function randomBytes(length) {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
}
export function randomBlinding() {
    const blinding = new Uint8Array(32);
    blinding.set(randomBytes(31), 1);
    return blinding;
}
export function randomSalt() {
    return randomBytes(16);
}
