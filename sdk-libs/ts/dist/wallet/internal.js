import { getBase64Encoder } from "@solana/kit";
import { WalletError } from "./error.js";
const base64Encoder = getBase64Encoder();
export function copy32(value, field) {
    if (!(value instanceof Uint8Array) || value.length !== 32) {
        throw new WalletError("WALLET_INVALID_LENGTH", {
            details: {
                field,
                expected: 32,
                actual: value instanceof Uint8Array ? value.length : -1,
            },
        });
    }
    return new Uint8Array(value);
}
export function equalBytes(left, right) {
    if (left.length !== right.length)
        return false;
    let difference = 0;
    for (let index = 0; index < left.length; index++) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}
export function bytesKey(value) {
    return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
export function concat(...parts) {
    const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
}
export function base64Bytes(value) {
    if (typeof value !== "string")
        throw new WalletError("WALLET_INVALID_BASE64");
    const clean = value.endsWith("==")
        ? value.slice(0, -2)
        : value.endsWith("=")
            ? value.slice(0, -1)
            : value;
    if (clean.length % 4 === 1 || !/^[A-Za-z0-9+/]*$/u.test(clean)) {
        throw new WalletError("WALLET_INVALID_BASE64");
    }
    try {
        return new Uint8Array(base64Encoder.encode(clean));
    }
    catch {
        throw new WalletError("WALLET_INVALID_BASE64");
    }
}
