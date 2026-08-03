import { sha256 } from "@noble/hashes/sha2.js";
import { assertIsSignature, getAddressEncoder, getBase58Encoder, getBase64Decoder, getBase64Encoder, } from "@solana/kit";
import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/index.js";
import { hashField as canonicalHashField } from "../keypair/hash.js";
import { ClientError, hasherError } from "./error.js";
export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const P256_MODULUS = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const addressEncoder = getAddressEncoder();
const base58Encoder = getBase58Encoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();
export function checkedServiceUrl(value, field) {
    let url;
    try {
        url = new URL(value instanceof URL ? value.href : value);
    }
    catch {
        throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
    }
    const hostname = url.hostname.endsWith(".") ? url.hostname.slice(0, -1) : url.hostname;
    const isLoopback = hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname === "[::1]" ||
        /^127(?:\.\d{1,3}){3}$/u.test(hostname);
    if ((url.protocol !== "https:" && (url.protocol !== "http:" || !isLoopback)) ||
        url.username !== "" ||
        url.password !== "" ||
        url.hash !== "") {
        throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
    }
    return url;
}
export function checkedBytes(value, length, field) {
    if (!(value instanceof Uint8Array) || value.length !== length) {
        throw new ClientError("CLIENT_INVALID_LENGTH", {
            details: {
                field,
                expected: length,
                actual: value instanceof Uint8Array ? value.length : -1,
            },
        });
    }
    return new Uint8Array(value);
}
export function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes)
        value = (value << 8n) | BigInt(byte);
    return value;
}
export function bigintToBytes(value, length = 32) {
    if (value < 0n || value >= 1n << BigInt(length * 8)) {
        throw new ClientError("CLIENT_INVALID_INTEGER", {
            details: { value: value.toString(), length },
        });
    }
    const result = new Uint8Array(length);
    let remaining = value;
    for (let index = length - 1; index >= 0; index--) {
        result[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return result;
}
export function field(value, name) {
    if (value < 0n || value >= BN254_MODULUS) {
        throw new ClientError("CLIENT_INVALID_FIELD", {
            details: { field: name, value: value.toString() },
        });
    }
    return value;
}
export function bytesField(bytes, name) {
    if (bytes.length > 32) {
        throw new ClientError("CLIENT_FIELD_TOO_LONG", {
            details: { field: name, actual: bytes.length, maximum: 32 },
        });
    }
    return field(bytesToBigInt(bytes), name);
}
export function poseidon(inputs) {
    if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
        throw hasherError("InvalidNumFields");
    }
    inputs.forEach((value, index) => field(value, `poseidon[${String(index)}]`));
    return bytesToBigInt(hash(inputs.map((value) => bigintToBytes(value))));
}
export function hashChain(values) {
    const first = values[0];
    if (first === undefined)
        return 0n;
    let result = first;
    for (let index = 1; index < values.length; index++) {
        const value = values[index];
        if (value === undefined)
            throw hasherError("EmptyInput");
        result = poseidon([result, value]);
    }
    return result;
}
export function rightHashChain(values) {
    const last = values.at(-1);
    if (last === undefined)
        return 0n;
    let result = last;
    for (let index = values.length - 2; index >= 0; index -= 1) {
        result = poseidon([values[index], result]);
    }
    return result;
}
export function hashField(bytes) {
    if (bytes.length !== 32) {
        throw new ClientError("CLIENT_INVALID_LENGTH", {
            details: { field: "hash field input", expected: 32, actual: bytes.length },
        });
    }
    return bytesToBigInt(canonicalHashField(bytes));
}
export function sha256Bytes(bytes) {
    return new Uint8Array(sha256(bytes));
}
export function addressBytes(value) {
    try {
        return new Uint8Array(addressEncoder.encode(value));
    }
    catch {
        throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: "address" } });
    }
}
export function signatureBytes(value) {
    try {
        assertIsSignature(value);
        return new Uint8Array(base58Encoder.encode(value));
    }
    catch {
        throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: "signature" } });
    }
}
export function decodeBase64(value, fieldName) {
    if (typeof value !== "string") {
        throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
    }
    try {
        const result = new Uint8Array(base64Encoder.encode(value));
        if (base64Decoder.decode(result) === value)
            return result;
    }
    catch {
        // Kit codec failures are mapped below.
    }
    throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
}
export function p256Coordinates(bytes) {
    const prefix = bytes[0];
    if (prefix !== 2 && prefix !== 3)
        throw new ClientError("CLIENT_INVALID_P256_KEY");
    const x = bytesToBigInt(bytes.subarray(1));
    if (x >= P256_MODULUS)
        throw new ClientError("CLIENT_INVALID_P256_KEY");
    const y2 = (x ** 3n - 3n * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn) %
        P256_MODULUS;
    let y = modPow(y2 < 0n ? y2 + P256_MODULUS : y2, (P256_MODULUS + 1n) / 4n, P256_MODULUS);
    if ((y & 1n) !== BigInt(prefix & 1))
        y = P256_MODULUS - y;
    if ((y * y) % P256_MODULUS !== (y2 + P256_MODULUS) % P256_MODULUS) {
        throw new ClientError("CLIENT_INVALID_P256_KEY");
    }
    return [x, y];
}
export function modPow(base, exponent, modulus) {
    let result = 1n;
    let value = base % modulus;
    let power = exponent;
    while (power > 0n) {
        if ((power & 1n) === 1n)
            result = (result * value) % modulus;
        value = (value * value) % modulus;
        power >>= 1n;
    }
    return result;
}
export function composeSignal(context, method) {
    const timeoutMs = context?.timeoutMs;
    if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)) {
        throw new ClientError("CLIENT_INVALID_CONTEXT", {
            details: { field: "timeoutMs", method },
        });
    }
    if (context?.signal?.aborted === true) {
        throw new ClientError("CLIENT_ABORTED", { details: { method } });
    }
    const controller = new AbortController();
    let timeout;
    let didTimeOut = false;
    const abort = () => {
        controller.abort();
    };
    context?.signal?.addEventListener("abort", abort, { once: true });
    if (timeoutMs !== undefined) {
        timeout = setTimeout(() => {
            didTimeOut = true;
            controller.abort();
        }, timeoutMs);
    }
    return {
        signal: controller.signal,
        timedOut: () => didTimeOut,
        cleanup() {
            if (timeout !== undefined)
                clearTimeout(timeout);
            context?.signal?.removeEventListener("abort", abort);
        },
    };
}
export function requestError(method, signal) {
    return new ClientError(signal.timedOut()
        ? "CLIENT_TIMEOUT"
        : signal.signal.aborted
            ? "CLIENT_ABORTED"
            : "CLIENT_REQUEST", {
        details: { method, retryable: signal.timedOut() || !signal.signal.aborted },
    });
}
export function sleep(delayMs, context) {
    if (delayMs < 0n || delayMs > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
            details: { field: "delayMs", value: delayMs.toString() },
        });
    }
    return new Promise((resolve, reject) => {
        if (context?.signal?.aborted === true) {
            reject(new ClientError("CLIENT_ABORTED"));
            return;
        }
        const finish = () => {
            context?.signal?.removeEventListener("abort", abort);
            resolve();
        };
        const timeout = setTimeout(finish, Number(delayMs));
        const abort = () => {
            clearTimeout(timeout);
            context?.signal?.removeEventListener("abort", abort);
            reject(new ClientError("CLIENT_ABORTED"));
        };
        context?.signal?.addEventListener("abort", abort, { once: true });
    });
}
