import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { address, getAddressDecoder, getAddressEncoder } from "@solana/kit";
import { InterfaceError } from "./errors.js";
const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
export function fail(code, details, cause) {
    throw new InterfaceError(code, details, cause);
}
export function copyBytes(value, length, name = "bytes") {
    if (!(value instanceof Uint8Array)) {
        fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: "non-bytes" });
    }
    if (length !== undefined && value.length !== length) {
        fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: value.length });
    }
    return value.slice();
}
export function unsigned(value, maximum, name) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        fail("INTERFACE_INVALID_INTEGER", { name, minimum: 0, maximum, actual: value });
    }
    return value;
}
export function unsignedBigint(value, maximum, name) {
    if (typeof value !== "bigint" || value < 0n || value > maximum) {
        fail("INTERFACE_INVALID_INTEGER", {
            name,
            minimum: "0",
            maximum: maximum.toString(),
            actual: String(value),
        });
    }
    return value;
}
export function signedBigint(value, minimum, maximum, name) {
    if (typeof value !== "bigint" || value < minimum || value > maximum) {
        fail("INTERFACE_INVALID_INTEGER", {
            name,
            minimum: minimum.toString(),
            maximum: maximum.toString(),
            actual: String(value),
        });
    }
    return value;
}
export function addressBytes(value, name = "address") {
    try {
        return new Uint8Array(addressEncoder.encode(value));
    }
    catch (cause) {
        fail("INTERFACE_INVALID_ADDRESS", { name, actual: value }, cause);
    }
}
export function checkedAddress(value, name = "address") {
    try {
        return address(value);
    }
    catch (cause) {
        fail("INTERFACE_INVALID_ADDRESS", { name, actual: value }, cause);
    }
}
export function encodeBase58(bytes) {
    try {
        return addressDecoder.decode(bytes);
    }
    catch (cause) {
        fail("INTERFACE_INVALID_ADDRESS", { actual: "invalid address bytes" }, cause);
    }
}
export function sha256(input) {
    return nobleSha256(input);
}
export class Writer {
    #bytes = [];
    bytes(value, length, name) {
        this.#bytes.push(...copyBytes(value, length, name));
        return this;
    }
    u8(value, name) {
        this.#bytes.push(unsigned(value, 0xff, name));
        return this;
    }
    bool(value, name) {
        if (typeof value !== "boolean")
            fail("INTERFACE_CODEC", { name, actual: value });
        this.#bytes.push(value ? 1 : 0);
        return this;
    }
    u16(value, name) {
        const checked = unsigned(value, 0xffff, name);
        this.#bytes.push(checked & 255, checked >>> 8);
        return this;
    }
    u32(value, name) {
        const checked = unsigned(value, 0xffffffff, name);
        this.#bytes.push(checked & 255, (checked >>> 8) & 255, (checked >>> 16) & 255, checked >>> 24);
        return this;
    }
    u64(value, name) {
        return this.integer(unsignedBigint(value, (1n << 64n) - 1n, name), 8);
    }
    i64(value, name) {
        const checked = signedBigint(value, -(1n << 63n), (1n << 63n) - 1n, name);
        return this.integer(checked < 0n ? checked + (1n << 64n) : checked, 8);
    }
    option(value, write) {
        this.bool(value !== undefined, "option");
        if (value !== undefined)
            write(this, value);
        return this;
    }
    finish() {
        return Uint8Array.from(this.#bytes);
    }
    integer(value, length) {
        for (let index = 0; index < length; index += 1) {
            this.#bytes.push(Number((value >> BigInt(index * 8)) & 255n));
        }
        return this;
    }
}
export class Reader {
    input;
    #offset = 0;
    constructor(input) {
        this.input = input;
        copyBytes(input);
    }
    bytes(length, name) {
        const end = this.#offset + length;
        if (!Number.isSafeInteger(length) || length < 0 || end > this.input.length) {
            fail("INTERFACE_CODEC", {
                name,
                offset: this.#offset,
                expected: length,
                remaining: this.input.length - this.#offset,
            });
        }
        const value = this.input.slice(this.#offset, end);
        this.#offset = end;
        return value;
    }
    u8(name) {
        return arrayValue(this.bytes(1, name), 0);
    }
    bool(name) {
        const value = this.u8(name);
        if (value !== 0 && value !== 1)
            fail("INTERFACE_CODEC", { name, actual: value });
        return value === 1;
    }
    nonzeroBool(name) {
        return this.u8(name) !== 0;
    }
    u16(name) {
        const value = this.bytes(2, name);
        return arrayValue(value, 0) | (arrayValue(value, 1) << 8);
    }
    u32(name) {
        const value = this.bytes(4, name);
        return (arrayValue(value, 0) +
            arrayValue(value, 1) * 0x100 +
            arrayValue(value, 2) * 0x10000 +
            arrayValue(value, 3) * 0x1000000);
    }
    u64(name) {
        return this.integer(8, name);
    }
    i64(name) {
        const value = this.integer(8, name);
        return value >= 1n << 63n ? value - (1n << 64n) : value;
    }
    option(name, read) {
        return this.bool(name) ? read(this) : undefined;
    }
    done() {
        if (this.#offset !== this.input.length) {
            fail("INTERFACE_CODEC", {
                reason: "trailing bytes",
                offset: this.#offset,
                length: this.input.length,
            });
        }
    }
    integer(length, name) {
        const value = this.bytes(length, name);
        let result = 0n;
        for (let index = value.length - 1; index >= 0; index -= 1) {
            result = (result << 8n) | BigInt(arrayValue(value, index));
        }
        return result;
    }
}
function arrayValue(values, index) {
    const value = values[index];
    if (value === undefined) {
        fail("INTERFACE_CODEC", { reason: "internal index out of bounds", index });
    }
    return value;
}
