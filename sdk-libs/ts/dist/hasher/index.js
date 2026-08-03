import { WasmFactory } from "@lightprotocol/hasher.rs";
/** A rejection from the Poseidon runtime, carrying the matching Rust hasher code. */
export class HasherWasmError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = "HasherWasmError";
        this.code = code;
    }
}
const FIELD_BYTES = 32;
/** The widest digest supported by both the runtime and the Solana verifier. */
export const MAX_POSEIDON_INPUTS = 12;
const ERROR_ARITY = 1;
const ERROR_UNINITIALIZED = 2;
const ERROR_POSEIDON = 7002;
const ERROR_INVALID_INPUT_LENGTH = 7005;
let loaded;
let loading;
/** Loads the dependency-backed hasher once while keeping hashing synchronous. */
export async function initializePoseidon() {
    if (loaded !== undefined)
        return;
    loading ??= WasmFactory.loadHasher();
    try {
        loaded = await loading;
    }
    catch (error) {
        loading = undefined;
        throw error;
    }
}
/** Whether `poseidon` can be called. */
export function isPoseidonInitialized() {
    return loaded !== undefined;
}
/** @internal Drops the loaded module so tests can exercise initialization. */
export function resetPoseidonForTests() {
    loaded = undefined;
    loading = undefined;
    WasmFactory.resetModule();
}
/** Hashes one to twelve unsigned big-endian field elements. */
export function poseidon(inputs) {
    const active = loaded;
    if (active === undefined) {
        throw new HasherWasmError(ERROR_UNINITIALIZED, "the Poseidon hasher is not loaded; await initializePoseidon() once before hashing");
    }
    if (inputs.length === 0 || inputs.length > MAX_POSEIDON_INPUTS) {
        throw new HasherWasmError(ERROR_ARITY, `Poseidon takes 1 to ${String(MAX_POSEIDON_INPUTS)} inputs, received ${String(inputs.length)}`);
    }
    const decimalInputs = inputs.map((input, index) => {
        if (input.length > FIELD_BYTES) {
            throw new HasherWasmError(ERROR_INVALID_INPUT_LENGTH, `Poseidon input ${String(index)} is ${String(input.length)} bytes, the field takes 32`);
        }
        let value = 0n;
        for (const byte of input)
            value = (value << 8n) | BigInt(byte);
        return value.toString();
    });
    try {
        return new Uint8Array(active.poseidonHash(decimalInputs));
    }
    catch (cause) {
        const reason = cause instanceof Error ? cause.message : String(cause);
        throw new HasherWasmError(ERROR_POSEIDON, `Poseidon rejected the input: ${reason}`);
    }
}
/** Packs fixed-size bytes into 31-byte fields and folds them like Rust `hash_bytes`. */
export function hashBytes(bytes) {
    if (bytes.length === 0)
        return new Uint8Array(FIELD_BYTES);
    let offset = 0;
    let result = packed(bytes.subarray(0, 31));
    offset = 31;
    while (offset < bytes.length) {
        result = poseidon([result, packed(bytes.subarray(offset, offset + 31))]);
        offset += 31;
    }
    return result;
}
function packed(bytes) {
    const field = new Uint8Array(FIELD_BYTES);
    field.set(bytes, FIELD_BYTES - bytes.length);
    return field;
}
