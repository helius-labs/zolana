/** A rejection from the Poseidon runtime, carrying the matching Rust hasher code. */
export declare class HasherWasmError extends Error {
    readonly code: number;
    constructor(code: number, message: string);
}
/** The widest digest supported by both the runtime and the Solana verifier. */
export declare const MAX_POSEIDON_INPUTS = 12;
/** Loads the dependency-backed hasher once while keeping hashing synchronous. */
export declare function initializePoseidon(): Promise<void>;
/** Whether `poseidon` can be called. */
export declare function isPoseidonInitialized(): boolean;
/** Hashes one to twelve unsigned big-endian field elements. */
export declare function poseidon(inputs: readonly Uint8Array[]): Uint8Array;
/** Packs fixed-size bytes into 31-byte fields and folds them like Rust `hash_bytes`. */
export declare function hashBytes(bytes: Uint8Array): Uint8Array;
