import type { CompressedProof, Proof } from "./types.js";
export declare function compressProof(proof: Proof): CompressedProof;
export declare function compressedProof(input: Readonly<{
    a: Uint8Array;
    b: Uint8Array;
    c: Uint8Array;
}>): CompressedProof;
export declare function parseProof(value: unknown): Proof;
