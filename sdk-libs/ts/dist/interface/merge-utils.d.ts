import type { Bytes32 } from "./types.js";
export declare function pkFieldCompressed(compressed: Uint8Array): Bytes32;
export declare function ownerPkFieldCompressed(compressed: Uint8Array): Bytes32;
export declare function pack33(bytes: Uint8Array): readonly [Bytes32, Bytes32];
export declare function ciphertextHash(ciphertext: Uint8Array): Bytes32;
