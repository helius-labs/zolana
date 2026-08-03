import { type Bytes32 } from "./bytes.js";
export declare function splitBigEndian128(value: Uint8Array): readonly [Uint8Array, Uint8Array];
export declare function hashField(value: Uint8Array): Bytes32;
export declare function ownerHash(ownerPublicKeyField: Uint8Array, nullifierPublicKey: Uint8Array): Uint8Array;
/**
 * The one boundary a TypeScript-only code belongs at: Rust's `pack33` takes
 * `&[u8; 33]` and cannot fail, so a wrong-length input has no Rust variant to
 * mirror.
 */
export declare function pack33(bytes: Uint8Array): readonly [Uint8Array, Uint8Array];
export declare function sha256Bytes(bytes: Uint8Array): Bytes32;
export declare function sha256Be(bytes: Uint8Array): Bytes32;
