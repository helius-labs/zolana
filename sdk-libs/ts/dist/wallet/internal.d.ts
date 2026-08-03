import type { Bytes32 } from "../interface/types.js";
export declare function copy32(value: Uint8Array, field: string): Bytes32;
export declare function equalBytes(left: Uint8Array, right: Uint8Array): boolean;
export declare function bytesKey(value: Uint8Array): string;
export declare function concat(...parts: readonly Uint8Array[]): Uint8Array;
export declare function base64Bytes(value: string): Uint8Array;
