import type { Address, Bytes16, Bytes31, Bytes32, Bytes33, Bytes64, Bytes128, RequestContext, Signature } from "../interface/types.js";
import { ClientError } from "./error.js";
export declare const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export declare function checkedServiceUrl(value: string | URL, field: string): URL;
export declare function checkedBytes<Length extends 16 | 31 | 32 | 33 | 64 | 128>(value: unknown, length: Length, field: string): Length extends 16 ? Bytes16 : Length extends 31 ? Bytes31 : Length extends 32 ? Bytes32 : Length extends 33 ? Bytes33 : Length extends 64 ? Bytes64 : Bytes128;
export declare function bytesToBigInt(bytes: Uint8Array): bigint;
export declare function bigintToBytes(value: bigint, length?: number): Uint8Array;
export declare function field(value: bigint, name: string): bigint;
export declare function bytesField(bytes: Uint8Array, name: string): bigint;
export declare function poseidon(inputs: readonly bigint[]): bigint;
export declare function hashChain(values: readonly bigint[]): bigint;
export declare function rightHashChain(values: readonly bigint[]): bigint;
export declare function hashField(bytes: Uint8Array): bigint;
export declare function sha256Bytes(bytes: Uint8Array): Bytes32;
export declare function addressBytes(value: Address): Bytes32;
export declare function signatureBytes(value: Signature): Bytes64;
export declare function decodeBase64(value: unknown, fieldName: string): Uint8Array;
export declare function p256Coordinates(bytes: Bytes33): readonly [bigint, bigint];
export declare function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint;
export interface ComposedSignal {
    readonly signal: AbortSignal;
    timedOut(): boolean;
    cleanup(): void;
}
export declare function composeSignal(context: RequestContext | undefined, method: string): ComposedSignal;
export declare function requestError(method: string, signal: ComposedSignal): ClientError;
export declare function sleep(delayMs: bigint, context?: RequestContext): Promise<void>;
