import { type Address } from "@solana/kit";
import { InterfaceError } from "./errors.js";
export declare function fail(code: InterfaceError["code"], details?: Readonly<Record<string, unknown>>, cause?: unknown): never;
export declare function copyBytes(value: Uint8Array, length?: number, name?: string): Uint8Array;
export declare function unsigned(value: number, maximum: number, name: string): number;
export declare function unsignedBigint(value: bigint, maximum: bigint, name: string): bigint;
export declare function signedBigint(value: bigint, minimum: bigint, maximum: bigint, name: string): bigint;
export declare function addressBytes(value: Address, name?: string): Uint8Array;
export declare function checkedAddress(value: string, name?: string): Address;
export declare function encodeBase58(bytes: Uint8Array): Address;
export declare function sha256(input: Uint8Array): Uint8Array;
export declare class Writer {
    #private;
    bytes(value: Uint8Array, length?: number, name?: string): this;
    u8(value: number, name: string): this;
    bool(value: boolean, name: string): this;
    u16(value: number, name: string): this;
    u32(value: number, name: string): this;
    u64(value: bigint, name: string): this;
    i64(value: bigint, name: string): this;
    option<T>(value: T | undefined, write: (writer: Writer, value: T) => void): this;
    finish(): Uint8Array;
    private integer;
}
export declare class Reader {
    #private;
    private readonly input;
    constructor(input: Uint8Array);
    bytes(length: number, name: string): Uint8Array;
    u8(name: string): number;
    bool(name: string): boolean;
    nonzeroBool(name: string): boolean;
    u16(name: string): number;
    u32(name: string): number;
    u64(name: string): bigint;
    i64(name: string): bigint;
    option<T>(name: string, read: (reader: Reader) => T): T | undefined;
    done(): void;
    private integer;
}
