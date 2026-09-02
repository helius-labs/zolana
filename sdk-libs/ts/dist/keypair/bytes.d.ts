type FixedBytes<Length extends number> = Uint8Array & {
    readonly __fixedBytesLength: Length;
};
export type Bytes16 = FixedBytes<16>;
export type Bytes31 = FixedBytes<31>;
export type Bytes32 = FixedBytes<32>;
export type Bytes33 = FixedBytes<33>;
export type Bytes34 = FixedBytes<34>;
export type Bytes64 = FixedBytes<64>;
export declare function copyBytes(bytes: Uint8Array): Uint8Array;
export declare function checkedBytes<T extends Uint8Array>(bytes: Uint8Array | T, length: number, name: string): T;
export declare function bytesToBigInt(bytes: Uint8Array): bigint;
/**
 * The Rust counterpart is `bigint_to_be_bytes_array`, which takes a `BigUint`
 * and returns `HasherError::InvalidInputLength` when the value needs more bytes
 * than the array holds. A negative value cannot be handed to it at all. Both
 * cases were silently absorbed here: truncation dropped the high bytes and a
 * negative value wrapped to its two's complement, either of which feeds Poseidon
 * a field element the caller never asked for.
 */
export declare function bigIntToBytes(value: bigint, length?: number): Uint8Array;
export declare function concatBytes(...parts: readonly Uint8Array[]): Uint8Array;
export declare function u32be(value: number): Uint8Array;
export declare function u64be(value: bigint): Uint8Array;
export declare function randomBytes(length: number): Uint8Array;
export declare function randomBlinding(): Bytes32;
export declare function randomSalt(): Bytes16;
export {};
