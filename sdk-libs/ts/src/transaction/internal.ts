import { getAddressDecoder, getAddressEncoder, getBase58Encoder } from "@solana/kit";
import {
  type ChainField,
  foldHashChain,
  foldHashChain4,
  foldNonZeroHashChain,
  foldRightHashChain,
} from "../hasher/chain.js";
import { poseidonOr } from "../hasher/index.js";

import { isZero } from "../interface/bytes.js";
import { U64_MAX } from "../interface/internal.js";
import type { Address, Bytes16, Bytes32, Bytes33 } from "../interface/types.js";
export { hashBytes } from "../hasher/index.js";
export { sha256Be } from "../keypair/hash.js";

import { TransactionError, type TransactionErrorCode } from "./error.js";

const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Encoder = getBase58Encoder();

export const ZERO_32 = new Uint8Array(32) as Bytes32;
export { U64_MAX };

export function copy<T extends Uint8Array>(bytes: T): T {
  return new Uint8Array(bytes) as T;
}

export function checked<T extends Uint8Array>(
  bytes: Uint8Array | T,
  length: number,
  name: string,
): T {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      name,
      expected: length,
      actual: bytes instanceof Uint8Array ? bytes.length : -1,
    });
  }
  return new Uint8Array(bytes) as T;
}

export function checkU64(value: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      name,
      minimum: "0",
      maximum: U64_MAX.toString(),
      actual: String(value),
    });
  }
  return value;
}

export function rightAlign(bytes: Uint8Array): Bytes32 {
  if (bytes.length > 32) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMaximum: 32,
      actual: bytes.length,
    });
  }
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}

function hashFields(inputs: readonly Uint8Array[], code: TransactionErrorCode): Bytes32 {
  return poseidonOr(inputs, (failure) => {
    if (failure.code === "NotInitialized") return failure;
    const { inputCount, index } = failure.details;
    return new TransactionError(
      code,
      inputCount === undefined ? { index, reason: "invalidField" } : { inputCount },
    );
  }) as Bytes32;
}

export function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  return hashFields(inputs, "TRANSACTION_KEYPAIR");
}

export function commitmentPoseidon(inputs: readonly Uint8Array[]): Bytes32 {
  return hashFields(inputs, "TRANSACTION_POSEIDON");
}

const FIELD: ChainField<Bytes32> = {
  zero: () => copy(ZERO_32),
  isZero,
  hash: poseidon,
};

export function hashChain(values: readonly Bytes32[]): Bytes32 {
  return copy(foldHashChain(values, FIELD));
}

/** Rust `create_nonzero_hash_chain_from_slice`, see `foldNonZeroHashChain`. */
export function nonZeroHashChain(values: readonly Bytes32[]): Bytes32 {
  return copy(foldNonZeroHashChain(values, FIELD));
}

/** Three elements per Poseidon call, see `foldHashChain4`. */
export function hashChain4(values: readonly Bytes32[]): Bytes32 {
  return copy(foldHashChain4(values, FIELD));
}

export function rightHashChain(values: readonly Bytes32[]): Bytes32 {
  return copy(foldRightHashChain(values, FIELD));
}

export function random16(): Bytes16 {
  const output = new Uint8Array(16);
  globalThis.crypto.getRandomValues(output);
  return output as Bytes16;
}

export function decodeAddress(address: Address): Bytes32 {
  try {
    return new Uint8Array(addressEncoder.encode(address)) as Bytes32;
  } catch (cause) {
    try {
      return checked<Bytes32>(new Uint8Array(base58Encoder.encode(address)), 32, "address");
    } catch (fallbackCause) {
      if (fallbackCause instanceof TransactionError) throw fallbackCause;
      throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { address }, cause);
    }
  }
}

export function encodeAddress(bytes: Uint8Array): Address {
  const input = checked<Bytes32>(bytes, 32, "address");
  return addressDecoder.decode(input);
}

export function checked33(bytes: Uint8Array): Bytes33 {
  return checked<Bytes33>(bytes, 33, "public key");
}
