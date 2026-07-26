import { sha256 } from "@noble/hashes/sha2.js";
import { MAX_POSEIDON_INPUTS, poseidon as hash } from "@zolana/hasher";

import type {
  Address,
  Bytes16,
  Bytes31,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  RequestContext,
  Signature,
} from "@zolana/interface";
import { hashField as canonicalHashField } from "@zolana/keypair/hash";

import { ClientError, hasherError } from "./error.js";

export const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
const P256_MODULUS =
  0xffff_ffff_0000_0001_0000_0000_0000_0000_0000_0000_ffff_ffff_ffff_ffff_ffff_ffffn;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function checkedBytes<Length extends 16 | 31 | 32 | 33 | 64 | 128>(
  value: unknown,
  length: Length,
  field: string,
): Length extends 16
  ? Bytes16
  : Length extends 31
    ? Bytes31
    : Length extends 32
      ? Bytes32
      : Length extends 33
        ? Bytes33
        : Length extends 64
          ? Bytes64
          : Bytes128 {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field,
        expected: length,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  }
  return new Uint8Array(value) as never;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigintToBytes(value: bigint, length = 32): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { value: value.toString(), length },
    });
  }
  const result = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index--) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

export function field(value: bigint, name: string): bigint {
  if (value < 0n || value >= BN254_MODULUS) {
    throw new ClientError("CLIENT_INVALID_FIELD", {
      details: { field: name, value: value.toString() },
    });
  }
  return value;
}

export function bytesField(bytes: Uint8Array, name: string): bigint {
  if (bytes.length > 32) {
    throw new ClientError("CLIENT_FIELD_TOO_LONG", {
      details: { field: name, actual: bytes.length, maximum: 32 },
    });
  }
  return field(bytesToBigInt(bytes), name);
}

export function poseidon(inputs: readonly bigint[]): bigint {
  if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw hasherError("InvalidNumFields");
  }
  inputs.forEach((value, index) => field(value, `poseidon[${String(index)}]`));
  return bytesToBigInt(hash(inputs.map((value) => bigintToBytes(value))));
}

export function hashChain(values: readonly bigint[]): bigint {
  const first = values[0];
  if (first === undefined) return 0n;
  let result = first;
  for (let index = 1; index < values.length; index++) {
    const value = values[index];
    if (value === undefined) throw hasherError("EmptyInput");
    result = poseidon([result, value]);
  }
  return result;
}

/// Rust `create_two_inputs_hash_chain`. Pairs the two slices elementwise:
/// `H(i) = Poseidon(H(i-1), first[i], second[i])`, seeded by
/// `Poseidon(first[0], second[0])`. The single-pair case stops at that seed, so
/// it is a two-input hash and not a three-input one.
///
/// No production Rust caller reaches this today, so it is not on the proof path;
/// it is ported because `sdk-libs/ts/vectors/program-libs-parity-v1.json`
/// already pins its vectors, and a chain with committed vectors and no
/// implementation is a gap that only looks closed.
export function twoInputsHashChain(first: readonly bigint[], second: readonly bigint[]): bigint {
  if (first.length !== second.length) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: "two inputs hash chain", expected: first.length, actual: second.length },
    });
  }
  const seedFirst = first[0];
  const seedSecond = second[0];
  if (seedFirst === undefined || seedSecond === undefined) return 0n;
  let result = poseidon([seedFirst, seedSecond]);
  for (let index = 1; index < first.length; index++) {
    const left = first[index];
    const right = second[index];
    if (left === undefined || right === undefined) throw hasherError("EmptyInput");
    result = poseidon([result, left, right]);
  }
  return result;
}

export function hashField(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: "hash field input", expected: 32, actual: bytes.length },
    });
  }
  return bytesToBigInt(canonicalHashField(bytes));
}

export function sha256Bytes(bytes: Uint8Array): Bytes32 {
  return new Uint8Array(sha256(bytes)) as Bytes32;
}

export function decodeBase58(value: unknown, length: number, fieldName: string): Uint8Array {
  // Empty base58 is the empty byte string in bs58 and in the sibling base64
  // decoder. Instruction data can be empty; addresses and signatures cannot.
  if (typeof value === "string" && value.length === 0 && length === 0) {
    return new Uint8Array(0);
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: fieldName } });
  }
  const bytes = [0];
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) {
      throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: fieldName } });
    }
    let carry = digit;
    for (let index = 0; index < bytes.length; index++) {
      const next = (bytes[index] ?? 0) * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >>> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>>= 8;
    }
  }
  let zeroes = 0;
  while (value.charAt(zeroes) === "1") zeroes++;
  const extra = bytes.length === 1 && bytes[0] === 0 ? 0 : bytes.length;
  const result = new Uint8Array(zeroes + extra);
  for (let index = 0; index < extra; index++) {
    result[result.length - 1 - index] = bytes[index] ?? 0;
  }
  if (result.length !== length || encodeBase58(result) !== value) {
    throw new ClientError("CLIENT_INVALID_BASE58", {
      details: { field: fieldName, expectedLength: length, actualLength: result.length },
    });
  }
  return result;
}

export function encodeBase58(value: Uint8Array): string {
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = "";
  for (const byte of value) {
    if (byte !== 0) break;
    output += "1";
  }
  const allZero = output.length === value.length;
  for (let index = digits.length - 1; index >= 0; index--) {
    if (allZero && index === 0) continue;
    output += BASE58.charAt(digits[index] ?? 0);
  }
  return output;
}

export function addressBytes(value: Address): Bytes32 {
  return decodeBase58(value, 32, "address") as Bytes32;
}

export function signatureBytes(value: Signature): Bytes64 {
  return decodeBase58(value, 64, "signature") as Bytes64;
}

export function encodeBase64(value: Uint8Array): string {
  let output = "";
  for (let index = 0; index < value.length; index += 3) {
    const a = value[index] ?? 0;
    const b = value[index + 1] ?? 0;
    const c = value[index + 2] ?? 0;
    const bits = (a << 16) | (b << 8) | c;
    output += BASE64.charAt((bits >>> 18) & 63);
    output += BASE64.charAt((bits >>> 12) & 63);
    output += index + 1 < value.length ? BASE64.charAt((bits >>> 6) & 63) : "=";
    output += index + 2 < value.length ? BASE64.charAt(bits & 63) : "=";
  }
  return output;
}

export function decodeBase64(value: unknown, fieldName: string): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const result = new Uint8Array((value.length / 4) * 3 - padding);
  let output = 0;
  for (let index = 0; index < value.length; index += 4) {
    const a = BASE64.indexOf(value[index] ?? "");
    const b = BASE64.indexOf(value[index + 1] ?? "");
    const c = value[index + 2] === "=" ? 0 : BASE64.indexOf(value[index + 2] ?? "");
    const d = value[index + 3] === "=" ? 0 : BASE64.indexOf(value[index + 3] ?? "");
    const bits = (a << 18) | (b << 12) | (c << 6) | d;
    if (output < result.length) result[output++] = bits >>> 16;
    if (output < result.length) result[output++] = bits >>> 8;
    if (output < result.length) result[output++] = bits;
  }
  if (encodeBase64(result) !== value) {
    throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
  }
  return result;
}

export function p256Coordinates(bytes: Bytes33): readonly [bigint, bigint] {
  const prefix = bytes[0];
  if (prefix !== 2 && prefix !== 3) throw new ClientError("CLIENT_INVALID_P256_KEY");
  const x = bytesToBigInt(bytes.subarray(1));
  if (x >= P256_MODULUS) throw new ClientError("CLIENT_INVALID_P256_KEY");
  const y2 =
    (x ** 3n - 3n * x + 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn) %
    P256_MODULUS;
  let y = modPow(y2 < 0n ? y2 + P256_MODULUS : y2, (P256_MODULUS + 1n) / 4n, P256_MODULUS);
  if ((y & 1n) !== BigInt(prefix & 1)) y = P256_MODULUS - y;
  if ((y * y) % P256_MODULUS !== (y2 + P256_MODULUS) % P256_MODULUS) {
    throw new ClientError("CLIENT_INVALID_P256_KEY");
  }
  return [x, y];
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let value = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * value) % modulus;
    value = (value * value) % modulus;
    power >>= 1n;
  }
  return result;
}

export interface ComposedSignal {
  readonly signal: AbortSignal;
  timedOut(): boolean;
  cleanup(): void;
}

export function composeSignal(context: RequestContext | undefined, method: string): ComposedSignal {
  const timeoutMs = context?.timeoutMs;
  if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)) {
    throw new ClientError("CLIENT_INVALID_CONTEXT", {
      details: { field: "timeoutMs", method },
    });
  }
  if (context?.signal?.aborted === true) {
    throw new ClientError("CLIENT_ABORTED", { details: { method } });
  }
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let didTimeOut = false;
  const abort = (): void => {
    controller.abort();
  };
  context?.signal?.addEventListener("abort", abort, { once: true });
  if (timeoutMs !== undefined) {
    timeout = setTimeout(() => {
      didTimeOut = true;
      controller.abort();
    }, timeoutMs);
  }
  return {
    signal: controller.signal,
    timedOut: () => didTimeOut,
    cleanup(): void {
      if (timeout !== undefined) clearTimeout(timeout);
      context?.signal?.removeEventListener("abort", abort);
    },
  };
}

export function requestError(method: string, signal: ComposedSignal): ClientError {
  return new ClientError(
    signal.timedOut()
      ? "CLIENT_TIMEOUT"
      : signal.signal.aborted
        ? "CLIENT_ABORTED"
        : "CLIENT_REQUEST",
    {
      details: { method, retryable: signal.timedOut() || !signal.signal.aborted },
    },
  );
}

export function sleep(delayMs: bigint, context?: RequestContext): Promise<void> {
  if (delayMs < 0n || delayMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "delayMs", value: delayMs.toString() },
    });
  }
  return new Promise((resolve, reject) => {
    if (context?.signal?.aborted === true) {
      reject(new ClientError("CLIENT_ABORTED"));
      return;
    }
    const finish = (): void => {
      context?.signal?.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = setTimeout(finish, Number(delayMs));
    const abort = (): void => {
      clearTimeout(timeout);
      context?.signal?.removeEventListener("abort", abort);
      reject(new ClientError("CLIENT_ABORTED"));
    };
    context?.signal?.addEventListener("abort", abort, { once: true });
  });
}
