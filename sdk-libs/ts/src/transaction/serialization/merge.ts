import { bytesToBigInt } from "../../interface/bytes.js";
import type { Address, Bytes16, Bytes32 } from "../../interface/types.js";
import { BN254_SCALAR_ORDER, fieldAdd, fieldSub } from "../../hasher/index.js";
import { bigIntToBytes } from "../../keypair/bytes.js";
import { MERGE_OUTPUT_CIPHERTEXT_ELEMENTS, mergeOutputPads } from "../../keypair/merge/index.js";
import { TransactionError } from "../error.js";
import { checked, decodeAddress, encodeAddress } from "../internal.js";
import {
  EncryptedScheme,
  decodeOutputData,
  encodeOutputData,
  mergeOutputDataEncoding,
} from "./codecs.js";

/** The two output fields a merge proof encrypts for the owner. Rust `MergeOutputPlaintext`. */
export interface MergeOutputPlaintext {
  readonly amount: bigint;
  readonly mint: Address;
}

export type MergeOutputCiphertext = readonly [Bytes32, Bytes32, Bytes32];

const SALT_LENGTH = 16;
const HASH_BYTES_CHUNK = 31;

/** Bytes of the encrypted part of a merge output body: the salt, then the ciphertext. */
export const MERGE_OUTPUT_BODY_LENGTH = SALT_LENGTH + 32 * MERGE_OUTPUT_CIPHERTEXT_ELEMENTS;

/** `[amount, mint chunk 0, mint chunk 1]`: the `hash_bytes_32` chunks of the mint. */
function plaintextFields(plaintext: MergeOutputPlaintext): readonly [bigint, bigint, bigint] {
  if (plaintext.amount < 0n || plaintext.amount > 0xffff_ffff_ffff_ffffn) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      field: "merge output amount",
      value: String(plaintext.amount),
    });
  }
  return [plaintext.amount, ...mergeMintChunks(plaintext.mint)];
}

/** The shared mint encoding used by the cipher and the merge prover inputs. */
export function mergeMintChunks(mint: Address): readonly [bigint, bigint] {
  const bytes = decodeAddress(mint);
  return [
    bytesToBigInt(bytes.subarray(0, HASH_BYTES_CHUNK)),
    bytesToBigInt(bytes.subarray(HASH_BYTES_CHUNK)),
  ];
}

/**
 * The ciphertext a merge instruction carries: element `i` of the plaintext
 * plus `mergeOutputPads(key, salt)[i]` in the BN254 scalar field. `key` is the
 * wallet's `mergeOutputKey` answer and `salt` must be fresh per proof. Mirrors
 * Rust `MergeOutputPlaintext::encrypt`.
 */
export function encryptMergeOutput(
  plaintext: MergeOutputPlaintext,
  key: Bytes32,
  salt: Bytes16,
): MergeOutputCiphertext {
  const [pad0, pad1, pad2] = mergeOutputPads(key, salt);
  const [amount, chunk0, chunk1] = plaintextFields(plaintext);
  const encrypt = (element: bigint, pad: bigint) =>
    bigIntToBytes(fieldAdd(element, pad)) as Bytes32;
  return Object.freeze([
    encrypt(amount, pad0),
    encrypt(chunk0, pad1),
    encrypt(chunk1, pad2),
  ] as const);
}

/**
 * Decrypts `salt || ciphertext` with the per-merge key. The cipher is
 * unauthenticated: an element outside its slot's range is how a ciphertext
 * addressed to another key shows up, and it fails closed. The caller still
 * checks the rebuilt output against the published commitment. Mirrors Rust
 * `MergeOutputPlaintext::decrypt`.
 */
export function decryptMergeOutput(body: Uint8Array, key: Bytes32): MergeOutputPlaintext {
  if (body.length !== MERGE_OUTPUT_BODY_LENGTH) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "merge output body",
      expected: MERGE_OUTPUT_BODY_LENGTH,
      actual: body.length,
    });
  }
  const [pad0, pad1, pad2] = mergeOutputPads(key, body.subarray(0, SALT_LENGTH));
  const decrypt = (index: number, pad: bigint): bigint => {
    const offset = SALT_LENGTH + 32 * index;
    const element = bytesToBigInt(body.subarray(offset, offset + 32));
    if (element >= BN254_SCALAR_ORDER) {
      throw new TransactionError("TRANSACTION_NON_CANONICAL_MERGE_CIPHERTEXT", { index });
    }
    return fieldSub(element, pad);
  };
  const amount = decrypt(0, pad0);
  const chunk0 = decrypt(1, pad1);
  const chunk1 = decrypt(2, pad2);
  if (amount >= 1n << 64n || chunk0 >= 1n << BigInt(8 * HASH_BYTES_CHUNK) || chunk1 >= 1n << 8n) {
    throw new TransactionError("TRANSACTION_INVALID_MERGE_OUTPUT_PLAINTEXT");
  }
  const mint = new Uint8Array(32);
  mint.set(bigIntToBytes(chunk0, HASH_BYTES_CHUNK));
  mint.set(bigIntToBytes(chunk1, 1), HASH_BYTES_CHUNK);
  return Object.freeze({ amount, mint: encodeAddress(mint) });
}

/**
 * A merge output's data slot, as Rust `encode_merge_output_data` and the
 * indexer rebuild it from the merge instruction: `VerifiablyEncrypted(scheme ||
 * salt || ciphertext)` for a default merge, whose proof binds the ciphertext,
 * and `Encrypted(scheme || ring_data_hash || salt || ciphertext)` for a ring
 * merge, whose proof does not.
 */
export function encodeMergeOutputData(
  input: Readonly<{
    salt: Bytes16;
    ciphertext: MergeOutputCiphertext;
    ringDataHash?: Bytes32;
  }>,
): Uint8Array {
  const parts = [
    ...(input.ringDataHash === undefined
      ? []
      : [checked<Bytes32>(input.ringDataHash, 32, "merge ring data hash")]),
    checked<Bytes16>(input.salt, SALT_LENGTH, "merge output salt"),
    ...input.ciphertext.map((element) => checked<Bytes32>(element, 32, "merge output ciphertext")),
  ];
  const body = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    body.set(part, offset);
    offset += part.length;
  }
  return encodeOutputData(
    EncryptedScheme.merge,
    body,
    mergeOutputDataEncoding(input.ringDataHash !== undefined),
  );
}

/** The encrypted body of a merge output slot. */
export type MergeOutputBody = Readonly<{ ringDataHash?: Bytes32; encrypted: Uint8Array }>;

/**
 * Reads a merge output slot's payload: `undefined` for any other scheme, a
 * payload that does not decode, or an encoding other than the one
 * [`mergeOutputDataEncoding`] gives the body's shape (a ring merge body is led
 * by its ring data hash). A ring merge ciphertext is unverified, so the caller
 * must check the decrypted output against the published commitment.
 */
export function readMergeOutputBody(payload: Uint8Array): MergeOutputBody | undefined {
  try {
    const frame = decodeOutputData(payload);
    if (frame.scheme !== EncryptedScheme.merge) return undefined;
    const body = splitMergeOutputBody(frame.body);
    if (body === undefined) return undefined;
    return frame.encoding === mergeOutputDataEncoding(body.ringDataHash !== undefined)
      ? body
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Splits a merge output body (after the scheme byte) into the `merge_ring`
 * output ring data hash and the encrypted part. `undefined` for any other length.
 */
export function splitMergeOutputBody(body: Uint8Array): MergeOutputBody | undefined {
  if (body.length === MERGE_OUTPUT_BODY_LENGTH) return Object.freeze({ encrypted: body });
  if (body.length === 32 + MERGE_OUTPUT_BODY_LENGTH) {
    return Object.freeze({
      ringDataHash: new Uint8Array(body.subarray(0, 32)) as Bytes32,
      encrypted: body.subarray(32),
    });
  }
  return undefined;
}
