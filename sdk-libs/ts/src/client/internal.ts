import {
  assertIsSignature,
  getAddressEncoder,
  getBase58Encoder,
  getBase64Decoder,
  getBase64Encoder,
} from "@solana/kit";
import {
  type ChainField,
  foldHashChain,
  foldHashChain4,
  foldRightHashChain,
  foldRightHashChain4,
} from "../hasher/chain.js";
import { BN254_SCALAR_ORDER, poseidonOr } from "../hasher/index.js";

import { bytesToBigInt } from "../interface/bytes.js";
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
} from "../interface/types.js";
import { INPUT_TREES } from "../interface/tree-slot.js";
import { hashBytes } from "../hasher/index.js";
import { bigIntToBytes } from "../keypair/bytes.js";
import { KeypairError } from "../keypair/error.js";
import { treeAddress } from "../interface/pda/index.js";
import type { IndexedProofAuthority, TreeContext } from "./ports.js";

import {
  composeSignal as composeTransportSignal,
  type ComposedSignal,
} from "../services/signal.js";
import { TransportFailure, checkedEndpoint } from "../services/transport.js";
import { ClientError, hasherError } from "./error.js";

/** The client's own tree id keeps its configured address, any other id is the pool's tree PDA. */
export function inputTreeAddress(client: TreeContext, treeId: number): Address {
  return treeId === client.treeId ? client.tree : treeAddress(treeId);
}

const addressEncoder = getAddressEncoder();
const base58Encoder = getBase58Encoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();

/**
 * Service URLs must be https, or http to loopback.
 *
 * This is stricter than a general "prefer TLS" default because of what these
 * two endpoints carry. The indexer's response says which UTXOs an identity
 * owns, and the prover's request carries the witness. In plaintext both are
 * readable by anyone on the path, which is the whole privacy property of a
 * shielded protocol, not a hardening nicety. A tamperer can also feed altered
 * merkle proofs or root indices and steer the client into proving against
 * state it did not choose.
 *
 * `allowInsecureHttp` exists for deployments where the transport is already
 * private -- an indexer inside your own VPC, a service mesh terminating TLS
 * elsewhere. It is opt-in so that choice is deliberate and greppable rather
 * than the silent default.
 */
export function checkedServiceUrl(
  value: string | URL,
  field: string,
  allowInsecureHttp = false,
): URL {
  try {
    return checkedEndpoint(value, { field, allowInsecureHttp, allowLoopbackHttp: true });
  } catch (error) {
    if (!(error instanceof TransportFailure)) throw error;
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
  }
}

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

/** `bigIntToBytes`, rejecting a value that does not fit as `CLIENT_INVALID_INTEGER`. */
export function bigintToBytes(value: bigint, name: string, length = 32): Uint8Array {
  try {
    return bigIntToBytes(value, length);
  } catch (cause) {
    if (!(cause instanceof KeypairError)) throw cause;
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: name, length } });
  }
}

export function field(value: bigint, name: string): bigint {
  if (value < 0n || value >= BN254_SCALAR_ORDER) {
    throw new ClientError("CLIENT_INVALID_FIELD", { details: { field: name } });
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

/** The hasher's `poseidon` over field elements, rejecting as `CLIENT_INVALID_FIELD` or `CLIENT_HASHER`. */
export function poseidon(inputs: readonly bigint[]): bigint {
  const fields = inputs.map((value, index) =>
    bigintToBytes(field(value, `poseidon[${String(index)}]`), "poseidon input"),
  );
  return bytesToBigInt(poseidonOr(fields, (failure) => hasherError(failure.code, failure)));
}

const FIELD: ChainField<bigint> = {
  zero: () => 0n,
  isZero: (value) => value === 0n,
  hash: poseidon,
};

export function hashChain(values: readonly bigint[]): bigint {
  return foldHashChain(values, FIELD);
}

/** Three elements per Poseidon call, see `foldHashChain4`. */
export function hashChain4(values: readonly bigint[]): bigint {
  return foldHashChain4(values, FIELD);
}

/**
 * The packed `input_flags` public input: bit 0 carries the dummy-input policy
 * and input `i`'s three-bit tree index sits at bits `1 + 3 * i` through
 * `3 + 3 * i`, for a total width of `1 + 3 * inputs` bits. The circuit decodes
 * that fixed width and asserts every input's private tree slot equals the index
 * published here, which is what binds the tree a proof opened against to the
 * tree the program queues that input's nullifier into. Mirrors Rust
 * `pack_input_flags`.
 */
export function inputFlags(allowDummyInputs: boolean, treeIndexes: readonly number[]): bigint {
  let flags = allowDummyInputs ? 1n : 0n;
  treeIndexes.forEach((treeIndex, index) => {
    if (!Number.isSafeInteger(treeIndex)) {
      throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "treeIndex" } });
    }
    if (treeIndex < 0 || treeIndex >= INPUT_TREES) {
      throw new ClientError("CLIENT_INPUT_TREE_INDEX_RANGE", {
        details: { index, treeIndex, max: INPUT_TREES - 1 },
      });
    }
    flags |= BigInt(treeIndex) << BigInt(1 + 3 * index);
  });
  return flags;
}

export function rightHashChain(values: readonly bigint[]): bigint {
  return foldRightHashChain(values, FIELD);
}

/** Rust `create_right_hash_chain_4_from_slice`, see `foldRightHashChain4`. */
export function rightHashChain4(values: readonly bigint[]): bigint {
  return foldRightHashChain4(values, FIELD);
}

export function hashBytesBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: "hash_bytes input", expected: 32, actual: bytes.length },
    });
  }
  return bytesToBigInt(hashBytes(bytes));
}

export function addressBytes(value: Address): Bytes32 {
  try {
    return new Uint8Array(addressEncoder.encode(value)) as Bytes32;
  } catch {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: "address" } });
  }
}

export function signatureBytes(value: Signature): Bytes64 {
  try {
    assertIsSignature(value);
    return new Uint8Array(base58Encoder.encode(value)) as Bytes64;
  } catch {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field: "signature" } });
  }
}

export function decodeBase64(value: unknown, fieldName: string): Uint8Array {
  if (typeof value !== "string") {
    throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
  }
  try {
    const result = new Uint8Array(base64Encoder.encode(value));
    if (base64Decoder.decode(result) === value) return result;
  } catch {
    // Kit codec failures are mapped below.
  }
  throw new ClientError("CLIENT_INVALID_BASE64", { details: { field: fieldName } });
}

export type { ComposedSignal };

export function composeSignal(context: RequestContext | undefined, method: string): ComposedSignal {
  try {
    return composeTransportSignal(context);
  } catch (error) {
    if (!(error instanceof TransportFailure)) throw error;
    if (error.kind === "context") {
      throw new ClientError("CLIENT_INVALID_CONTEXT", { details: { field: "timeoutMs", method } });
    }
    throw new ClientError("CLIENT_ABORTED", { details: { method } });
  }
}

/**
 * Settles with `promise`, or rejects with `aborted()` once `signal` aborts, even
 * when the work behind `promise`, such as an injected fetch, ignores the signal.
 */
export function untilAborted<T>(
  promise: Promise<T>,
  signal: ComposedSignal,
  aborted: () => unknown,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(aborted());
    if (signal.signal.aborted) abort();
    else signal.signal.addEventListener("abort", abort, { once: true });
    void promise
      .then(resolve, reject)
      .finally(() => signal.signal.removeEventListener("abort", abort));
  });
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

/** Whether `candidate` answers indexed requests, callers name the error. */
export function hasIndexedMethod(candidate: unknown): candidate is IndexedProofAuthority {
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    typeof Reflect.get(candidate, "proveIndexed") === "function"
  );
}

/** Whether `candidate` carries the two proving methods; callers name the error. */
export function hasProofMethods(candidate: unknown): boolean {
  return (
    typeof candidate === "object" &&
    candidate !== null &&
    typeof Reflect.get(candidate, "prove") === "function" &&
    typeof Reflect.get(candidate, "proveMerge") === "function"
  );
}
