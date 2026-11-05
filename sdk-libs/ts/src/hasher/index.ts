import { WasmFactory, type LightWasm } from "@lightprotocol/hasher.rs";

export type HasherFailureCode =
  | "NotInitialized"
  | "InvalidNumFields"
  | "InvalidInputLength"
  | "Poseidon";

/** Which input a rejected hash named: the input count, or one input's position and width. */
export type HasherFailureDetails = Readonly<{
  inputCount?: number;
  index?: number;
  length?: number;
}>;

/** @internal No barrel exports it. */
export class HasherFailure extends Error {
  readonly code: HasherFailureCode;
  readonly details: HasherFailureDetails;

  constructor(code: HasherFailureCode, message: string, details: HasherFailureDetails = {}) {
    super(message);
    this.name = "HasherFailure";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

const FIELD_BYTES = 32;

/** Every Poseidon input and output is below it. */
export const BN254_SCALAR_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** `a + b` in the BN254 scalar field, for the additive Poseidon-pad ciphers. */
export function fieldAdd(a: bigint, b: bigint): bigint {
  return (((a + b) % BN254_SCALAR_ORDER) + BN254_SCALAR_ORDER) % BN254_SCALAR_ORDER;
}

/** `a - b` in the BN254 scalar field. */
export function fieldSub(a: bigint, b: bigint): bigint {
  return (((a - b) % BN254_SCALAR_ORDER) + BN254_SCALAR_ORDER) % BN254_SCALAR_ORDER;
}

/** The widest digest supported by both the runtime and the Solana verifier. */
export const MAX_POSEIDON_INPUTS = 12;

let loaded: LightWasm | undefined;
let loading: Promise<LightWasm> | undefined;

/** Loads the dependency-backed hasher once while keeping hashing synchronous. */
export async function initializePoseidon(): Promise<void> {
  if (loaded !== undefined) return;
  loading ??= WasmFactory.loadHasher();
  try {
    loaded = await loading;
  } catch (error) {
    loading = undefined;
    throw error;
  }
}

/** Whether `poseidon` can be called. */
export function isPoseidonInitialized(): boolean {
  return loaded !== undefined;
}

/** @internal Drops the loaded module so tests can exercise initialization. */
export function resetPoseidonForTests(): void {
  loaded = undefined;
  loading = undefined;
  WasmFactory.resetModule();
}

/**
 * Hashes one to twelve unsigned big-endian field elements. Every input is at
 * most 32 bytes and below `BN254_SCALAR_ORDER`; anything else is a
 * `HasherFailure` naming the input. Layers with their own error taxonomy call
 * it through `poseidonOr`.
 */
export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  const active = loaded;
  if (active === undefined) {
    throw new HasherFailure(
      "NotInitialized",
      "the Poseidon hasher is not loaded, await initializePoseidon() once before hashing",
    );
  }
  if (inputs.length === 0 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw new HasherFailure(
      "InvalidNumFields",
      `Poseidon takes 1 to ${String(MAX_POSEIDON_INPUTS)} inputs, received ${String(inputs.length)}`,
      { inputCount: inputs.length },
    );
  }

  const decimalInputs = inputs.map((input, index) => {
    if (input.length > FIELD_BYTES) {
      throw new HasherFailure(
        "InvalidInputLength",
        `Poseidon input ${String(index)} is ${String(input.length)} bytes, the field takes 32`,
        { index, length: input.length },
      );
    }
    let value = 0n;
    for (const byte of input) value = (value << 8n) | BigInt(byte);
    if (value >= BN254_SCALAR_ORDER) {
      throw new HasherFailure(
        "Poseidon",
        `Poseidon input ${String(index)} is not below the BN254 scalar order`,
        { index, length: input.length },
      );
    }
    return value.toString();
  });
  try {
    return new Uint8Array(active.poseidonHash(decimalInputs));
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new HasherFailure("Poseidon", `Poseidon rejected the input, ${reason}`);
  }
}

/**
 * `poseidon`, with a rejection mapped to the caller's error by `fail`. Returning
 * the failure itself lets it pass through unchanged.
 */
export function poseidonOr(
  inputs: readonly Uint8Array[],
  fail: (failure: HasherFailure) => Error,
): Uint8Array {
  try {
    return poseidon(inputs);
  } catch (cause) {
    if (cause instanceof HasherFailure) throw fail(cause);
    throw cause;
  }
}

/** Packs fixed-size bytes into 31-byte fields and folds them like Rust `hash_bytes`. */
export function hashBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) return new Uint8Array(FIELD_BYTES);
  let offset = 0;
  let result = packed(bytes.subarray(0, 31));
  offset = 31;
  while (offset < bytes.length) {
    result = poseidon([result, packed(bytes.subarray(offset, offset + 31))]);
    offset += 31;
  }
  return result;
}

/** Algorithm tag of an Ed25519 or PDA owner identity, `'S'`. */
export const SOLANA_OWNER_TAG = 0x53;
/** Hashes the Solana owner tag with a fixed-width identity key. */
export function solanaOwnerIdentity(key: Uint8Array): Uint8Array {
  if (key.length !== FIELD_BYTES) {
    throw new HasherFailure(
      "InvalidInputLength",
      `an owner identity takes a 32-byte key, received ${String(key.length)} bytes`,
    );
  }
  const tagged = new Uint8Array(FIELD_BYTES + 1);
  tagged[0] = SOLANA_OWNER_TAG;
  tagged.set(key, 1);
  return hashBytes(tagged);
}

function packed(bytes: Uint8Array): Uint8Array {
  const field = new Uint8Array(FIELD_BYTES);
  field.set(bytes, FIELD_BYTES - bytes.length);
  return field;
}
