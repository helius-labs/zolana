import { WasmFactory, type LightWasm } from "@lightprotocol/hasher.rs";

export type HasherFailureCode =
  | "NotInitialized"
  | "InvalidNumFields"
  | "InvalidInputLength"
  | "Poseidon";

/** @internal No barrel exports it. */
export class HasherFailure extends Error {
  readonly code: HasherFailureCode;

  constructor(code: HasherFailureCode, message: string) {
    super(message);
    this.name = "HasherFailure";
    this.code = code;
  }
}

const FIELD_BYTES = 32;

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

/** Hashes one to twelve unsigned big-endian field elements. */
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
    );
  }

  const decimalInputs = inputs.map((input, index) => {
    if (input.length > FIELD_BYTES) {
      throw new HasherFailure(
        "InvalidInputLength",
        `Poseidon input ${String(index)} is ${String(input.length)} bytes, the field takes 32`,
      );
    }
    let value = 0n;
    for (const byte of input) value = (value << 8n) | BigInt(byte);
    return value.toString();
  });
  try {
    return new Uint8Array(active.poseidonHash(decimalInputs));
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new HasherFailure("Poseidon", `Poseidon rejected the input, ${reason}`);
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
/** Algorithm tag of a P256 owner identity, `'P'`. */
export const P256_OWNER_TAG = 0x50;

/**
 * Proof-input identity of a Solana signer, `hash_bytes(0x53 || pubkey)`.
 * Mirrors Rust `solana_owner_identity`. The tag keeps an Ed25519 key and a
 * P256 x-coordinate with equal bytes apart and avoids the SEC1 prefixes, so
 * an owner identity can never equal a viewing-key commitment.
 */
export function solanaOwnerIdentity(publicKey: Uint8Array): Uint8Array {
  return taggedIdentity(SOLANA_OWNER_TAG, publicKey);
}

/** Proof-input identity of a P256 owner, `hash_bytes(0x50 || x)`. Mirrors Rust `p256_owner_identity`. */
export function p256OwnerIdentity(x: Uint8Array): Uint8Array {
  return taggedIdentity(P256_OWNER_TAG, x);
}

function taggedIdentity(tag: number, key: Uint8Array): Uint8Array {
  if (key.length !== FIELD_BYTES) {
    throw new HasherFailure(
      "InvalidInputLength",
      `an owner identity takes a 32-byte key, received ${String(key.length)} bytes`,
    );
  }
  const tagged = new Uint8Array(FIELD_BYTES + 1);
  tagged[0] = tag;
  tagged.set(key, 1);
  return hashBytes(tagged);
}

function packed(bytes: Uint8Array): Uint8Array {
  const field = new Uint8Array(FIELD_BYTES);
  field.set(bytes, FIELD_BYTES - bytes.length);
  return field;
}
