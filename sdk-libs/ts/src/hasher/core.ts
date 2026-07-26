/**
 * The one Poseidon the TypeScript SDK hashes with, compiled from
 * `zolana_hasher::Poseidon`.
 *
 * Everything here is independent of where the artifact came from, which is what
 * lets default and host-supplied artifact loading share a single instance.
 * Only the loading differs; the digests cannot.
 *
 * The artifact is instantiated by an initializer, not at import time. A
 * module-scope `await` would make every package import asynchronous and removes
 * the caller's ability to supply relocated bytes. The asynchrony therefore sits
 * in one initialization call, and hashing stays synchronous everywhere above it.
 *
 * Calling `poseidon` first is an error rather than an implicit wait. A promise
 * returned where a digest was expected, or a digest that arrives late, is worse
 * than a refusal that names the missing call.
 */

interface PoseidonExports {
  readonly zolana_poseidon_input: () => number;
  readonly zolana_poseidon_output: () => number;
  readonly zolana_poseidon_max_inputs: () => number;
  readonly zolana_poseidon_hashv: (count: number) => number;
  readonly memory: WebAssembly.Memory;
}

interface Loaded {
  readonly wasm: PoseidonExports;
  readonly inputOffset: number;
  readonly outputOffset: number;
}

/** A rejection the Rust hasher raised, carrying the code Rust gives it. */
export class HasherWasmError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.name = "HasherWasmError";
    this.code = code;
  }
}

const FIELD_BYTES = 32;

/**
 * The arity ceiling. Twelve is where `light_poseidon` and the `sol_poseidon`
 * syscall stop, so a wider digest is one no verifier can reproduce. It is
 * stated here because a caller needs it before the module is loaded, and
 * checked against the module at every load, so the two cannot drift.
 */
export const MAX_POSEIDON_INPUTS = 12;

/** Codes outside the `HasherError` space, which starts at 7001. */
const ERROR_ARITY = 1;
const ERROR_UNINITIALIZED = 2;
const ERROR_ARITY_MISMATCH = 3;

/**
 * `HasherError::InvalidInputLength`. An over-wide input is caught here rather
 * than in the module, because the wrapper's buffer has no room for it, so this
 * side raises the code Rust would have.
 */
const ERROR_INVALID_INPUT_LENGTH = 7005;

let loaded: Loaded | undefined;
let loading: Promise<Loaded> | undefined;

async function instantiate(instance: () => Promise<WebAssembly.Instance>): Promise<Loaded> {
  const wasm = (await instance()).exports as unknown as PoseidonExports;
  const arity = wasm.zolana_poseidon_max_inputs();
  if (arity !== MAX_POSEIDON_INPUTS) {
    throw new HasherWasmError(
      ERROR_ARITY_MISMATCH,
      `the compiled hasher takes ${String(arity)} inputs where this module expects ${String(MAX_POSEIDON_INPUTS)}`,
    );
  }
  return {
    wasm,
    inputOffset: wasm.zolana_poseidon_input(),
    outputOffset: wasm.zolana_poseidon_output(),
  };
}

/**
 * Loads the compiled hasher from whatever the caller's entry point instantiated.
 * Safe to call more than once and from several callers at once: the first call
 * does the work and the rest await it, so default and host-supplied loading in
 * one graph converge on one instance rather than two. A failed load is not
 * cached, so a caller can retry.
 */
export async function loadPoseidon(instance: () => Promise<WebAssembly.Instance>): Promise<void> {
  if (loaded !== undefined) return;
  loading ??= instantiate(instance);
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

/**
 * Drops the loaded module so a test can exercise the uninitialized path. Not
 * part of the package's public surface.
 */
export function resetPoseidonForTests(): void {
  loaded = undefined;
  loading = undefined;
}

/**
 * Hashes one to twelve big-endian field elements. An input shorter than 32
 * bytes is right-aligned, which is what every caller already does and what the
 * hand-written implementations this replaces accepted.
 */
export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  const active = loaded;
  if (active === undefined) {
    throw new HasherWasmError(
      ERROR_UNINITIALIZED,
      "the Poseidon hasher is not loaded; await initializePoseidon() once before hashing",
    );
  }
  if (inputs.length === 0 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw new HasherWasmError(
      ERROR_ARITY,
      `Poseidon takes 1 to ${String(MAX_POSEIDON_INPUTS)} inputs, received ${String(inputs.length)}`,
    );
  }

  const { wasm, inputOffset, outputOffset } = active;
  const view = new Uint8Array(wasm.memory.buffer, inputOffset, MAX_POSEIDON_INPUTS * FIELD_BYTES);
  view.fill(0, 0, inputs.length * FIELD_BYTES);
  for (const [index, input] of inputs.entries()) {
    if (input.length > FIELD_BYTES) {
      throw new HasherWasmError(
        ERROR_INVALID_INPUT_LENGTH,
        `Poseidon input ${String(index)} is ${String(input.length)} bytes, the field takes 32`,
      );
    }
    view.set(input, (index + 1) * FIELD_BYTES - input.length);
  }

  const code = wasm.zolana_poseidon_hashv(inputs.length);
  if (code !== 0) {
    throw new HasherWasmError(code, `Poseidon rejected the input with hasher code ${String(code)}`);
  }
  return new Uint8Array(wasm.memory.buffer, outputOffset, FIELD_BYTES).slice();
}
