/**
 * The one Poseidon the TypeScript packages hash with, compiled from
 * `zolana_hasher::Poseidon`.
 *
 * The artifact is instantiated by `initializePoseidon`, not at import time. A
 * module-scope `await` would keep `poseidon` synchronous for free, but it also
 * makes the module inexpressible in a CommonJS build, and this SDK ships one.
 * So the asynchrony sits in one call the consumer makes once, and hashing stays
 * synchronous everywhere above it.
 *
 * Calling `poseidon` first is an error rather than an implicit wait. A promise
 * returned where a digest was expected, or a digest that arrives late, is worse
 * than a refusal that names the missing call.
 */
import { ARTIFACT, ARTIFACT_BYTE_LENGTH } from "./artifact.js";

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

/** The size of the compiled artifact, for the packaging report. */
export const POSEIDON_ARTIFACT_BYTES = ARTIFACT_BYTE_LENGTH;

/** Codes outside the `HasherError` space, which starts at 7001. */
const ERROR_ARITY = 1;
const ERROR_UNINITIALIZED = 2;
const ERROR_ARITY_MISMATCH = 3;

let loaded: Loaded | undefined;
let loading: Promise<Loaded> | undefined;

function decodeArtifact(): ArrayBuffer {
  const binary = atob(ARTIFACT);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return buffer;
}

async function instantiate(): Promise<Loaded> {
  const { instance } = await WebAssembly.instantiate(decodeArtifact(), {});
  const wasm = instance.exports as unknown as PoseidonExports;
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
 * Loads the compiled hasher. Safe to call more than once and from several
 * callers at once: the first call does the work and the rest await it. A failed
 * load is not cached, so a caller can retry.
 */
export async function initializePoseidon(): Promise<void> {
  if (loaded !== undefined) return;
  loading ??= instantiate();
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
 * part of the packages' public surface.
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
        7005,
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
