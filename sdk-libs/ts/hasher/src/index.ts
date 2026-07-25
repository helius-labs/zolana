/**
 * The one Poseidon the TypeScript packages hash with, compiled from
 * `zolana_hasher::Poseidon`.
 *
 * The module is instantiated once at import time. That top-level `await` is
 * load bearing rather than stylistic: a browser refuses to compile a
 * WebAssembly buffer larger than 4 KB synchronously on the main thread, and
 * this one is well past that, so the alternative to awaiting here is an
 * asynchronous `poseidon` and an asynchronous everything above it. Consumers
 * therefore need an ES module graph; a bundle emitted as CommonJS cannot
 * express it.
 */
import { ARTIFACT, ARTIFACT_BYTE_LENGTH } from "./artifact.js";

interface PoseidonExports {
  readonly zolana_poseidon_input: () => number;
  readonly zolana_poseidon_output: () => number;
  readonly zolana_poseidon_max_inputs: () => number;
  readonly zolana_poseidon_hashv: (count: number) => number;
  readonly memory: WebAssembly.Memory;
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

function decodeArtifact(): ArrayBuffer {
  const binary = atob(ARTIFACT);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return buffer;
}

const { instance } = await WebAssembly.instantiate(decodeArtifact(), {});
const wasm = instance.exports as unknown as PoseidonExports;

const FIELD_BYTES = 32;
const inputOffset = wasm.zolana_poseidon_input();
const outputOffset = wasm.zolana_poseidon_output();

/**
 * The arity ceiling, read off the module rather than restated here. Twelve is
 * where `light_poseidon` and the `sol_poseidon` syscall stop, so a wider digest
 * is one no verifier can reproduce.
 */
export const MAX_POSEIDON_INPUTS = wasm.zolana_poseidon_max_inputs();

/** The size of the compiled artifact, for the packaging report. */
export const POSEIDON_ARTIFACT_BYTES = ARTIFACT_BYTE_LENGTH;

/**
 * Hashes one to twelve big-endian field elements. An input shorter than 32
 * bytes is right-aligned, which is what every caller already does and what the
 * hand-written implementations this replaces accepted.
 */
export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  if (inputs.length === 0 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw new HasherWasmError(
      1,
      `Poseidon takes 1 to ${String(MAX_POSEIDON_INPUTS)} inputs, received ${String(inputs.length)}`,
    );
  }

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
