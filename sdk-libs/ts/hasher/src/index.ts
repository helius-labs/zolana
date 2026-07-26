/**
 * The default entry point: the compiled Poseidon, inlined.
 *
 * These packages emit plain `tsc` output with no bundler step, so a sibling
 * `.wasm` cannot be located from here. `fetch` does not read a `file:` URL in
 * Node, and `node:fs` is what the browser gate exists to exclude. Inlining is
 * what makes one import work in both runtimes with no host cooperation, and it
 * costs the artifact as base64 rather than as bytes.
 *
 * A consumer that can serve or read a file should import `@zolana/hasher/slim`
 * instead and hand it the `poseidon.wasm` this package ships. Same digests,
 * same module, a third less to download and no base64 through the JavaScript
 * parser.
 */
import { ARTIFACT, ARTIFACT_BYTE_LENGTH } from "./artifact.js";
import { loadPoseidon } from "./core.js";

export {
  HasherWasmError,
  isPoseidonInitialized,
  MAX_POSEIDON_INPUTS,
  poseidon,
  resetPoseidonForTests,
} from "./core.js";

/** The size of the compiled artifact, for the packaging report. */
export const POSEIDON_ARTIFACT_BYTES = ARTIFACT_BYTE_LENGTH;

function decodeArtifact(): ArrayBuffer {
  const binary = atob(ARTIFACT);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return buffer;
}

/**
 * Loads the compiled hasher from the inlined artifact. Safe to call more than
 * once and from several callers at once; a failed load is not cached, so a
 * caller can retry.
 */
export async function initializePoseidon(): Promise<void> {
  await loadPoseidon(async () => {
    const { instance } = await WebAssembly.instantiate(decodeArtifact(), {});
    return instance;
  });
}
