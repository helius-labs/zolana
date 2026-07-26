/**
 * The same Poseidon, loaded from the `poseidon.wasm` this package ships rather
 * than from the base64 the default entry point carries. A consumer that can
 * serve or read a file downloads the artifact once as bytes instead of a third
 * again as text, and skips compiling that text as JavaScript.
 *
 * The artifact is a parameter rather than something this module goes looking
 * for. Locating a sibling file needs a host: `fetch` refuses a `file:` URL in
 * Node, `node:fs` is what the browser gate excludes, and `import.meta.url` is
 * not expressible in the CommonJS half of this build. Only the consumer knows
 * which of those it has, so this module takes what they resolved and stops
 * there. The default entry point exists for consumers who have none of them.
 *
 * ```ts
 * import { initializePoseidon, poseidon } from "@zolana/hasher/slim";
 *
 * // Node
 * await initializePoseidon(
 *   await readFile(createRequire(import.meta.url).resolve("@zolana/hasher/poseidon.wasm")),
 * );
 * // Browser, from wherever the asset is served
 * await initializePoseidon(fetch("/assets/poseidon.wasm"));
 * ```
 */
import { loadPoseidon } from "../core.js";

export {
  HasherWasmError,
  isPoseidonInitialized,
  MAX_POSEIDON_INPUTS,
  poseidon,
  resetPoseidonForTests,
} from "../core.js";

/**
 * Where the artifact comes from. A string or `URL` is fetched, which is why a
 * `file:` URL does not work in Node: read it and pass the bytes.
 */
export type PoseidonArtifact = BufferSource | WebAssembly.Module | Response | URL | string;

async function instantiateResponse(response: Response): Promise<WebAssembly.Instance> {
  if (typeof WebAssembly.instantiateStreaming === "function") {
    try {
      return (await WebAssembly.instantiateStreaming(response, {})).instance;
    } catch (error) {
      // A host that serves the artifact as `application/octet-stream` rejects
      // the streaming compile before reading the body, and buffering it works.
      // A body already consumed means the compile itself failed, and retrying
      // it would only replace the real error with a confusing one.
      if (response.bodyUsed) throw error;
    }
  }
  return (await WebAssembly.instantiate(await response.arrayBuffer(), {})).instance;
}

async function instantiate(artifact: PoseidonArtifact): Promise<WebAssembly.Instance> {
  if (typeof artifact === "string" || artifact instanceof URL) {
    return instantiateResponse(await fetch(artifact));
  }
  if (artifact instanceof Response) return instantiateResponse(artifact);
  if (artifact instanceof WebAssembly.Module) return WebAssembly.instantiate(artifact, {});
  return (await WebAssembly.instantiate(artifact, {})).instance;
}

/**
 * Loads the compiled hasher from the artifact the caller resolved. Shares the
 * one instance with the default entry point, so a graph holding both hashes
 * through whichever initialized first rather than compiling the module twice.
 * Safe to call more than once and from several callers at once; a failed load
 * is not cached, so a caller can retry.
 */
export async function initializePoseidon(
  artifact: PoseidonArtifact | Promise<PoseidonArtifact>,
): Promise<void> {
  await loadPoseidon(async () => instantiate(await artifact));
}
