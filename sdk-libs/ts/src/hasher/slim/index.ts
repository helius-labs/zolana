/** Host-supplied Poseidon loading for runtimes that relocate package assets. */
import { loadPoseidon } from "../core.js";

export {
  HasherWasmError,
  isPoseidonInitialized,
  MAX_POSEIDON_INPUTS,
  poseidon,
  resetPoseidonForTests,
} from "../core.js";

/** A string or URL source is fetched; file URLs should be passed as bytes. */
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

/** Loads a caller-resolved artifact into the process-wide shared instance. */
export async function initializePoseidon(
  artifact: PoseidonArtifact | Promise<PoseidonArtifact>,
): Promise<void> {
  await initializePoseidonLazy(async () => artifact);
}

/**
 * Resolves an artifact only if this loader wins the process-wide initialization
 * race. This prevents a losing default package URL from fetching or rejecting
 * after a host has already supplied relocated bytes.
 */
export async function initializePoseidonLazy(
  artifact: () => PoseidonArtifact | Promise<PoseidonArtifact>,
): Promise<void> {
  await loadPoseidon(async () => instantiate(await artifact()));
}
