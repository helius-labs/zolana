import {
  initializePoseidon as initializeFromArtifact,
  initializePoseidonLazy,
  type PoseidonArtifact,
} from "./slim/index.js";

export {
  HasherWasmError,
  isPoseidonInitialized,
  MAX_POSEIDON_INPUTS,
  poseidon,
  resetPoseidonForTests,
} from "./core.js";

async function defaultArtifact(): Promise<PoseidonArtifact> {
  const url = new URL("./poseidon.wasm", import.meta.url);
  if (url.protocol === "file:") {
    if (typeof process === "undefined" || process.getBuiltinModule === undefined) {
      throw new Error("pass the Poseidon WASM bytes when loading from a file URL");
    }
    const fileSystem = process.getBuiltinModule(
      "node:fs/promises",
    ) as typeof import("node:fs/promises");
    return fileSystem.readFile(url);
  }
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load Poseidon WASM (${String(response.status)})`);
  }
  return response;
}

/**
 * Loads the package's sibling WASM asset in Node or a browser. A custom source
 * can be supplied by hosts that relocate package assets.
 */
export async function initializePoseidon(
  artifact?: PoseidonArtifact | Promise<PoseidonArtifact>,
): Promise<void> {
  if (artifact === undefined) {
    await initializePoseidonLazy(defaultArtifact);
  } else {
    await initializeFromArtifact(artifact);
  }
}
