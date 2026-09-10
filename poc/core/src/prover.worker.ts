/// <reference lib="webworker" />
/**
 * Hosts the Go wasm proving instance off the main thread.
 *
 * Mopro runs FFTs and MSMs on a Rayon worker pool. Go's
 * js/wasm runtime occupies whichever thread instantiated it, so this has to be a
 * worker. Every operation is timed here rather than on the page so the reported
 * proving cost excludes postMessage and structured-clone overhead.
 */

// The Go runtime shim, vendored here by build_prover_wasm.sh from the same
// toolchain that built the .wasm (its js/wasm ABI is not stable across Go
// releases, so the two must ship together).
//
// A static import rather than a runtime load, because the alternatives are all
// worse: `importScripts` is present in a module worker but throws when called,
// and Vite refuses to `import()` a path under public/. Bundling it means
// `globalThis.Go` is assigned before init() runs.
import "./vendor/wasm_exec.js";

import type { WorkerRequest, WorkerResponse } from "./wasm-prover.js";

/** The API `cmd/prover-wasm` installs on `globalThis`. */
interface ZolanaProverApi {
  loadKey(fileName: string, key: Uint8Array): unknown;
  prove(requestJson: string): unknown;
  loadedKeys(): unknown;
  verify(requestJson: string, proofJson: string): unknown;
}

declare const __zolanaProver: ZolanaProverApi | undefined;

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

let api: ZolanaProverApi | undefined;
let activeThreads = 0;

async function init(wasmUrl: string, threads: number): Promise<void> {
  if (api !== undefined) return;

  if (!Number.isInteger(threads) || threads < 0 || threads > 64) {
    throw new Error("Threads must be an integer between 0 and 64");
  }
  if (threads > 0) {
    if (!globalThis.crossOriginIsolated) throw new Error("Threaded proving requires cross-origin isolation. Use the Vite server with COOP/COEP headers.");
    const kernelUrl = new URL("./accelerator/gnark_kernel.js", new URL(wasmUrl, self.location.href)).href;
    const kernel = await import(/* @vite-ignore */ kernelUrl);
    await kernel.default();
    await kernel.initThreadPool(threads);
    Object.assign(globalThis, { __moproGnarkKernel: kernel.Key });
    activeThreads = threads;
  }

  const ready = new Promise<void>((resolve) => {
    (globalThis as unknown as { __zolanaProverReady: () => void }).__zolanaProverReady = resolve;
  });

  const GoCtor = (globalThis as unknown as { Go?: new () => GoRuntime }).Go;
  if (GoCtor === undefined) {
    throw new Error("the vendored wasm_exec.js did not define globalThis.Go");
  }
  const go = new GoCtor();

  const response = await fetch(wasmUrl);
  if (!response.ok) {
    throw new Error(`fetching ${wasmUrl} failed: ${String(response.status)}`);
  }
  const { instance } = await WebAssembly.instantiateStreaming(response, go.importObject);

  // Deliberately not awaited: the Go main blocks forever to keep its exported
  // callbacks alive, so this promise only settles when the instance dies.
  void go.run(instance).catch((error: unknown) => {
    console.error("zolana prover instance exited", error);
    api = undefined;
  });

  await ready;
  if (typeof __zolanaProver === "undefined") {
    throw new Error("prover module ran but did not install __zolanaProver");
  }
  api = __zolanaProver;
}

function requireApi(): ZolanaProverApi {
  if (api === undefined) throw new Error("prover module is not initialized; send init first");
  return api;
}

/**
 * The wasm side returns `{ error }` on failure instead of throwing, so a bad
 * request cannot tear down the instance. Unwrap that into the worker protocol.
 */
function unwrap(result: unknown): unknown {
  if (typeof result === "object" && result !== null && "error" in result) {
    const message = (result as { error?: unknown }).error;
    throw new Error(typeof message === "string" ? message : "prover returned an error");
  }
  return result;
}

async function handle(request: WorkerRequest): Promise<unknown> {
  switch (request.kind) {
    case "init":
      await init(request.wasmUrl, request.threads);
      return { initialized: true, threads: activeThreads };
    case "loadKey":
      return unwrap(requireApi().loadKey(request.fileName, new Uint8Array(request.key)));
    case "prove": {
      const result = unwrap(requireApi().prove(request.body)) as { proof?: unknown };
      // The page rebuilds an HTTP response from this, so hand back the exact
      // JSON string the prover server would have sent.
      return result.proof;
    }
    case "verify":
      return unwrap(requireApi().verify(request.body, request.proof));
    case "loadedKeys":
      return unwrap(requireApi().loadedKeys());
  }
}

let queue = Promise.resolve();
self.addEventListener("message", (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  const started = performance.now();
  queue = queue.then(() => handle(request)).then(
    (value) => {
      const response: WorkerResponse = {
        id: request.id,
        ok: true,
        value,
        ms: performance.now() - started,
      };
      self.postMessage(response);
    },
    (error: unknown) => {
      const response: WorkerResponse = {
        id: request.id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        ms: performance.now() - started,
      };
      self.postMessage(response);
    },
  );
});
