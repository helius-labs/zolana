/**
 * Local proving in the browser, wired into the SDK without patching it.
 *
 * `ProverClient` takes an injectable `fetch`, and the wasm module's `prove`
 * accepts and returns exactly the JSON a `POST /prove` exchange uses (it mirrors
 * `server.processProofSync`). So the whole integration is a `fetch` that
 * recognizes the prover URL and answers it from wasm instead of the network.
 * Everything else -- indexer calls, Solana RPC -- falls through untouched.
 *
 * Why not mopro: its gnark adapter is `#[cfg(not(target_arch = "wasm32"))]`
 * because it binds Go gnark through cgo, and its wasm-capable adapters are
 * circom/halo2/noir only. Zolana's circuits are gnark, so browser proving has to
 * use gnark's own js/wasm target. mopro remains the right tool on iOS/Android,
 * where that cgo path does work.
 */

import type { Measurement } from "./bench.js";
import { keyForProveRequest, type ShapeKey } from "./shapes.js";

/** Messages the worker understands. Mirrored by `prover.worker.ts`. */
export type WorkerRequest =
  | Readonly<{ id: number; kind: "init"; wasmUrl: string }>
  | Readonly<{ id: number; kind: "loadKey"; fileName: string; key: ArrayBuffer }>
  | Readonly<{ id: number; kind: "prove"; body: string }>
  | Readonly<{ id: number; kind: "loadedKeys" }>;

/**
 * `Omit` over a union collapses to the union's common keys, which would erase
 * every request's payload. Distribute it so each member keeps its own fields.
 */
type WithoutId<T> = T extends unknown ? Omit<T, "id"> : never;

export type WorkerResponse = Readonly<{
  id: number;
  ok: boolean;
  /** Present when ok; shape depends on the request kind. */
  value?: unknown;
  error?: string;
  /** Time spent inside the worker, so the page reports proving cost honestly. */
  ms: number;
}>;

export interface WasmProverOptions {
  /** URL of `zolana-prover.wasm` (built by `build_prover_wasm.sh`). */
  readonly wasmUrl: string;
  /** Base URL proving keys are fetched from, e.g. the CloudFront prefix. */
  readonly keyBaseUrl: string;
  /** The prover URL handed to the SDK; requests to it are intercepted. */
  readonly proverUrl: string;
  readonly fetch?: typeof globalThis.fetch;
  /** Called for each timed worker operation so the UI can chart it. */
  readonly onMeasurement?: (measurement: Measurement) => void;
}

export class WasmProverError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WasmProverError";
  }
}

/**
 * Owns the worker, the key cache, and the `fetch` shim.
 *
 * Proving keys are cached in the Cache API rather than memory: they are 8-37 MB
 * each and immutable (the lockfile pins their sha256 and the CloudFront prefix
 * is version-hashed), so re-downloading one per page load is pure waste.
 */
export class WasmProver {
  #worker: Worker | undefined;
  #manifest: Promise<ReadonlyMap<string, KeyDigest>> | undefined;
  #nextId = 1;
  readonly #pending = new Map<
    number,
    Readonly<{ resolve: (value: WorkerResponse) => void; reject: (error: unknown) => void }>
  >();
  readonly #loaded = new Set<string>();
  readonly #options: WasmProverOptions;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: WasmProverOptions) {
    this.#options = options;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Starts the worker and instantiates the module.
   *
   * The module must run in a worker: Go's js/wasm runtime shares the thread it
   * is instantiated on, and `groth16.Prove` blocks for seconds, so on the main
   * thread it would freeze the page for the whole proof.
   */
  async start(source: Worker | (() => Worker)): Promise<void> {
    if (this.#worker !== undefined) return;
    // Takes a Worker (or a factory), not a URL: a bundler's worker import gives
    // back a constructor, and stringifying that into a URL yields a worker that
    // silently fails to load.
    const worker = typeof source === "function" ? source() : source;
    worker.addEventListener("message", (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      const pending = this.#pending.get(response.id);
      if (pending === undefined) return;
      this.#pending.delete(response.id);
      pending.resolve(response);
    });
    worker.addEventListener("error", (event) => {
      // A module worker that fails to load fires `error` with no message at all,
      // so fall back to something a reader can act on rather than "undefined".
      const detail =
        event.message !== "" && event.message !== undefined
          ? event.message
          : `failed to load${event.filename === "" ? "" : ` (${event.filename})`}` +
            " -- check the worker entry resolves and the browser console for the cause";
      const failure = new WasmProverError(`prover worker failed: ${detail}`);
      for (const [, pending] of this.#pending) pending.reject(failure);
      this.#pending.clear();
    });
    this.#worker = worker;

    await this.#call(
      { kind: "init", wasmUrl: this.#options.wasmUrl },
      "wasm-init",
    );
  }

  /** Downloads (or reads from cache) and deserializes one shape's proving key. */
  async ensureKey(shape: ShapeKey): Promise<void> {
    if (this.#loaded.has(shape.keyFile)) {
      // Reported rather than returned silently: a second sweep would otherwise
      // show a passing run with no steps, which reads as a lost measurement.
      this.#options.onMeasurement?.({
        step: "key-load",
        ms: 0,
        bytes: shape.keyBytes,
        note: `${shape.keyFile} already deserialized in this instance`,
      });
      return;
    }

    const url = `${this.#options.keyBaseUrl.replace(/\/+$/u, "")}/${shape.keyFile}`;
    const started = performance.now();
    const key = await this.#fetchKey(url, shape);
    this.#options.onMeasurement?.({
      step: "key-fetch",
      ms: performance.now() - started,
      bytes: key.byteLength,
      note: shape.keyFile,
    });

    const response = await this.#call(
      { kind: "loadKey", fileName: shape.keyFile, key },
      "key-load",
      [key],
    );
    const info = response.value as
      | Readonly<{ key?: string; nbPublic?: number; nbSecret?: number }>
      | undefined;
    this.#options.onMeasurement?.({
      step: "key-load",
      ms: response.ms,
      bytes: shape.keyBytes,
      // The constraint system's variable count is what a witness-size mismatch is
      // measured against, so it belongs next to the key that supplied it.
      note:
        info?.nbPublic === undefined
          ? shape.keyFile
          : `${shape.keyFile} as ${String(info.key)} nbPublic=${String(info.nbPublic)} nbSecret=${String(info.nbSecret)}`,
    });
    this.#loaded.add(shape.keyFile);
  }

  /**
   * The digests `just poc-keys` copied out of `proving-keys.lock`.
   *
   * Fetched once and required: a key rotation changes every size and digest, and
   * validating against anything other than the lockfile lets a stale key through.
   * That is not a theoretical failure -- a same-shape key from an older rotation
   * deserializes cleanly and only surfaces as `groth16.Prove` reporting a witness
   * size mismatch, which reads as a malformed request rather than a bad key.
   */
  async #keyManifest(): Promise<ReadonlyMap<string, KeyDigest>> {
    this.#manifest ??= (async () => {
      const url = `${this.#options.keyBaseUrl.replace(/\/+$/u, "")}/manifest.json`;
      const response = await this.#fetch(url);
      if (!response.ok) {
        throw new WasmProverError(
          `proving-key manifest ${url} is missing (${String(response.status)}). Run \`just poc-keys\`.`,
        );
      }
      const parsed = (await response.json()) as Record<string, KeyDigest>;
      return new Map(Object.entries(parsed));
    })();
    return await this.#manifest;
  }

  async #fetchKey(url: string, shape: ShapeKey): Promise<ArrayBuffer> {
    const manifest = await this.#keyManifest();
    const expected = manifest.get(shape.keyFile);
    if (expected === undefined) {
      throw new WasmProverError(
        `${shape.keyFile} is not in the proving-key manifest; run \`just poc-keys\``,
      );
    }

    const cacheName = "zolana-proving-keys";
    const cacheable = typeof globalThis.caches === "object";
    if (cacheable) {
      const cache = await globalThis.caches.open(cacheName);
      const hit = await cache.match(url);
      if (hit !== undefined) {
        const cached = await hit.arrayBuffer();
        if (await matchesDigest(cached, expected)) return cached;
        // Written before a rotation: same shape, different circuit. Evict rather
        // than prove against it.
        await cache.delete(url);
      }
    }

    const response = await this.#fetch(url);
    if (!response.ok) {
      throw new WasmProverError(
        `fetching proving key ${url} failed: ${String(response.status)} ${response.statusText}`,
      );
    }
    const bytes = await response.arrayBuffer();
    if (!(await matchesDigest(bytes, expected))) {
      const actual = await sha256Hex(bytes);
      throw new WasmProverError(
        `proving key ${shape.keyFile} does not match the lockfile: got ` +
          `${String(bytes.byteLength)} bytes sha256=${actual.slice(0, 16)}..., expected ` +
          `${String(expected.size)} bytes sha256=${expected.sha256.slice(0, 16)}.... ` +
          "Re-run `just poc-keys` after a rebase; the pinned key version moves with it.",
      );
    }
    if (cacheable) {
      const cache = await globalThis.caches.open(cacheName);
      await cache.put(url, new Response(bytes.slice(0)));
    }
    return bytes;
  }

  /**
   * A `fetch` for `ZolanaClientConfig.fetch`. Prover requests are answered from
   * wasm; everything else is delegated, so one shim covers the whole client.
   */
  createFetch(): typeof globalThis.fetch {
    const proverPath = new URL(this.#options.proverUrl);
    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = requestUrl(input);
      const isProve =
        url !== undefined && url.origin === proverPath.origin && url.pathname.endsWith("/prove");
      if (!isProve) return await this.#fetch(input as RequestInfo, init);

      const body = await readBody(input, init);
      if (body === undefined) {
        throw new WasmProverError("intercepted a prove request with no body");
      }
      // Load the key the request actually needs. Predicting the shape ahead of
      // time is unreliable -- the protocol picks it from the real input/output
      // counts -- so read it off the request, exactly as the server's
      // LazyKeyManager does.
      const shape = requestShape(body);
      // The variable-length arrays are what set the witness size, and gnark
      // reports only a total. Record them so a size mismatch names the culprit.
      this.#options.onMeasurement?.({
        step: "transfer-prove",
        ms: 0,
        note: `request ${describeRequest(body)}`,
      });
      if (shape !== undefined) {
        try {
          await this.ensureKey(shape);
        } catch (cause) {
          return proverErrorResponse(
            `loading ${shape.keyFile}: ${cause instanceof Error ? cause.message : String(cause)}`,
            this.#options.onMeasurement,
          );
        }
      }

      const response = await this.#call({ kind: "prove", body }, "prove");
      this.#options.onMeasurement?.({
        step: "transfer-prove",
        ms: response.ms,
        note: response.ok
          ? `wasm groth16.Prove, single-threaded${shape === undefined ? "" : ` (${shape.label})`}`
          : `wasm prove failed: ${response.error ?? "unknown"}`,
      });
      if (!response.ok) {
        // Parked where a console one-liner can retrieve it. A witness-size
        // mismatch is only diagnosable by diffing the request against a
        // known-good one, and a 12 KB body is not something to read off a page.
        (globalThis as { __lastProveRequest?: string }).__lastProveRequest = body;
        console.error(
          `[wasm prover] ${response.error ?? "unknown"}\n` +
            `  ${describeRequest(body)} bodyBytes=${String(body.length)}\n` +
            "  full request: copy(__lastProveRequest)",
        );
        // The reason has to travel in the body AND in a measurement: the SDK
        // reports only the HTTP status, so a bare 500 would reach the UI with no
        // indication of what the prover objected to.
        return proverErrorResponse(
          `${response.error ?? "unknown wasm prover error"} [${describeRequest(body)}]`,
        );
      }
      return new Response(String(response.value), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
  }

  async loadedKeys(): Promise<readonly string[]> {
    const response = await this.#call({ kind: "loadedKeys" }, "loadedKeys");
    const value = response.value;
    if (typeof value === "object" && value !== null && "keys" in value) {
      const keys = (value as { keys?: unknown }).keys;
      if (Array.isArray(keys)) return keys.map(String);
    }
    return [];
  }

  terminate(): void {
    this.#worker?.terminate();
    this.#worker = undefined;
    this.#loaded.clear();
    for (const [, pending] of this.#pending) {
      pending.reject(new WasmProverError("prover worker terminated"));
    }
    this.#pending.clear();
  }

  async #call(
    request: WithoutId<WorkerRequest>,
    label: string,
    transfer: readonly Transferable[] = [],
  ): Promise<WorkerResponse> {
    const worker = this.#worker;
    if (worker === undefined) {
      throw new WasmProverError(`${label}: prover worker is not started`);
    }
    const id = this.#nextId++;
    const response = await new Promise<WorkerResponse>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      worker.postMessage({ ...request, id }, transfer as Transferable[]);
    });
    // `prove` failures are returned to the caller so they can become a 500;
    // every other failure is a setup problem and should throw.
    if (!response.ok && request.kind !== "prove") {
      throw new WasmProverError(`${label}: ${response.error ?? "unknown worker error"}`);
    }
    return response;
  }
}

function requestUrl(input: RequestInfo | URL): URL | undefined {
  try {
    if (typeof input === "string") return new URL(input);
    if (input instanceof URL) return input;
    return new URL(input.url);
  } catch {
    return undefined;
  }
}

async function readBody(input: RequestInfo | URL, init?: RequestInit): Promise<string | undefined> {
  if (typeof init?.body === "string") return init.body;
  if (input instanceof Request) return await input.clone().text();
  return undefined;
}

/** One entry of `keys/manifest.json`, copied from `proving-keys.lock`. */
export interface KeyDigest {
  readonly size: number;
  readonly sha256: string;
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function matchesDigest(bytes: ArrayBuffer, expected: KeyDigest): Promise<boolean> {
  // Size first: it is free and rejects the common case (a dev server with no keys
  // staged answers 200 with its SPA fallback HTML) without hashing megabytes.
  if (bytes.byteLength !== expected.size) return false;
  return (await sha256Hex(bytes)) === expected.sha256;
}

/** Circuit type and shape declared by a `/prove` request body. */
function requestShape(body: string): ShapeKey | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const request = parsed as Record<string, unknown>;
    const circuitType = request["circuitType"];
    const inputs = request["nInputs"];
    const outputs = request["nOutputs"];
    if (typeof circuitType !== "string") return undefined;
    return keyForProveRequest(circuitType, Number(inputs), Number(outputs));
  } catch {
    return undefined;
  }
}

/**
 * A 500 carrying the reason, so the SDK's prover error path handles it as a
 * server rejection rather than a retryable transport fault.
 */
function proverErrorResponse(
  message: string,
  onMeasurement?: (measurement: Measurement) => void,
): Response {
  onMeasurement?.({ step: "transfer-prove", ms: 0, note: `wasm prover: ${message}` });
  // Logged as well: the page shows one measurement at a time, and a sweep can
  // move past this before anyone reads it.
  console.error(`[wasm prover] ${message}`);
  return new Response(JSON.stringify({ code: "wasm_prover_error", message }), {
    status: 500,
    headers: { "content-type": "application/json" },
  });
}

/** Shape and array lengths declared by a `/prove` request, for diagnosis. */
function describeRequest(body: string): string {
  try {
    const r = JSON.parse(body) as Record<string, unknown>;
    const len = (key: string): string => {
      const value = r[key];
      return Array.isArray(value) ? String(value.length) : "-";
    };
    return (
      `${String(r["circuitType"])} ${String(r["nInputs"])}x${String(r["nOutputs"])} ` +
      `in=${len("inputs")} out=${len("outputs")} pubAssets=${len("publicAssets")} ` +
      `pubAmounts=${len("publicAmounts")} signers=${len("signerPkHashes")} ` +
      `outOwners=${len("publishedOutputOwnerPkHashes")}`
    );
  } catch {
    return "unparseable";
  }
}
