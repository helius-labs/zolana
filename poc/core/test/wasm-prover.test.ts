import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  WasmProver,
  type WorkerRequest,
  type WorkerResponse,
  type WorkerFatal,
} from "../src/wasm-prover.js";
import type { Measurement } from "../src/bench.js";
import { TRANSFER_SHAPES } from "../src/shapes.js";

const body = JSON.stringify({ circuitType: "transfer-confidential", nInputs: 2, nOutputs: 3 });
const endpoint = "http://localhost:3001/prove";
const key = new Uint8Array([1, 2, 3]);
const factory = () => new Worker("test-worker");

class TestWorker extends EventTarget {
  static instances: TestWorker[] = [];
  static holdInit = false;
  static throwOnPost = false;
  readonly requests: WorkerRequest[] = [];
  terminated = false;
  hold: WorkerRequest["kind"] | undefined;
  constructor() {
    super();
    TestWorker.instances.push(this);
  }
  postMessage(request: WorkerRequest): void {
    if (TestWorker.throwOnPost) throw new Error("postMessage failed");
    this.requests.push(request);
    if (request.kind === this.hold || (request.kind === "init" && TestWorker.holdInit)) return;
    queueMicrotask(() => this.reply(request));
  }
  reply(request: WorkerRequest): void {
    let value: unknown;
    switch (request.kind) {
      case "init":
        value = { threads: 2 };
        break;
      case "loadKey":
        value = { key: request.fileName };
        break;
      case "prove":
        value = '{"proof":"test"}';
        break;
      case "verify":
        value = { valid: true };
        break;
      case "loadedKeys":
        value = { keys: [] };
        break;
    }
    this.message({ id: request.id, ok: true, value, ms: 1 });
  }
  message(data: WorkerResponse | WorkerFatal): void {
    this.dispatchEvent(new MessageEvent("message", { data }));
  }
  crash(): void {
    const event = new Event("error");
    Object.assign(event, { message: "worker crashed" });
    this.dispatchEvent(event);
  }
  terminate(): void {
    this.terminated = true;
  }
}
function current(): TestWorker {
  const worker = TestWorker.instances.at(-1);
  if (worker === undefined) throw new Error("no worker");
  return worker;
}
function request(worker: TestWorker, kind: WorkerRequest["kind"]): WorkerRequest {
  const found = worker.requests.find((value) => value.kind === kind);
  if (found === undefined) throw new Error(`missing ${kind}`);
  return found;
}
function failure(work: Promise<unknown>): Promise<unknown> {
  return work.then(
    () => {
      throw new Error("unexpected success");
    },
    (error: unknown) => error,
  );
}
async function fixture(onMeasurement: (measurement: Measurement) => void = () => {}) {
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", key)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    if (String(input).endsWith("manifest.json")) {
      return Response.json(
        Object.fromEntries(
          TRANSFER_SHAPES.map((shape) => [shape.keyFile, { size: key.length, sha256: digest }]),
        ),
      );
    }
    return new Response(key);
  });
  const prover = new WasmProver({
    wasmUrl: "/prover/test.wasm",
    keyBaseUrl: "/keys",
    proverUrl: "http://localhost:3001",
    onMeasurement,
    fetch,
  });
  return { prover, fetch };
}

beforeEach(() => {
  TestWorker.instances = [];
  TestWorker.holdInit = false;
  TestWorker.throwOnPost = false;
  vi.stubGlobal("Worker", TestWorker);
  vi.stubGlobal("caches", undefined);
});
afterEach(() => vi.unstubAllGlobals());

describe("prover lifecycle", () => {
  it("shares initialization across concurrent starts", async () => {
    const { prover } = await fixture();
    TestWorker.holdInit = true;
    const first = prover.start(factory);
    const second = prover.start(factory);
    expect(first).toBe(second);
    expect(TestWorker.instances).toHaveLength(1);
    current().reply(request(current(), "init"));
    await Promise.all([first, second]);
    expect(prover.threads).toBe(2);
    prover.terminate();
  });

  it.each(["error", "messageerror", "fatal"])(
    "discards state on %s, rejects queued work, and reloads keys on retry",
    async (kind) => {
      const { prover } = await fixture();
      await prover.start(factory);
      await prover.proveRequest(body);
      const old = current();
      old.hold = "prove";
      const pending = failure(prover.proveRequest(body));
      const queued = failure(prover.proveRequest(body));
      await vi.waitFor(() =>
        expect(old.requests.filter((r) => r.kind === "prove")).toHaveLength(2),
      );
      if (kind === "error") old.crash();
      else if (kind === "fatal") old.message({ fatal: true, error: "Go exited" });
      else old.dispatchEvent(new Event("messageerror"));
      expect(await pending).toBeInstanceOf(Error);
      expect(await queued).toBeInstanceOf(Error);
      expect(old.terminated).toBe(true);
      expect(prover.threads).toBe(0);
      await prover.proveRequest(body);
      expect(TestWorker.instances).toHaveLength(2);
      expect(current().requests.filter((r) => r.kind === "loadKey")).toHaveLength(1);
      old.crash();
      old.message({ fatal: true, error: "late error" });
      await prover.proveRequest(body);
      expect(current().terminated).toBe(false);
      prover.terminate();
    },
  );

  it.each(["response", "postMessage"])(
    "cleans up failed initialization (%s) and can start again",
    async (kind) => {
      const { prover } = await fixture();
      TestWorker.holdInit = true;
      TestWorker.throwOnPost = kind === "postMessage";
      const failed = failure(prover.start(factory));
      const old = current();
      if (kind === "response")
        old.message({ id: request(old, "init").id, ok: false, error: "missing Wasm", ms: 0 });
      expect(await failed).toBeInstanceOf(Error);
      expect(old.terminated).toBe(true);
      TestWorker.holdInit = false;
      TestWorker.throwOnPost = false;
      await prover.start(factory);
      await prover.proveRequest(body);
      prover.terminate();
    },
  );

  it("manual termination rejects downloads and does not resurrect the runtime", async () => {
    const { prover, fetch } = await fixture();
    await prover.start(factory);
    fetch.mockImplementation(() => new Promise(() => {}));
    const pending = failure(prover.proveRequest(body));
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    prover.terminate();
    expect(await pending).toBeInstanceOf(Error);
    await expect(prover.proveRequest(body)).rejects.toThrow("not started");
    expect(TestWorker.instances).toHaveLength(1);
  });
});

describe("fetch cancellation", () => {
  it("rejects a pre-aborted signal before any key fetch or worker work", async () => {
    const { prover, fetch } = await fixture();
    const signal = AbortSignal.abort();
    await expect(prover.createFetch()(endpoint, { method: "POST", body, signal })).rejects.toBe(
      signal.reason,
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(TestWorker.instances).toHaveLength(0);
  });

  it("cancels a queued request without terminating active proving", async () => {
    const { prover } = await fixture();
    await prover.start(factory);
    const worker = current();
    worker.hold = "prove";
    const first = prover.proveRequest(body);
    await vi.waitFor(() => expect(worker.requests.some((r) => r.kind === "prove")).toBe(true));
    const controller = new AbortController();
    const queued = failure(
      prover.createFetch()(endpoint, { method: "POST", body, signal: controller.signal }),
    );
    controller.abort();
    expect(await queued).toBe(controller.signal.reason);
    expect(worker.terminated).toBe(false);
    worker.hold = undefined;
    worker.reply(request(worker, "prove"));
    await first;
    await prover.proveRequest(body);
    expect(worker.requests.filter((r) => r.kind === "prove")).toHaveLength(2);
    prover.terminate();
  });

  it.each(["loadKey", "prove", "verify"] as const)(
    "terminates active %s on Request cancellation and reloads after retry",
    async (kind) => {
      const { prover } = await fixture();
      await prover.start(factory);
      const worker = current();
      worker.hold = kind;
      const controller = new AbortController();
      const pending = failure(
        prover.createFetch()(
          new Request(endpoint, { method: "POST", body, signal: controller.signal }),
        ),
      );
      await vi.waitFor(() => expect(worker.requests.some((r) => r.kind === kind)).toBe(true));
      controller.abort();
      expect(await pending).toBe(controller.signal.reason);
      expect(worker.terminated).toBe(true);
      await prover.proveRequest(body);
      expect(TestWorker.instances).toHaveLength(2);
      expect(current().requests.filter((r) => r.kind === "loadKey")).toHaveLength(1);
      prover.terminate();
    },
  );

  it("propagates cancellation to downloads and suppresses late key installation", async () => {
    const { prover, fetch } = await fixture();
    await prover.start(factory);
    const controller = new AbortController();
    const download = Promise.withResolvers<Response>();
    const normalFetch = fetch.getMockImplementation();
    if (normalFetch === undefined) throw new Error("missing fetch implementation");
    let downloadSignal: AbortSignal | null | undefined;
    fetch.mockImplementation(async (input, init) => {
      if (String(input).endsWith(".key")) {
        downloadSignal = init?.signal;
        return download.promise;
      }
      return normalFetch(input, init);
    });
    const pending = failure(
      prover.createFetch()(endpoint, { method: "POST", body, signal: controller.signal }),
    );
    await vi.waitFor(() => expect(downloadSignal).toBeDefined());
    controller.abort();
    expect(await pending).toBe(controller.signal.reason);
    expect(downloadSignal?.aborted).toBe(true);
    fetch.mockImplementation(normalFetch);
    await prover.proveRequest(body);
    download.resolve(new Response(key));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(TestWorker.instances[0]?.requests.some((r) => r.kind === "loadKey")).toBe(false);
    expect(current().requests.filter((r) => r.kind === "loadKey")).toHaveLength(1);
    prover.terminate();
  });

  it.each(["key-fetch", "key-load"])(
    "cannot install stale key state when a %s callback cancels and restarts",
    async (step) => {
      const controller = new AbortController();
      let restarted: Promise<void> | undefined;
      const { prover } = await fixture((measurement) => {
        if (measurement.step === step && !controller.signal.aborted) {
          controller.abort();
          restarted = prover.start(factory);
        }
      });
      await prover.start(factory);
      const error = await failure(prover.proveRequest(body, controller.signal));
      expect(error).toBe(controller.signal.reason);
      await restarted;
      await prover.proveRequest(body);
      expect(TestWorker.instances).toHaveLength(2);
      expect(current().requests.filter((r) => r.kind === "loadKey")).toHaveLength(1);
      prover.terminate();
    },
  );

  it("RequestInit can override a Request's aborted signal", async () => {
    const { prover } = await fixture();
    await prover.start(factory);
    const req = new Request(endpoint, { method: "POST", body, signal: AbortSignal.abort() });
    expect((await prover.createFetch()(req, { signal: null })).status).toBe(200);
    prover.terminate();
  });
});
