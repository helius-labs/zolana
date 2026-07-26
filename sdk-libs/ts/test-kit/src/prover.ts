import { TestKitError } from "./error.js";

export interface TestProver {
  readonly fetch: typeof globalThis.fetch;
  requests(): readonly unknown[];
  enqueue(result: unknown): void;
}

export function createTestProver(): TestProver {
  const queued: unknown[] = [];
  const requests: unknown[] = [];
  const testFetch = (input: URL | string | Request, init?: RequestInit): Promise<Response> => {
    if (init?.signal?.aborted) throw new TestKitError("TEST_KIT_ABORTED");
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.pathname === "/health") return Promise.resolve(Response.json({ status: "ok" }));
    if (queued.length === 0) {
      return Promise.resolve(Response.json({ error: "no queued proof" }, { status: 503 }));
    }
    if (typeof init?.body !== "string") {
      throw new TestKitError("TEST_KIT_FIXTURE", {
        details: { reason: "proverBody" },
      });
    }
    requests.push(JSON.parse(init.body) as unknown);
    return Promise.resolve(Response.json(queued.shift()));
  };
  return Object.freeze({
    fetch: testFetch,
    requests: () => structuredClone(requests),
    enqueue: (result: unknown) => queued.push(structuredClone(result)),
  });
}
