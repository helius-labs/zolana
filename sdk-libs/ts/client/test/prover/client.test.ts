import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../../src/error.js";
import { ProverClient } from "../../src/prover/client.js";
import type { ProverInputs } from "../../src/prover/types.js";

/// The eight cases below are the TypeScript counterparts of the `poll_async_*`
/// tests in `sdk-libs/client/src/prover/client.rs`. Each one drives the same
/// status sequence and asserts the same classification, so the two clients
/// agree on which status is final, which is transient, and which job handles
/// are accepted.

const ZERO_POINT = ["0x0", "0x0"];
const GNARK_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

type Reply =
  | Readonly<{ kind: "json"; status: number; body: unknown }>
  | Readonly<{ kind: "text"; status: number; body: string }>
  | Readonly<{ kind: "disconnect" }>
  | Readonly<{ kind: "hang" }>;

interface Recorder {
  readonly fetch: typeof globalThis.fetch;
  readonly paths: string[];
}

function recorder(replies: readonly Reply[]): Recorder {
  const paths: string[] = [];
  let index = 0;
  const fetch = (async (input: URL | string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof URL ? input.href : input);
    paths.push(`${url.pathname}${url.search}`);
    const reply = replies[index++] ?? { kind: "disconnect" as const };
    if (reply.kind === "disconnect") throw new Error("connection reset");
    if (reply.kind === "hang") {
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      });
    }
    const body = reply.kind === "json" ? JSON.stringify(reply.body) : reply.body;
    return new Response(body, {
      status: reply.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { fetch, paths };
}

function client(replies: readonly Reply[]): Readonly<{ prove: () => Promise<unknown> } & Recorder> {
  const recorded = recorder(replies);
  const prover = new ProverClient({
    url: "http://127.0.0.1:3001",
    fetch: recorded.fetch,
    asyncPoll: { pollIntervalMs: 1_000, maxWaitMs: 2_000 },
  });
  // `prove` only reads `circuit`; the request body is never inspected by the
  // recorder, so an empty eddsa payload is enough to reach the poll loop.
  const inputs = {
    circuit: "transfer",
    payload: {
      inputs: [],
      outputs: [],
      externalDataHash: 0n,
      privateTxHash: 0n,
      publicSolAmount: 0n,
      publicSplAmount: 0n,
      publicSplAssetPublicKey: 0n,
      zoneProgramId: 0n,
      payerPublicKeyHash: 0n,
      publicInputHash: 0n,
    },
  } as unknown as ProverInputs;
  return { ...recorded, prove: () => prover.prove(inputs) };
}

async function expectCode(operation: Promise<unknown>, code: string): Promise<void> {
  try {
    await operation;
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("queued prover status polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function run<T>(operation: Promise<T>): Promise<T> {
    // Attach a handler before the timers advance: without it a rejection that
    // lands first is reported as unhandled even though the caller awaits it.
    operation.catch(() => undefined);
    await vi.runAllTimersAsync();
    return operation;
  }

  it("returns the proof nested under a completed result", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-1", status: "queued" } },
      { kind: "json", status: 200, body: { status: "queued" } },
      {
        kind: "json",
        status: 200,
        body: { status: "completed", result: { proof: GNARK_PROOF, proof_duration_ms: 7 } },
      },
    ]);

    const proof = await run(prove());

    expect(paths).toEqual([
      "/prove",
      "/prove/status?job_id=job-1",
      "/prove/status?job_id=job-1",
    ]);
    expect(proof).toMatchObject({ a: new Uint8Array(64) });
    expect((proof as { commitment?: unknown }).commitment).toBeUndefined();
  });

  it("polls immediately rather than waiting one interval first", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-fast" } },
      { kind: "json", status: 200, body: { status: "completed", result: { proof: GNARK_PROOF } } },
    ]);

    const settled = prove();
    // No timer has been advanced, so a first status request can only have gone
    // out if the loop requests before it sleeps, as `poll_async` does.
    await vi.advanceTimersByTimeAsync(0);
    expect(paths).toEqual(["/prove", "/prove/status?job_id=job-fast"]);
    await run(settled);
  });

  it("treats a failed status as final", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-failed" } },
      { kind: "json", status: 200, body: { status: "failed", message: "prover rejected witness" } },
    ]);

    await expectCode(run(prove()), "CLIENT_PROVER_SERVER");
    expect(paths).toEqual(["/prove", "/prove/status?job_id=job-failed"]);
  });

  it("times out after the configured wait", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-slow" } },
      { kind: "json", status: 200, body: { status: "queued" } },
      { kind: "json", status: 200, body: { status: "processing" } },
      { kind: "json", status: 200, body: { status: "processing" } },
    ]);

    await expectCode(run(prove()), "CLIENT_PROVER_TIMEOUT");
    // Two sleeps of one second exhaust the two-second bound, and, as in Rust,
    // the request that follows the last sleep still goes out.
    expect(paths).toHaveLength(4);
  });

  it("fails on a malformed status body", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-bad-json" } },
      { kind: "text", status: 200, body: "not json" },
    ]);

    await expectCode(run(prove()), "CLIENT_PROVER_JSON");
    expect(paths).toEqual(["/prove", "/prove/status?job_id=job-bad-json"]);
  });

  it("rejects a job id that could rewrite the status URL", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-1&job_id=other" } },
    ]);

    await expectCode(run(prove()), "CLIENT_PROVER_JOB");
    expect(paths).toEqual(["/prove"]);
  });

  it("fails fast on a client-error status", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "missing-job" } },
      { kind: "json", status: 404, body: { code: "job_not_found" } },
    ]);

    await expectCode(run(prove()), "CLIENT_PROVER_HTTP");
    expect(paths).toEqual(["/prove", "/prove/status?job_id=missing-job"]);
  });

  it("retries a transient poll failure and a server-error status", async () => {
    const { prove, paths } = client([
      { kind: "json", status: 202, body: { job_id: "job-transient" } },
      { kind: "disconnect" },
      { kind: "json", status: 503, body: { message: "restarting" } },
      { kind: "json", status: 200, body: { status: "completed", result: { proof: GNARK_PROOF } } },
    ]);

    const proof = await run(prove());

    expect(paths).toHaveLength(4);
    expect(proof).toMatchObject({ a: new Uint8Array(64) });
  });

  /// Before the status request carried its own bound, a server that accepted
  /// the connection and never answered held the poll open forever: `maxWaitMs`
  /// is only consulted between attempts, and there was never a next attempt.
  it("bounds a status request that never answers", async () => {
    const { prove } = client([
      { kind: "json", status: 202, body: { job_id: "job-hang" } },
      { kind: "hang" },
    ]);

    const settled = prove();
    const assertion = expectCode(settled, "CLIENT_PROVER_TIMEOUT");
    await vi.advanceTimersByTimeAsync(700_000);
    await assertion;
  });
});
