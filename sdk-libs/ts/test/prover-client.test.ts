import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import { ProverClient } from "../src/client/prover/client.js";
import type { ProverInputs } from "../src/client/prover/types.js";

const INPUTS = {
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

describe("queued prover polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("applies maxWaitMs to a status request that never answers", async () => {
    let request = 0;
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit): Promise<Response> => {
      request++;
      if (request === 1) {
        return new Response(JSON.stringify({ job_id: "job-hang" }), {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      }
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      url: "http://127.0.0.1:3001",
      fetch,
      asyncPoll: { pollIntervalMs: 1_000, maxWaitMs: 2_000 },
    });

    const settled = prover.prove(INPUTS);
    let rejected = false;
    const assertion = settled.catch((error: unknown) => {
      rejected = true;
      expect(error).toBeInstanceOf(ClientError);
      expect((error as ClientError).code).toBe("CLIENT_PROVER_TIMEOUT");
    });
    await vi.advanceTimersByTimeAsync(2_001);
    await assertion;
    expect(rejected).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
