import { afterEach, describe, expect, it, vi } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { assemble, ProverClient } from "../../src/prover/index.js";
import { buildProofInputs, type ProverShapesFixture } from "../helpers/prover-vectors.js";

const proverFixture = proverFixtureJson as ProverShapesFixture;

function response(): Response {
  const c = proofFixture.expected.vanilla.uncompressed.cBytes;
  const b = proofFixture.expected.vanilla.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return Response.json({
    proof: {
      ar: g1,
      bs: [
        [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
        [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
      ],
      krs: g1,
    },
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("EdDSA prover rail", () => {
  it("sends the frozen request and converts the valid proof", async () => {
    const shape = proverFixture.expected.rails[0]?.shapes[0];
    if (!shape) throw new Error("missing EdDSA fixture shape");
    const source = buildProofInputs(proverFixture, "eddsa", { inputs: 1, outputs: 1 });
    const assembled = assemble(source.proofInputs, source.spendProofs);
    const fetch = vi.fn((_request: URL | RequestInfo, init?: RequestInit) => {
      expect(JSON.parse(typeof init?.body === "string" ? init.body : "")).toEqual(shape.proverJson);
      return Promise.resolve(response());
    });

    const proof = await new ProverClient({
      url: "https://prover.example.test",
      fetch,
    }).prove(assembled.proverInputs);

    expect(fetch).toHaveBeenCalledOnce();
    expect(proof.commitment).toBeUndefined();
    expect(proofFixture.expected.vanilla.rail).toBe("eddsa");
  });

  it("retries transport failures at the frozen two-second interval", async () => {
    vi.useFakeTimers();
    const source = buildProofInputs(proverFixture, "eddsa", { inputs: 1, outputs: 1 });
    const assembled = assemble(source.proofInputs, source.spendProofs);
    const calls: number[] = [];
    const fetch = vi.fn(() => {
      calls.push(Date.now());
      return calls.length < 3
        ? Promise.reject(new TypeError("connection failed"))
        : Promise.resolve(response());
    });
    const pending = new ProverClient({
      url: "https://prover.example.test",
      fetch,
    }).prove(assembled.proverInputs);
    await vi.runAllTimersAsync();
    await expect(pending).resolves.toBeDefined();

    expect(calls.map((value) => value - (calls[0] ?? value))).toEqual([0, 2_000, 4_000]);
  });

  it("distinguishes abort from request timeout", async () => {
    const source = buildProofInputs(proverFixture, "eddsa", { inputs: 1, outputs: 1 });
    const assembled = assemble(source.proofInputs, source.spendProofs);
    const fetch = vi.fn(
      (_request: URL | RequestInfo, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const prover = new ProverClient({ url: "https://prover.example.test", fetch });
    const controller = new AbortController();
    const aborted = prover.prove(assembled.proverInputs, { signal: controller.signal });
    controller.abort();

    await expect(aborted).rejects.toEqual(expect.objectContaining({ code: "CLIENT_ABORTED" }));
    await expect(prover.prove(assembled.proverInputs, { timeoutMs: 1 })).rejects.toEqual(
      expect.objectContaining({ code: "CLIENT_TIMEOUT" }),
    );
  });
});
