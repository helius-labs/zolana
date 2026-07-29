import { address } from "@solana/kit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import {
  circuitUtxo,
  createDummyTransferInput,
  createOutput,
} from "../src/client/prover/assembly.js";
import { ProverClient } from "../src/client/prover/client.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import type { MergeInputs, ProverInputs } from "../src/client/prover/types.js";
import { ProofInputUtxo, createProofOutput } from "../src/transaction/index.js";

const INPUTS = {
  circuit: "transfer",
  payload: {
    inputs: [],
    outputs: [],
    externalDataHash: 0n,
    privateTxHash: 0n,
    publicAssets: [0n, 0n, 0n],
    publicAmounts: [0n, 0n, 0n],
    zoneProgramId: 0n,
    payerPublicKeyHash: 0n,
    allowDummyInputs: 1n,
    publicInputHash: 0n,
  },
} as unknown as ProverInputs;
const ZERO_POINT = ["0x0", "0x0"];
const STANDARD_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function mergeInputs(): MergeInputs {
  return {
    inputs: [],
    output: createOutput(
      createProofOutput({
        asset: address("11111111111111111111111111111111"),
        amount: 0n,
        blinding: new Uint8Array(32) as never,
      }),
    ),
    ownerPublicKeyHash: 0n,
    userNullifierPublicKey: 0n,
    userNullifierSecret: 0n,
    externalDataHash: 0n,
    privateTxHash: 0n,
    allowDummyInputs: 1n,
    publicInputHash: 0n,
    outputZoneDataHash: 0n,
    zoneProgramId: 0n,
  } as unknown as MergeInputs;
}

describe("queued prover polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("applies maxWaitMs to a status request that never answers", async () => {
    let request = 0;
    const redirects: (RequestRedirect | undefined)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit): Promise<Response> => {
      request++;
      redirects.push(init?.redirect);
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
    expect(redirects).toEqual(["error", "error"]);
  });
});

describe("prover request routing", () => {
  it("routes merge through its canonical circuit type", async () => {
    const bodies: unknown[] = [];
    const redirects: (RequestRedirect | undefined)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)));
      redirects.push(init?.redirect);
      return new Response(JSON.stringify(STANDARD_PROOF), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "http://127.0.0.1:3001", fetch });

    await prover.proveMerge(mergeInputs());

    expect(bodies).toMatchObject([{ circuitType: "merge" }]);
    expect(redirects).toEqual(["error"]);
  });
});

describe("dummy prover inputs", () => {
  it("zeroes every inert UTXO field except blinding", () => {
    const input = ProofInputUtxo.dummy(bytes(7));
    const proof = {
      leaf: input.nullifier(),
      merkleContext: {
        treeType: 0,
        tree: address("11111111111111111111111111111111"),
      },
      lowElement: bytes(1),
      highElement: bytes(2),
      highElementIndex: 1n,
      path: [],
      lowElementIndex: 0n,
      root: bytes(3),
      rootSeq: 0n,
      rootIndex: 0,
    } as NonInclusionProof;

    const utxo = circuitUtxo(createDummyTransferInput(input, 4n, proof, 5n));

    expect(utxo).toEqual({
      domain: 1n,
      owner: 0n,
      asset: 0n,
      amount: 0n,
      blinding: BigInt(`0x${"07".repeat(32)}`),
      dataHash: 0n,
      zoneDataHash: 0n,
      zoneProgramId: 0n,
    });
  });
});
