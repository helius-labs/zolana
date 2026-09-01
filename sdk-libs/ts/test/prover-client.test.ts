import { p256 } from "@noble/curves/nist.js";
import { address } from "@solana/kit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import { asField, createDummyTransferInput, createOutput } from "../src/client/prover/assembly.js";
import { ProverClient } from "../src/client/prover/client.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import type { MergeInputs, ProverInputs, TransferInput } from "../src/client/prover/types.js";
import { ProofInputUtxo, createProofOutput } from "../src/transaction/index.js";

const INPUTS: ProverInputs = {
  circuit: "transfer",
  payload: {
    inputs: [],
    outputs: [],
    externalDataHash: asField(0n),
    privateTxHash: asField(0n),
    publicAssets: [asField(0n), asField(0n), asField(0n)],
    publicAmounts: [asField(0n), asField(0n), asField(0n)],
    ringProgramId: asField(0n),
    signerPublicKeyHashes: [asField(0n)],
    allowDummyInputs: asField(1n),
    publishedOutputOwnerPublicKeyHashes: [],
    publicInputHash: asField(0n),
  },
};
const ZERO_POINT = ["0x0", "0x0"];
const STANDARD_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

/** Printed by the Rust test `proof_request_json_matches_the_server_wire_format`. */
const CUSTOM_RING_REQUEST_VECTOR =
  '{"circuitType":"custom-ring","variant":"transfer","publicInputHash":"0x0000000000000000000000000000000000000000000000000000000000000000","privateTxHash":"0x0101010101010101010101010101010101010101010101010101010101010101","txViewingSk":"0x0202020202020202020202020202020202020202020202020202020202020202","ephSk":"0x0303030303030303030303030303030303030303030303030303030303030303","auditorPk":"0x0473103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a64d82c8c99e9d3c45f9245ba9b27982c9aea8ec1db94b19c44795942c0eb22aa32"}';

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
        blinding: bytes(0),
      }),
    ),
    ownerPublicKeyHash: asField(0n),
    userNullifierPublicKey: asField(0n),
    userNullifierSecret: asField(0n),
    externalDataHash: asField(0n),
    privateTxHash: asField(0n),
    allowDummyInputs: asField(1n),
    publicInputHash: asField(0n),
    outputRingDataHash: asField(0n),
    ringProgramId: asField(0n),
  };
}

function dummyTransferInput(): TransferInput {
  const utxo = ProofInputUtxo.dummy(bytes(7));
  return createDummyTransferInput(utxo, 4n, {
    leaf: utxo.nullifier(),
    merkleContext: { treeType: 0, tree: address("11111111111111111111111111111111") },
    lowElement: bytes(1),
    highElement: bytes(2),
    highElementIndex: 1n,
    path: [],
    lowElementIndex: 0n,
    root: bytes(3),
    rootSeq: 0n,
    rootIndex: 0,
  } satisfies NonInclusionProof);
}

async function sentBody(
  send: (prover: ProverClient) => Promise<unknown>,
): Promise<Record<string, unknown>> {
  const raw: string[] = [];
  const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
    raw.push(String(init?.body));
    return new Response(JSON.stringify(STANDARD_PROOF), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  await send(new ProverClient({ url: "https://prover.example", fetch }));
  return JSON.parse(raw[0] ?? "") as Record<string, unknown>;
}

function keysOf(value: unknown): string[] {
  return Object.keys(value as object).sort();
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
        return new Response(JSON.stringify({ jobId: "job-hang" }), {
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
      asyncPoll: { pollIntervalCapMs: 1_000, maxWaitMs: 2_000 },
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
    const deliveries: (string | null)[] = [];
    const urls: URL[] = [];
    const redirects: (RequestRedirect | undefined)[] = [];
    const fetch = vi.fn(async (input: URL | string, init?: RequestInit) => {
      urls.push(new URL(String(input)));
      bodies.push(JSON.parse(String(init?.body)));
      deliveries.push(new Headers(init?.headers).get("X-Sync"));
      redirects.push(init?.redirect);
      return new Response(JSON.stringify(STANDARD_PROOF), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch,
    });

    await prover.proveMerge(mergeInputs());

    expect(bodies).toMatchObject([{ circuitType: "merge" }]);
    expect(deliveries).toEqual(["true"]);
    expect(redirects).toEqual(["error"]);
    expect(urls[0]?.pathname).toBe("/zolana/prove");
    expect(urls[0]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[0]?.searchParams.get("tenant")).toBe("alpha");
  });

  it("encodes the custom-ring request byte for byte like Rust `CustomRingProofRequest::body`", async () => {
    const raw: string[] = [];
    const deliveries: (string | null)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      raw.push(String(init?.body));
      deliveries.push(new Headers(init?.headers).get("X-Sync"));
      return new Response(JSON.stringify(STANDARD_PROOF), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example", fetch });
    // The Rust test's inputs, the auditor key is the P-256 point of the scalar [4; 32].
    const auditorPublicKey = p256.getPublicKey(bytes(4), false);

    await prover.proveCustomRing({
      publicInputHash: bytes(0),
      privateTxHash: bytes(1),
      txViewingSecret: bytes(2),
      ephemeralSecret: bytes(3),
      auditorPublicKey,
    });

    expect(raw[0]).toBe(CUSTOM_RING_REQUEST_VECTOR);
    expect(deliveries).toEqual([null]);
    const body = JSON.parse(raw[0] ?? "") as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "auditorPk",
      "circuitType",
      "ephSk",
      "privateTxHash",
      "publicInputHash",
      "txViewingSk",
      "variant",
    ]);
    expect(body["circuitType"]).toBe("custom-ring");
    expect(body["variant"]).toBe("transfer");
    expect(body["auditorPk"]).toHaveLength(132);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRing({
          publicInputHash: bytes(0),
          privateTxHash: bytes(1),
          txViewingSecret: bytes(2),
          ephemeralSecret: bytes(3),
          auditorPublicKey,
        }),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_P256_KEY" });
    }
    expect(raw).toHaveLength(1);
  });

  it("pins the merge request keys to the Go `MergeParametersJSON` tags", async () => {
    const body = await sentBody((prover) =>
      prover.proveMerge({ ...mergeInputs(), inputs: [dummyTransferInput()] }),
    );
    const [input] = body["inputs"] as unknown[];

    expect(keysOf(body)).toEqual(
      [
        "circuitType",
        "inputs",
        "output",
        "asset",
        "ownerPkHash",
        "userNullifierPk",
        "userNullifierSecret",
        "externalDataHash",
        "privateTxHash",
        "publicInputHash",
        "allowDummyInputs",
        "outputRingDataHash",
        "ringProgramId",
      ].sort(),
    );
    expect(keysOf(input)).toEqual(
      [
        "domain",
        "amount",
        "blinding",
        "ringDataHash",
        "statePathElements",
        "statePathIndex",
        "nullifierLowValue",
        "nullifierNextValue",
        "nullifierLowPathElements",
        "nullifierLowPathIndex",
        "utxoTreeRoot",
        "nullifierTreeRoot",
        "nullifier",
      ].sort(),
    );
    expect(keysOf(body["output"])).toEqual(["ringDataHash", "hash"].sort());
  });

  it("pins the transfer request keys to the Go `TransferParametersJSON` tags", async () => {
    const body = await sentBody((prover) =>
      prover.prove({
        ...INPUTS,
        payload: {
          ...INPUTS.payload,
          inputs: [dummyTransferInput()],
          outputs: [mergeInputs().output],
        },
      }),
    );
    const [input] = body["inputs"] as Record<string, unknown>[];
    const [output] = body["outputs"] as unknown[];

    expect(keysOf(body)).toEqual(
      [
        "circuitType",
        "nInputs",
        "nOutputs",
        "inputs",
        "outputs",
        "externalDataHash",
        "privateTxHash",
        "publicAssets",
        "publicAmounts",
        "ringProgramId",
        "signerPkHashes",
        "allowDummyInputs",
        "publishedOutputOwnerPkHashes",
        "publicInputHash",
      ].sort(),
    );
    expect(keysOf(input)).toEqual(
      [
        "utxo",
        "isDummy",
        "statePathElements",
        "statePathIndex",
        "nullifierLowValue",
        "nullifierNextValue",
        "nullifierLowPathElements",
        "nullifierLowPathIndex",
        "utxoTreeRoot",
        "nullifierTreeRoot",
        "nullifier",
        "ownerPkHash",
        "nullifierSecret",
      ].sort(),
    );
    expect(keysOf(output)).toEqual(
      ["utxo", "isDummy", "hash", "ownerPkHash", "nullifierPk"].sort(),
    );
    expect(keysOf(input?.["utxo"])).toEqual(
      [
        "domain",
        "owner",
        "asset",
        "amount",
        "blinding",
        "dataHash",
        "ringDataHash",
        "ringProgramId",
      ].sort(),
    );
  });

  it("queues a transfer after sync admission is refused", async () => {
    const deliveries: (string | null)[] = [];
    const refusal = new Response("busy", { status: 429 });
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      if (init?.method === "POST") {
        deliveries.push(new Headers(init.headers).get("X-Sync"));
        if (deliveries.length === 1) return refusal;
        return new Response(JSON.stringify({ jobId: "job-123" }), {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ status: "completed", result: STANDARD_PROOF }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example", fetch });

    await prover.prove(INPUTS);

    expect(deliveries).toEqual(["true", null]);
    expect(refusal.bodyUsed).toBe(true);
  });

  it("reads the served circuits from the health endpoint", async () => {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      urls.push(new URL(input));
      return new Response(
        JSON.stringify({ circuits: ["transfer-ring", "custom-ring"], status: "ok" }),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example/base?tenant=alpha", fetch });
    const health = await prover.health();
    expect(health).toEqual({ status: "ok", circuits: ["transfer-ring", "custom-ring"] });
    expect(urls[0]?.pathname).toBe("/base/health");
    expect(urls[0]?.searchParams.get("tenant")).toBe("alpha");
  });

  it("preserves endpoint queries when polling a queued proof", async () => {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      const url = new URL(String(input));
      urls.push(url);
      return urls.length === 1
        ? new Response(JSON.stringify({ jobId: "job-123" }), {
            status: 202,
            headers: { "content-type": "application/json" },
          })
        : new Response(JSON.stringify({ status: "completed", result: STANDARD_PROOF }), {
            headers: { "content-type": "application/json" },
          });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch,
    });

    await prover.prove(INPUTS);

    expect(urls.map((url) => url.pathname)).toEqual(["/zolana/prove", "/zolana/prove/status"]);
    expect(urls[1]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[1]?.searchParams.get("tenant")).toBe("alpha");
    expect(urls[1]?.searchParams.get("jobId")).toBe("job-123");
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

    const converted = createDummyTransferInput(input, 4n, proof);
    const utxo = converted.circuit;

    expect({ ...converted }.circuit).toBe(converted.circuit);
    expect(converted.ownerPublicKeyHash).toBe(0n);
    expect(utxo).toEqual({
      domain: 1n,
      owner: 0n,
      asset: 0n,
      amount: 0n,
      blinding: BigInt(`0x${"07".repeat(32)}`),
      dataHash: 0n,
      ringDataHash: 0n,
      ringProgramId: 0n,
    });
  });
});
