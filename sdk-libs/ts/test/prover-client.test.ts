import { p256 } from "@noble/curves/nist.js";
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
    signerPublicKeyHashes: [0n],
    allowDummyInputs: 1n,
    publishedOutputOwnerPublicKeyHashes: [],
    publicInputHash: 0n,
  },
} as unknown as ProverInputs;
const ZERO_POINT = ["0x0", "0x0"];
const STANDARD_PROOF = {
  ar: ZERO_POINT,
  bs: [ZERO_POINT, ZERO_POINT],
  krs: ZERO_POINT,
};

/** Printed by the Rust test `audit_request_json_matches_the_server_wire_format`. */
const AUDIT_REQUEST_VECTOR =
  '{"circuitType":"custom-ring-audit","variant":"transfer","publicInputHash":"0x0000000000000000000000000000000000000000000000000000000000000000","privateTxHash":"0x0101010101010101010101010101010101010101010101010101010101010101","txViewingSk":"0x0202020202020202020202020202020202020202020202020202020202020202","ephSk":"0x0303030303030303030303030303030303030303030303030303030303030303","auditorPk":"0x0473103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a64d82c8c99e9d3c45f9245ba9b27982c9aea8ec1db94b19c44795942c0eb22aa32"}';

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
    const urls: URL[] = [];
    const redirects: (RequestRedirect | undefined)[] = [];
    const fetch = vi.fn(async (input: URL | string, init?: RequestInit) => {
      urls.push(new URL(String(input)));
      bodies.push(JSON.parse(String(init?.body)));
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
    expect(redirects).toEqual(["error"]);
    expect(urls[0]?.pathname).toBe("/zolana/prove");
    expect(urls[0]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[0]?.searchParams.get("tenant")).toBe("alpha");
  });

  it("encodes the audit request byte for byte like Rust `AuditProofRequest::body`", async () => {
    const raw: string[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      raw.push(String(init?.body));
      return new Response(JSON.stringify(STANDARD_PROOF), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example", fetch });
    // The Rust test's inputs, the auditor key is the P-256 point of the scalar [4; 32].
    const auditorPublicKey = p256.getPublicKey(bytes(4), false);

    await prover.proveCustomRingAudit({
      publicInputHash: bytes(0),
      privateTxHash: bytes(1),
      txViewingSecret: bytes(2),
      ephemeralSecret: bytes(3),
      auditorPublicKey,
    });

    expect(raw[0]).toBe(AUDIT_REQUEST_VECTOR);
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
    expect(body["circuitType"]).toBe("custom-ring-audit");
    expect(body["variant"]).toBe("transfer");
    expect(body["auditorPk"]).toHaveLength(132);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRingAudit({
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

  it("reads the served circuits from the health endpoint", async () => {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      urls.push(new URL(input));
      return new Response(
        JSON.stringify({ circuits: ["transfer-ring", "custom-ring-audit"], status: "ok" }),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example/base?tenant=alpha", fetch });
    const health = await prover.health();
    expect(health).toEqual({ status: "ok", circuits: ["transfer-ring", "custom-ring-audit"] });
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
    const utxo = circuitUtxo(converted);

    expect(converted.ownerPublicKeyHash).toBe(0n);
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
