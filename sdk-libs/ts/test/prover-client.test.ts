import { p256 } from "@noble/curves/nist.js";
import { address } from "@solana/kit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import { asField, createDummyTransferInput, createOutput } from "../src/client/prover/assembly.js";
import { ProverClient } from "../src/client/prover/client.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import { disabledRuleAnswer } from "../src/client/prover/types.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingOpening,
  CustomRingPolicyProofRequest,
  MergeInputs,
  ProverInputs,
  TransferInput,
} from "../src/client/prover/types.js";
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

/** The uncompressed P-256 point of the scalar [4; 32]. */
const AUDITOR_PK_HEX =
  "0x0473103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a64d82c8c99e9d3c45f9245ba9b27982c9aea8ec1db94b19c44795942c0eb22aa32";

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function fieldHex(byte: number): string {
  return `0x${byte.toString(16).padStart(2, "0").repeat(32)}`;
}

function zeroOpening(): CustomRingOpening {
  return {
    domain: bytes(0),
    ownerPkHash: bytes(0),
    nullifierPk: bytes(0),
    asset: bytes(0),
    amount: bytes(0),
    blinding: bytes(0),
    dataHash: bytes(0),
    ringDataHash: bytes(0),
    ringProgramId: bytes(0),
  };
}

/** The Rust wire-format test's request, `the_request_matches_the_server_wire_format`. */
function ringRequest(auditorPublicKey: Uint8Array): CustomRingPolicyProofRequest {
  return {
    publicInputHash: bytes(0),
    privateTxHash: bytes(1),
    txViewingSecret: bytes(2),
    ephemeralSecret: bytes(3),
    auditorPublicKey,
    nIn: 2,
    nOut: 2,
    inputs: Array.from({ length: 5 }, () => zeroOpening()),
    outputs: Array.from({ length: 4 }, () => zeroOpening()),
    addressChain: bytes(0),
    externalDataHash: bytes(6),
    sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: bytes(0) })),
    policyLen: 1,
    rules: Array.from({ length: 16 }, () => bytes(0)),
    inlineAssets: Array.from({ length: 8 }, () => bytes(0)),
    inlineLimits: Array.from({ length: 8 }, () => 0n),
    inlineCount: 0,
    stateRoot: bytes(8),
    nullifierRoot: bytes(9),
    answers: Array.from({ length: 10 }, () => disabledRuleAnswer()),
  };
}

/** The no-policy request, matching Rust `CustomRingBaseProofRequest`. */
function auditRequest(auditorPublicKey: Uint8Array): CustomRingBaseProofRequest {
  return {
    publicInputHash: bytes(0),
    privateTxHash: bytes(1),
    txViewingSecret: bytes(2),
    ephemeralSecret: bytes(3),
    auditorPublicKey,
  };
}

/** Key order from Rust `CustomRingBaseProofRequestJson` in `request_ring.rs`. */
const EXPECTED_AUDIT_BODY = {
  circuitType: "custom-ring-base",
  publicInputHash: fieldHex(0),
  privateTxHash: fieldHex(1),
  txViewingSk: fieldHex(2),
  ephSk: fieldHex(3),
  auditorPk: AUDITOR_PK_HEX,
};

const EXPECTED_OPENING = {
  domain: fieldHex(0),
  ownerPkHash: fieldHex(0),
  nullifierPk: fieldHex(0),
  asset: fieldHex(0),
  amount: fieldHex(0),
  blinding: fieldHex(0),
  dataHash: fieldHex(0),
  ringDataHash: fieldHex(0),
  ringProgramId: fieldHex(0),
};

const EXPECTED_RULE_ANSWER = {
  enabled: false,
  mode: 1,
  listId: 1,
  state: 1,
  absentBranch: 1,
  member: fieldHex(0),
  contentHash: fieldHex(0),
  version: 0,
  low: fieldHex(0),
  next: fieldHex(0),
  nfPathElements: Array.from({ length: 40 }, () => fieldHex(0)),
  nfPathIndex: 0,
  statePathElements: Array.from({ length: 32 }, () => fieldHex(0)),
  statePathIndex: 0,
};

/** Key order from Rust `CustomRingPolicyProofRequestJson` in `request_ring.rs`. */
const EXPECTED_RING_BODY = {
  circuitType: "custom-ring-policy",
  publicInputHash: fieldHex(0),
  privateTxHash: fieldHex(1),
  txViewingSk: fieldHex(2),
  ephSk: fieldHex(3),
  auditorPk: AUDITOR_PK_HEX,
  nIn: 2,
  nOut: 2,
  inputs: Array.from({ length: 5 }, () => EXPECTED_OPENING),
  outputs: Array.from({ length: 4 }, () => EXPECTED_OPENING),
  addressChain: fieldHex(0),
  externalDataHash: fieldHex(6),
  sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: fieldHex(0) })),
  policyLen: 1,
  ruleEnc: Array.from({ length: 16 }, () => fieldHex(0)),
  inlineAssets: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineLimits: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineCount: 0,
  stateRoot: fieldHex(8),
  nullifierRoot: fieldHex(9),
  answers: Array.from({ length: 10 }, () => EXPECTED_RULE_ANSWER),
};

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

  it("encodes the custom-ring request byte for byte like Rust `CustomRingPolicyProofRequest::body`", async () => {
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

    await prover.proveCustomRingPolicy(ringRequest(auditorPublicKey));

    expect(raw[0]).toBe(JSON.stringify(EXPECTED_RING_BODY));
    expect(deliveries).toEqual([null]);
    const body = JSON.parse(raw[0] ?? "") as Record<string, unknown>;
    // The sorted key set of Rust `the_request_matches_the_server_wire_format`.
    expect(Object.keys(body).sort()).toEqual([
      "addressChain",
      "answers",
      "auditorPk",
      "circuitType",
      "ephSk",
      "externalDataHash",
      "inlineAssets",
      "inlineCount",
      "inlineLimits",
      "inputs",
      "nIn",
      "nOut",
      "nullifierRoot",
      "outputs",
      "policyLen",
      "privateTxHash",
      "publicInputHash",
      "ruleEnc",
      "sources",
      "stateRoot",
      "txViewingSk",
    ]);
    expect(body["circuitType"]).toBe("custom-ring-policy");
    expect(body["auditorPk"]).toHaveLength(132);
    expect(body["publicInputHash"]).toHaveLength(66);
    const answers = body["answers"] as Record<string, unknown>[];
    expect(answers).toHaveLength(10);
    expect(answers[0]?.["nfPathElements"]).toHaveLength(40);
    expect(answers[0]?.["statePathElements"]).toHaveLength(32);
    const sources = body["sources"] as Record<string, unknown>[];
    expect(sources).toHaveLength(8);
    expect(Object.keys(sources[0] ?? {}).sort()).toEqual(["listId", "ownerHash"]);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRingPolicy(ringRequest(auditorPublicKey)),
      ).rejects.toMatchObject({
        code: "CLIENT_INVALID_P256_KEY",
      });
    }
    // The server rejects `answers.len() != 10`, an unpadded answers array must not leave the client.
    await expect(
      prover.proveCustomRingPolicy({ ...ringRequest(auditorPublicKey), answers: [] }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_LENGTH" });
    expect(raw).toHaveLength(1);
  });

  it("encodes the base request byte for byte like Rust `CustomRingBaseProofRequest::body`", async () => {
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
    const auditorPublicKey = p256.getPublicKey(bytes(4), false);

    await prover.proveCustomRingBase(auditRequest(auditorPublicKey));

    expect(raw[0]).toBe(JSON.stringify(EXPECTED_AUDIT_BODY));
    // The audit proof is queued, never sent inline.
    expect(deliveries).toEqual([null]);
    const body = JSON.parse(raw[0] ?? "") as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "auditorPk",
      "circuitType",
      "ephSk",
      "privateTxHash",
      "publicInputHash",
      "txViewingSk",
    ]);
    expect(body["circuitType"]).toBe("custom-ring-base");
    expect(body["auditorPk"]).toHaveLength(132);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRingBase(auditRequest(auditorPublicKey)),
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
        JSON.stringify({
          circuits: ["transfer-ring", "custom-ring-base", "custom-ring-policy"],
          status: "ok",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example/base?tenant=alpha", fetch });
    const health = await prover.health();
    expect(health).toEqual({
      status: "ok",
      circuits: ["transfer-ring", "custom-ring-base", "custom-ring-policy"],
    });
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
