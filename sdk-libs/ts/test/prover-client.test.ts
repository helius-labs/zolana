import { address } from "@solana/kit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import { prepareMerge } from "../src/client/prover/merge.js";
import { parseProof } from "../src/client/prover/proof.js";
import type { RegisterKeyProofRequest } from "../src/client/prover/ring.js";
import {
  asField,
  asInteger,
  createDummyTransferInput,
  createOutput,
  treeSlotFields,
} from "../src/client/prover/assembly.js";
import { LocalKeys } from "../src/client/keys.js";
import { BN254_MODULUS, bytesField } from "../src/client/internal.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import {
  ProverClient,
  mergeProverRequestBody,
  proverRequestBody,
} from "../src/client/prover/client.js";
import { proofFor } from "./helpers/proofs.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import { MERGE_INPUT_COUNT } from "../src/interface/constants.js";
import { PROVING_KEY_SHA256S } from "../src/interface/proving-keys.js";
import { QUAD_HEIGHT } from "../src/interface/member-registry.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { INPUT_TREES, ZERO_TREE_SLOT } from "../src/interface/tree-slot.js";
import type {
  MergeInputs,
  ProverInputs,
  TransferInput,
  TreeSlotFields,
} from "../src/client/prover/types.js";
import {
  Merge,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  createProofOutput,
} from "../src/transaction/index.js";

/** Every fixture proves from tree 0, the id the client and the wallet default to. */
const OUTPUT_TREE_ID = 0;
const INPUT_TREE = treeAddress(OUTPUT_TREE_ID);
/** The wire form of `INPUT_TREES` unused slots. */
const TREE_SLOTS: readonly TreeSlotFields[] = Array.from({ length: INPUT_TREES }, () =>
  treeSlotFields(ZERO_TREE_SLOT),
);
const RETIRED_KEYS = [
  "utxoTreeRoot",
  "nullifierTreeRoot",
  "outputBlindingSeed",
  "privateTxBlinding",
];

const INPUTS: ProverInputs = {
  circuit: "transfer",
  payload: {
    inputs: [],
    outputs: [],
    treeSlots: TREE_SLOTS,
    outputTreeId: asField(0n),
    externalDataHash: asField(0n),
    privateTxHash: asField(0n),
    blindingSeed: asField(0n),
    ringSecrets: [],
    publicAssets: [asField(0n), asField(0n), asField(0n)],
    publicAmounts: [asField(0n), asField(0n), asField(0n)],
    ringProgramId: asField(0n),
    signerPublicKeyHashes: [asField(0n)],
    inputFlags: asField(1n),
    publishedOutputOwnerPublicKeyHashes: [],
    cacheTreeId: asField(0n),
    cacheReadHashChain: asField(0n),
    cacheReadHashes: [],
    cacheIsCached: [],
    cacheReadIndex: [],
    publicInputHash: asField(0n),
  },
};
/** The proof a prover returns for `transferInputs()`. */
const TRANSFER_PROOF = proofFor({ circuitType: "transfer-confidential", nInputs: 2, nOutputs: 2 });

/** A 2-in/2-out transfer, the smallest shape every transfer rail has a key for. */
function transferInputs(): ProverInputs {
  const output = mergeInputs().output;
  return {
    ...INPUTS,
    payload: {
      ...INPUTS.payload,
      inputs: [dummyTransferInput(), dummyTransferInput()],
      outputs: [output, output],
      publishedOutputOwnerPublicKeyHashes: [asField(0n), asField(0n)],
    },
  };
}

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function mergeInputs(): MergeInputs {
  return {
    inputs: Array.from({ length: MERGE_INPUT_COUNT }, () => dummyTransferInput()),
    output: createOutput(
      createProofOutput({
        asset: address("11111111111111111111111111111111"),
        amount: 0n,
        blinding: bytes(0),
      }),
      OUTPUT_TREE_ID,
    ),
    treeSlots: TREE_SLOTS,
    outputTreeId: asField(0n),
    // The all-zero mint above splits into two zero chunks.
    mintChunks: [asField(0n), asField(0n)],
    outputCiphertextSalt: asField(0n),
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

function dummyNullifierProof(utxo: ProofInputUtxo): NonInclusionProof {
  return {
    leaf: utxo.nullifier(),
    merkleContext: { treeType: 0, tree: INPUT_TREE },
    lowElement: bytes(1),
    highElement: bytes(2),
    highElementIndex: 1n,
    path: [],
    lowElementIndex: 0n,
    root: bytes(3),
    rootSeq: 0n,
    rootIndex: 0,
  } satisfies NonInclusionProof;
}

function dummyTransferInput(): TransferInput {
  const utxo = ProofInputUtxo.dummy(bytes(7));
  return createDummyTransferInput(utxo, dummyNullifierProof(utxo));
}

/**
 * Mirrors the Rust `assert_tree_slot_contract`: the roots moved from every
 * input into `INPUT_TREES` public tree slots, an input only names its slot, and
 * the circuit derives the blindings the client used to send.
 */
function expectTreeSlotContract(body: Record<string, unknown>): void {
  const slots = body["treeSlots"];
  if (!Array.isArray(slots)) throw new Error("treeSlots is an array");
  expect(slots).toHaveLength(INPUT_TREES);
  for (const slot of slots as unknown[]) {
    expect(keysOf(slot)).toEqual(["id", "utxoRoot", "nullifierRoot"].sort());
  }
  expect(body["outputTreeId"]).toBeDefined();
  for (const key of RETIRED_KEYS) expect(body).not.toHaveProperty(key);
  const inputs = body["inputs"];
  if (!Array.isArray(inputs)) throw new Error("inputs is an array");
  for (const input of inputs as unknown[]) {
    expect(input).toHaveProperty("treeSlot");
    for (const key of RETIRED_KEYS) expect(input).not.toHaveProperty(key);
  }
}

async function sentBody(
  send: (prover: ProverClient) => Promise<unknown>,
): Promise<Record<string, unknown>> {
  const raw: string[] = [];
  const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
    raw.push(String(init?.body));
    return new Response(JSON.stringify(proofFor(JSON.parse(String(init?.body)))), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  await send(new ProverClient({ tee: false, url: "https://prover.example", fetch }));
  return JSON.parse(raw[0] ?? "") as Record<string, unknown>;
}

function keysOf(value: unknown): string[] {
  return Object.keys(value as object).sort();
}

describe("ring prover contracts", () => {
  const registerKey: RegisterKeyProofRequest = {
    kind: "registerKey",
    publicInputHash: bytes(1),
    member: bytes(2),
    nullifierSecret: new Uint8Array(32) as Bytes32,
    ephSk: bytes(3),
    auditorPk: bytes(4),
  };

  it("decodes a ring proof and refuses a malformed response", async () => {
    const proof = proofFor({ circuitType: "custom-ring-register-key" });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(proof));
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    await expect(prover.proveRing(registerKey)).resolves.toEqual(parseProof(proof));
    fetch.mockResolvedValueOnce(Response.json({ ...proof, ar: [] }));
    await expect(prover.proveRing(registerKey)).rejects.toMatchObject({
      code: "CLIENT_PROOF_PARSE",
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("refuses a ring proof from another ring key", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json(proofFor({ circuitType: "custom-ring-deposit" })),
    );
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    await expect(prover.proveRing(registerKey)).rejects.toMatchObject({
      code: "CLIENT_PROVING_KEY_MISMATCH",
      details: { keyName: "custom_ring_register_key.key" },
    });
  });
});

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

    const settled = prover.prove(transferInputs());
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
  it("rejects a merge for another wallet before submitting a proof", async () => {
    const owner = ShieldedKeypair.generate();
    const other = ShieldedKeypair.generate();
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const proofs = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    const keys = LocalKeys.fromKeypair(other, proofs);
    const { userNullifierSecret, ...incomplete } = mergeInputs();
    expect(userNullifierSecret).toBe(0n);
    try {
      await expect(
        keys.proveMerge({
          ...incomplete,
          userNullifierPublicKey: asField(bytesField(owner.nullifierPublicKey(), "public key")),
        }),
      ).rejects.toMatchObject({ code: "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH" });
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      keys.destroy();
      owner.destroy();
      other.destroy();
    }
  });

  it("encodes an incomplete merge for its remote holder and requires completion before posting", async () => {
    const { userNullifierSecret, ...incomplete } = mergeInputs();
    expect(userNullifierSecret).toBe(0n);
    expect(mergeProverRequestBody(incomplete)).toEqual({
      ...mergeProverRequestBody(mergeInputs()),
      userNullifierSecret: null,
    });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const proofs = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    await expect(proofs.proveMerge(incomplete)).rejects.toMatchObject({
      code: "CLIENT_MISSING_NULLIFIER_SECRET",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("expects the key of the circuit each transfer is proven by", async () => {
    const json = { "content-type": "application/json" };
    for (const [circuit, circuitType, keyName] of [
      ["transfer", "transfer-confidential", "transfer_confidential_2_2.key"],
      ["transferRing", "transfer-ring", "transfer_ring_2_2.key"],
      ["transferRingAuthority", "transfer-ring-authority", "transfer_ring_authority_2_2.key"],
    ] as const) {
      const transfer = transferInputs();
      const ringSecrets =
        circuit === "transfer" ? [] : transfer.payload.outputs.map(() => asField(0n));
      const inputs = { circuit, payload: { ...transfer.payload, ringSecrets } };
      let posted: unknown;
      const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
        posted = JSON.parse(String(init?.body));
        return new Response(JSON.stringify(proofFor(posted)), { headers: json });
      }) as typeof globalThis.fetch;
      await new ProverClient({ tee: false, url: "https://prover.example", fetch }).prove(inputs);
      expect(posted).toMatchObject({ circuitType });

      if (circuitType === "transfer-confidential") continue;
      // A proof from the confidential key is refused for the ring circuits.
      const wrong = vi.fn(
        async () => new Response(JSON.stringify(TRANSFER_PROOF), { headers: json }),
      ) as typeof globalThis.fetch;
      await expect(
        new ProverClient({ tee: false, url: "https://prover.example", fetch: wrong }).prove(inputs),
      ).rejects.toMatchObject({ code: "CLIENT_PROVING_KEY_MISMATCH", details: { keyName } });
    }
  });

  it("refuses a ring rail request without one ring secret per output before posting", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const transfer = transferInputs();
    const inputs: ProverInputs = {
      circuit: "transferRing",
      payload: { ...transfer.payload, ringSecrets: [asField(0n)] },
    };
    await expect(
      new ProverClient({ tee: false, url: "https://prover.example", fetch }).prove(inputs),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_LENGTH", details: { field: "ringSecrets" } });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("expects the merge-ring key for a merge inside a custom ring", async () => {
    const json = { "content-type": "application/json" };
    const ringMerge: MergeInputs = {
      ...mergeInputs(),
      ringProgramId: asField(7n),
      memberRegistryRoot: asField(2n),
      registeredCiphertextHash: asField(3n),
      memberRecord: {
        kind: "present",
        record: { member: bytes(6), next: bytes(4), lists: 0n, escrowKey: bytes(5) },
        path: {
          index: 1,
          siblings: Array.from({ length: QUAD_HEIGHT }, () => [bytes(0), bytes(0), bytes(0)]),
        },
      },
    };
    let posted: unknown;
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      posted = JSON.parse(String(init?.body));
      return new Response(JSON.stringify(proofFor(posted)), { headers: json });
    }) as typeof globalThis.fetch;
    await new ProverClient({ tee: false, url: "https://prover.example", fetch }).proveMerge(
      ringMerge,
    );
    expect(posted).toMatchObject({ circuitType: "merge-ring" });

    // A proof from the plain merge key is refused.
    const plainProof = proofFor({ ...(posted as Record<string, unknown>), circuitType: "merge" });
    const plain = vi.fn(
      async () => new Response(JSON.stringify(plainProof), { headers: json }),
    ) as typeof globalThis.fetch;
    await expect(
      new ProverClient({ tee: false, url: "https://prover.example", fetch: plain }).proveMerge(
        ringMerge,
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVING_KEY_MISMATCH",
      details: { keyName: "merge_ring_24_1.key" },
    });
  });

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
      return new Response(JSON.stringify(proofFor(bodies.at(-1))), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      tee: false,
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch,
    });

    await prover.proveMerge(mergeInputs());

    expect(bodies).toMatchObject([{ circuitType: "merge" }]);
    expect(deliveries).toEqual(["true"]);
    expect(redirects).toEqual(["error"]);
    expect(urls[0]?.pathname).toBe("/zolana/prove/merge_24_1");
    expect(urls[0]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[0]?.searchParams.get("tenant")).toBe("alpha");
  });

  it("pins the merge request keys to the Go `MergeParametersJSON` tags", async () => {
    const body = await sentBody((prover) => prover.proveMerge(mergeInputs()));
    const [input] = body["inputs"] as unknown[];

    expect(keysOf(body)).toEqual(
      [
        "circuitType",
        "inputs",
        "output",
        "treeSlots",
        "outputTreeId",
        "mintChunks",
        "ownerPkHash",
        "userNullifierPk",
        "userNullifierSecret",
        "externalDataHash",
        "privateTxHash",
        "publicInputHash",
        "allowDummyInputs",
        "outputCiphertextSalt",
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
        "treeSlot",
        "nullifier",
      ].sort(),
    );
    expect(keysOf(body["output"])).toEqual(["ringDataHash", "hash"].sort());
    // The circuit derives the asset from the two mint chunks, so the request
    // carries the chunks and no separate asset.
    expect(body["mintChunks"]).toEqual(["0x0", "0x0"]);
    expect(body["outputCiphertextSalt"]).toBe("0x0");
    expect(body).not.toHaveProperty("asset");
    expectTreeSlotContract(body);
    // The merge circuit derives every blinding from userNullifierSecret, so
    // the transfer-only root seed is not part of this request.
    expect(body).not.toHaveProperty("blindingSeed");
  });

  it("pins the transfer request keys to the Go `TransferParametersJSON` tags", async () => {
    const body = await sentBody((prover) => prover.prove(transferInputs()));
    const [input] = body["inputs"] as Record<string, unknown>[];
    const [output] = body["outputs"] as unknown[];

    expect(keysOf(body)).toEqual(
      [
        "circuitType",
        "nInputs",
        "nOutputs",
        "inputs",
        "outputs",
        "treeSlots",
        "outputTreeId",
        "externalDataHash",
        "privateTxHash",
        "blindingSeed",
        "ringSecrets",
        "publicAssets",
        "publicAmounts",
        "ringProgramId",
        "signerPkHashes",
        "inputFlags",
        "publishedOutputOwnerPkHashes",
        "cacheTreeId",
        "cacheReadHashChain",
        "cacheReadHashes",
        "cacheIsCached",
        "cacheReadIndex",
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
        "treeSlot",
        "nullifier",
        "ownerPkHash",
        "nullifierSecret",
      ].sort(),
    );
    expect(keysOf(output)).toEqual(
      ["utxo", "isDummy", "hash", "ownerPkHash", "nullifierPk"].sort(),
    );
    expectTreeSlotContract(body);
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
    const queued: (string | null)[] = [];
    const refusal = new Response("busy", { status: 429 });
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      if (init?.method === "POST") {
        deliveries.push(new Headers(init.headers).get("X-Sync"));
        queued.push(new Headers(init.headers).get("X-Async"));
        if (deliveries.length === 1) return refusal;
        return new Response(JSON.stringify({ jobId: "job-123" }), {
          status: 202,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ status: "completed", result: TRANSFER_PROOF }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });

    await prover.prove(transferInputs());

    expect(deliveries).toEqual(["true", null]);
    expect(queued).toEqual([null, "true"]);
    expect(refusal.bodyUsed).toBe(true);
  });

  it("reports the prover's own error code and message on a refused request", async () => {
    const fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ code: "malformed_body", message: "unknown circuit type: custom-ring" }),
          { status: 400, headers: { "content-type": "application/json" } },
        ),
    ) as typeof globalThis.fetch;
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });

    await expect(prover.prove(transferInputs())).rejects.toMatchObject({
      code: "CLIENT_PROVER_HTTP",
      details: {
        method: "prove",
        status: 400,
        attempts: 1,
        reason: "malformed_body: unknown circuit type: custom-ring",
      },
    });

    // A body that is not the prover's error shape adds nothing.
    const html = vi.fn(
      async () => new Response("<html>502</html>", { status: 502 }),
    ) as typeof globalThis.fetch;
    await expect(
      new ProverClient({ tee: false, url: "https://prover.example", fetch: html }).prove(
        transferInputs(),
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVER_HTTP",
      details: { method: "prove", status: 502 },
    });
  });

  it("reads the served circuits from the health endpoint", async () => {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      urls.push(new URL(input));
      return new Response(
        JSON.stringify({
          circuits: ["transfer-ring", "custom-ring-audit-packed-2", "custom-ring-policy-member-2"],
          status: "ok",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      tee: false,
      url: "https://prover.example/base?tenant=alpha",
      fetch,
    });
    const health = await prover.health();
    expect(health).toEqual({
      status: "ok",
      circuits: ["transfer-ring", "custom-ring-audit-packed-2", "custom-ring-policy-member-2"],
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
        : new Response(JSON.stringify({ status: "completed", result: TRANSFER_PROOF }), {
            headers: { "content-type": "application/json" },
          });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      tee: false,
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch,
    });

    await prover.prove(transferInputs());

    expect(urls.map((url) => url.pathname)).toEqual([
      "/zolana/prove/transfer_confidential_2_2",
      "/zolana/prove/transfer_confidential_2_2/status",
    ]);
    expect(urls[1]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[1]?.searchParams.get("tenant")).toBe("alpha");
    expect(urls[1]?.searchParams.get("jobId")).toBe("job-123");
  });
  it("sends a proof and its poll to the Helius gateway's key-less paths", async () => {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      const url = new URL(String(input));
      urls.push(url);
      return urls.length === 1
        ? new Response(JSON.stringify({ jobId: "job-123" }), {
            status: 202,
            headers: { "content-type": "application/json" },
          })
        : new Response(JSON.stringify({ status: "completed", result: TRANSFER_PROOF }), {
            headers: { "content-type": "application/json" },
          });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      tee: false,
      url: "https://beta-devnet.helius-rpc.com/v1/zolana?api-key=k",
      fetch,
    });

    await prover.prove(transferInputs());

    expect(urls.map((url) => url.pathname)).toEqual([
      "/v1/zolana/prove",
      "/v1/zolana/prove/status",
    ]);
    expect(urls.map((url) => url.searchParams.get("api-key"))).toEqual(["k", "k"]);
    expect(urls[1]?.searchParams.get("jobId")).toBe("job-123");
  });
});

describe("proving key check", () => {
  const json = { "content-type": "application/json" };
  const expected = TRANSFER_PROOF["provingKeySha256"] as string;

  /** Prove `transferInputs()` against a prover answering with `proof`, in the response or queued. */
  async function proveAgainst(proof: unknown, queued: boolean): Promise<unknown> {
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      if (queued && init?.method === "POST") {
        return new Response(JSON.stringify({ jobId: "job-key" }), { status: 202, headers: json });
      }
      const body = queued ? { status: "completed", result: proof } : proof;
      return new Response(JSON.stringify(body), { headers: json });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    try {
      return await prover.prove(transferInputs());
    } catch (error) {
      return error;
    }
  }

  it("accepts a proof from the key the verifying key pins", async () => {
    for (const queued of [false, true]) {
      const proof = await proveAgainst(TRANSFER_PROOF, queued);
      expect(proof).not.toBeInstanceOf(Error);
      expect(proof).toHaveProperty("a");
    }
  });

  it("rejects a proof from another proving key on both rails", async () => {
    const foreign = "ab".repeat(32);
    for (const queued of [false, true]) {
      const error = await proveAgainst({ ...TRANSFER_PROOF, provingKeySha256: foreign }, queued);
      expect(error).toBeInstanceOf(ClientError);
      expect(error).toMatchObject({
        code: "CLIENT_PROVING_KEY_MISMATCH",
        details: {
          keyName: "transfer_confidential_2_2.key",
          expectedSha256: expected,
          reportedSha256: foreign,
        },
      });
    }
  });

  it("fails closed when the prover does not report its key", async () => {
    const { provingKeySha256: _omitted, ...unreported } = TRANSFER_PROOF;
    for (const queued of [false, true]) {
      const error = await proveAgainst(unreported, queued);
      expect(error).toMatchObject({
        code: "CLIENT_PROVING_KEY_MISSING",
        details: { keyName: "transfer_confidential_2_2.key" },
      });
    }
  });

  it("rejects a malformed digest without echoing it", async () => {
    for (const reported of [
      "AB".repeat(32),
      "ab".repeat(31),
      "ab".repeat(33),
      `0x${"ab".repeat(31)}`,
      "<script>",
      7,
      null,
    ]) {
      const error = await proveAgainst({ ...TRANSFER_PROOF, provingKeySha256: reported }, false);
      expect(error).toMatchObject({
        code: "CLIENT_PROOF_PARSE",
        details: { path: "$.proof.provingKeySha256" },
      });
      expect(JSON.stringify((error as ClientError).details)).not.toContain(String(reported));
    }
  });

  it("refuses a shape without a committed verifying key before any request", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    await expect(prover.prove(INPUTS)).rejects.toMatchObject({ code: "CLIENT_PROVER_INPUT" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("prover proving keys check", () => {
  const json = { "content-type": "application/json" };

  /** What a prover built from this commit reports before it loads anything. */
  function matchingReport(): { prefix: string; keys: Record<string, unknown>[] } {
    return {
      prefix: "proving-keys/test",
      keys: Object.entries(PROVING_KEY_SHA256S).map(([name, sha256]) => ({
        name,
        expectedSha256: sha256,
        loadedSha256: null,
        available: true,
      })),
    };
  }

  function entry(report: ReturnType<typeof matchingReport>, name: string): Record<string, unknown> {
    const found = report.keys.find((key) => key["name"] === name);
    if (found === undefined) throw new Error(`${name} is not listed`);
    return found;
  }

  async function check(body: unknown, init: ResponseInit = {}): Promise<unknown> {
    const urls: URL[] = [];
    const fetch = vi.fn(async (input: URL | string) => {
      urls.push(new URL(String(input)));
      return new Response(JSON.stringify(body), { headers: json, ...init });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      tee: false,
      url: "https://gateway.example/zolana?api-key=k%2B1",
      fetch,
    });
    try {
      return await prover.checkProvingKeys();
    } catch (error) {
      return error;
    } finally {
      expect(urls.map((url) => `${url.pathname}?${url.searchParams.toString()}`)).toEqual([
        "/zolana/proving-keys?api-key=k%2B1",
      ]);
    }
  }

  it("reports every known key of a prover on the same key set", async () => {
    const report = matchingReport();
    const loaded = entry(report, "transfer_ring_2_2.key");
    loaded["loadedSha256"] = loaded["expectedSha256"];

    expect(await check(report)).toEqual({
      prefix: "proving-keys/test",
      keys: Object.keys(PROVING_KEY_SHA256S).map((name) => ({
        name,
        served: true,
        available: true,
        loaded: name === "transfer_ring_2_2.key",
      })),
    });
  });

  it("names every key whose expected or loaded digest differs", async () => {
    const report = matchingReport();
    entry(report, "merge_24_1.key")["expectedSha256"] = "ab".repeat(32);
    entry(report, "custom_ring_register_key.key")["loadedSha256"] = "cd".repeat(32);

    expect(await check(report)).toMatchObject({
      code: "CLIENT_PROVER_PROVING_KEYS_MISMATCH",
      details: { keyNames: "custom_ring_register_key.key,merge_24_1.key" },
    });
  });

  it("reports a key the prover lacks or cannot load without failing", async () => {
    const report = matchingReport();
    report.keys = report.keys.filter((key) => key["name"] !== "merge_52_1.key");
    entry(report, "transfer_ring_49_2.key")["available"] = false;

    const result = (await check(report)) as {
      keys: { name: string; served: boolean; available: boolean }[];
    };
    expect(
      result.keys.filter((key) => ["merge_52_1.key", "transfer_ring_49_2.key"].includes(key.name)),
    ).toEqual([
      { name: "merge_52_1.key", served: false, available: false, loaded: false },
      { name: "transfer_ring_49_2.key", served: true, available: false, loaded: false },
    ]);
  });

  it("rejects a malformed report instead of skipping keys", async () => {
    const malformed: unknown[] = [
      [],
      { keys: [] },
      { prefix: "p", keys: {} },
      { prefix: "p", keys: [{ name: "merge_24_1.key", loadedSha256: null, available: true }] },
      {
        prefix: "p",
        keys: [
          {
            name: "merge_24_1.key",
            expectedSha256: "AB".repeat(32),
            loadedSha256: null,
            available: true,
          },
        ],
      },
      {
        prefix: "p",
        keys: [{ name: "merge_24_1.key", expectedSha256: null, loadedSha256: 7, available: true }],
      },
      {
        prefix: "p",
        keys: [
          { name: "merge_24_1.key", expectedSha256: null, loadedSha256: null, available: "yes" },
        ],
      },
    ];
    for (const body of malformed) {
      expect(await check(body)).toMatchObject({ code: "CLIENT_PROVER_JSON" });
    }
  });

  it("fails on a prover without the endpoint", async () => {
    expect(await check({}, { status: 404 })).toMatchObject({
      code: "CLIENT_PROVER_HTTP",
      details: { method: "provingKeys", status: 404 },
    });
  });

  it("honours cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      init?.signal?.throwIfAborted();
      return new Response(JSON.stringify(matchingReport()), { headers: json });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
    await expect(prover.checkProvingKeys({ signal: controller.signal })).rejects.toBeInstanceOf(
      ClientError,
    );
  });
});

describe("dummy prover inputs", () => {
  it("zeroes every inert UTXO field except blinding", () => {
    const input = ProofInputUtxo.dummy(bytes(7));

    const converted = createDummyTransferInput(input, dummyNullifierProof(input));
    const utxo = converted.circuit;

    expect(converted.ownerPublicKeyHash).toBe(0n);
    // A single-tree proof opens every input, padding included, against slot 0.
    expect(converted.treeSlot).toBe(0n);
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

describe("indexed prover failures", () => {
  const SERVER_TEXT = "photon echoed caller data";

  /** An indexed merge, the route a ring merge's registry lookup refuses on. */
  function prove(fetch: typeof globalThis.fetch): Promise<unknown> {
    const prover = new ProverClient({
      tee: false,
      url: "https://prover.example",
      fetch,
      asyncPoll: { pollIntervalCapMs: 1, maxWaitMs: 1_000 },
    });
    const owner = ShieldedKeypair.generate();
    const input = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 5n,
        blinding: randomBlinding(),
      }),
      owner,
    );
    const prepared = Merge.fromKeypair(owner, [input]).prepare();
    return LocalKeys.fromKeypair(owner, prover)
      .proveIndexed(prepareMerge(prepared, treeAddress(prepared.inputTreeId)).inputs)
      .finally(() => owner.destroy());
  }

  /** Refuses sync admission, queues, then reports `status` for the job. */
  function queued(status: Readonly<Record<string, unknown>>) {
    return vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      if (init?.method !== "POST") return Response.json({ status: "failed", ...status });
      if (new Headers(init.headers).get("X-Sync") === "true")
        return new Response(null, { status: 429 });
      return Response.json({ jobId: "job-1" }, { status: 202 });
    });
  }

  it.each([
    [
      404,
      new Response("404 page not found", { status: 404 }),
      "CLIENT_PROVER_INDEXER_UNCONFIGURED",
    ],
    [
      404,
      Response.json({ code: "indexer_unconfigured", message: SERVER_TEXT }, { status: 404 }),
      "CLIENT_PROVER_INDEXER_UNCONFIGURED",
    ],
    // A key the prover does not serve is not a prover without an indexer.
    [
      404,
      Response.json({ code: "proving_key_not_served", message: SERVER_TEXT }, { status: 404 }),
      "CLIENT_PROVER_HTTP",
    ],
    [
      503,
      Response.json({ code: "indexer_not_ready", message: SERVER_TEXT }, { status: 503 }),
      "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
    ],
    [
      502,
      Response.json({ code: "indexer_unavailable", message: SERVER_TEXT }, { status: 502 }),
      "CLIENT_PROVER_HTTP",
    ],
  ] as const)("maps a %i indexed answer to %s", async (_status, response, code) => {
    const error = await prove(vi.fn<typeof globalThis.fetch>(async () => response)).catch(
      (cause: unknown) => cause,
    );
    expect(error).toMatchObject({ code });
    expect(JSON.stringify(error)).not.toContain(SERVER_TEXT);
  });

  it("branches a failed job on its code, never on its error text", async () => {
    await expect(prove(queued({ code: "indexer_not_ready" }))).rejects.toMatchObject({
      code: "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
    });
    await expect(prove(queued({ error: "indexer proof data not ready" }))).rejects.toMatchObject({
      code: "CLIENT_PROVER_SERVER",
    });
  });
});

describe("error details", () => {
  it("keeps an out-of-range secret out of the error and its JSON", () => {
    const secret = BN254_MODULUS + 0x5ec2e7n;
    const [input] = transferInputs().payload.inputs;
    if (input === undefined) throw new Error("missing fixture input");
    const transfer = transferInputs();
    const requests = [
      () =>
        proverRequestBody({
          ...transfer,
          payload: {
            ...transfer.payload,
            inputs: [{ ...input, nullifierSecret: asInteger(secret) }],
          },
        }),
      () => mergeProverRequestBody({ ...mergeInputs(), userNullifierSecret: asInteger(secret) }),
    ];
    for (const [index, request] of requests.entries()) {
      let error: unknown;
      try {
        request();
      } catch (cause) {
        error = cause;
      }
      expect(error).toMatchObject({
        code: "CLIENT_INVALID_FIELD",
        details: { field: index === 0 ? "nullifierSecret" : "userNullifierSecret" },
      });
      const json = JSON.stringify(error);
      expect(json).not.toContain(secret.toString());
      expect(json).not.toContain(secret.toString(16));
    }
  });

  it.each(["CLIENT_INVALID_FIELD", "CLIENT_INVALID_INTEGER"] as const)(
    "refuses a %s that carries the value",
    (code) => {
      const details = { field: "nullifierSecret", value: "7" };
      expect(() => new ClientError(code, { details })).toThrow(TypeError);
    },
  );
});
