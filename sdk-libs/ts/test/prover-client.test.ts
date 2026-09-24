import { p256 } from "@noble/curves/nist.js";
import { address } from "@solana/kit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import {
  asField,
  createDummyTransferInput,
  createOutput,
  treeSlotFields,
} from "../src/client/prover/assembly.js";
import { LocalKeys } from "../src/client/keys.js";
import { bytesField } from "../src/client/internal.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  ProverClient,
  customRingCompressedPolicyProofRequest,
  customRingPolicyProofRequest,
  customRingRegisterKeyProofRequest,
  mergeProverRequestBody,
} from "../src/client/prover/client.js";
import { proofFor } from "./helpers/proofs.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import { MERGE_INPUT_COUNT } from "../src/interface/constants.js";
import { PROVING_KEY_SHA256S } from "../src/interface/proving-keys.js";
import { disabledRuleAnswer, velocityProofInputOff } from "../src/client/prover/types.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { INPUT_TREES, ZERO_TREE_SLOT } from "../src/interface/tree-slot.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingOpening,
  CustomRingPolicyProofRequest,
  MergeInputs,
  ProverInputs,
  TransferInput,
  TreeSlotFields,
} from "../src/client/prover/types.js";
import { ProofInputUtxo, createProofOutput } from "../src/transaction/index.js";

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
const TRANSFER_PROOF = proofFor({ circuitType: "transfer-confidential", nInputs: 1, nOutputs: 1 });

/** A 1-in/1-out transfer, the smallest shape with a committed verifying key. */
function transferInputs(): ProverInputs {
  return {
    ...INPUTS,
    payload: { ...INPUTS.payload, inputs: [dummyTransferInput()], outputs: [mergeInputs().output] },
  };
}

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
    treeId: bytes(0),
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
    salt: new Uint8Array(16) as import("../src/interface/types.js").Bytes16,
    nIn: 2,
    nOut: 2,
    inputs: Array.from({ length: 5 }, () => zeroOpening()),
    outputs: Array.from({ length: 4 }, () => zeroOpening()),
    addressChain: bytes(0),
    externalDataHash: bytes(6),
    privateTxBlinding: bytes(7),
    sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: bytes(0) })),
    policyLen: 1,
    rules: Array.from({ length: 16 }, () => bytes(0)),
    inlineAssets: Array.from({ length: 8 }, () => bytes(0)),
    inlineLimits: Array.from({ length: 8 }, () => 0n),
    inlineCount: 0,
    treeSlots: [{ id: 3, utxoRoot: bytes(8), nullifierRoot: bytes(9) }],
    addressTreeId: 3,
    velocity: velocityProofInputOff({ ringId: bytes(10), namespaceOwnerHash: bytes(11) }),
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
    salt: new Uint8Array(16) as import("../src/interface/types.js").Bytes16,
    nOut: 2,
    outputs: Array.from({ length: 4 }, () => zeroOpening()),
  };
}

describe("compressed ring prover contracts", () => {
  it("nests the member policy beside the transaction salt only", () => {
    const request = {
      policy: ringRequest(p256.getPublicKey(bytes(4), false)),
      transactionSalt: new Uint8Array(16) as import("../src/interface/types.js").Bytes16,
    };
    const body = customRingCompressedPolicyProofRequest(request);
    expect(body).toMatchObject({
      circuitType: "custom-ring-compressed-policy",
      policy: { circuitType: "custom-ring-policy" },
    });
    expect(Object.keys(body).sort()).toEqual(["circuitType", "policy", "transactionSalt"]);
  });

  it("serializes the key registration like Rust `RegisterKeyProofRequest::body`", () => {
    const nullifierSecret = bytes(0);
    nullifierSecret[31] = 7;
    const request = {
      publicInputHash: bytes(0),
      registryOldRoot: bytes(1),
      registryNewRoot: bytes(2),
      member: bytes(3),
      newIndex: 1n,
      lowMember: bytes(0),
      lowNext: bytes(5),
      lowKey: bytes(0),
      lowIndex: 0n,
      lowProof: Array.from({ length: 40 }, () => bytes(0)),
      newProof: Array.from({ length: 40 }, () => bytes(0)),
      nullifierSecret,
      ephemeralSecret: bytes(6),
      auditorPublicKey: p256.getPublicKey(bytes(4), false),
    };
    const body = customRingRegisterKeyProofRequest(request);
    expect(body).toMatchObject({
      circuitType: "custom-ring-register-key",
      newIndex: `0x${"0".repeat(63)}1`,
      nullifierSecret: `0x${"0".repeat(62)}07`,
      ephSk: fieldHex(6),
    });
    expect(String(body["auditorPk"])).toHaveLength(132);
    expect(String(body["ephSk"])).toHaveLength(66);
    expect(body).not.toHaveProperty("key");
    expect(body["registryNewRoot"]).toBe(fieldHex(2));
    const high = bytes(0);
    high[0] = 1;
    expect(() => customRingRegisterKeyProofRequest({ ...request, nullifierSecret: high })).toThrow(
      "CLIENT_INVALID_PROOF_INPUTS",
    );
    expect(() => customRingRegisterKeyProofRequest({ ...request, lowIndex: -1n })).toThrow(
      "CLIENT_INVALID_INTEGER",
    );
    expect(() => customRingRegisterKeyProofRequest({ ...request, newIndex: 1n << 40n })).toThrow(
      "CLIENT_INVALID_INTEGER",
    );
  });

  it("keeps delegate policy rows but sends no velocity charge", async () => {
    const bodies: unknown[] = [];
    const prover = new ProverClient({
      url: "https://prover.example",
      fetch: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return Response.json(proofFor(String(init?.body)));
      },
    });
    const request = ringRequest(p256.getPublicKey(bytes(4), false));
    const velocity = {
      ...request.velocity,
      windowSlots: 100n,
      rows: [{ asset: bytes(1), cap: 1n, cosignAbove: 1n }],
    };
    await prover.proveCustomRingDelegatePolicy({ ...request, velocity });
    expect(bodies).toMatchObject([
      {
        circuitType: "custom-ring-delegate-policy",
        policy: {
          circuitType: "custom-ring-policy",
          velocityCount: 1,
          windowSlots: 100,
          windowIndex: 0,
          approvalRequired: false,
        },
      },
    ]);
    await expect(
      prover.proveCustomRingDelegatePolicy({
        ...request,
        velocity: { ...velocity, approvalRequired: true },
      }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
    expect(bodies).toHaveLength(1);
  });
});

/** Key order from Rust `CustomRingBaseProofRequestJson` in `request_ring.rs`. */
const EXPECTED_AUDIT_BODY = {
  circuitType: "custom-ring-base",
  publicInputHash: fieldHex(0),
  privateTxHash: fieldHex(1),
  txViewingSk: fieldHex(2),
  ephSk: fieldHex(3),
  auditorPk: AUDITOR_PK_HEX,
  salt: "0x00000000000000000000000000000000",
  nOut: 2,
  outputs: Array.from({ length: 4 }, () => ({
    domain: fieldHex(0),
    treeId: fieldHex(0),
    ownerHash: fieldHex(0),
    asset: fieldHex(0),
    amount: fieldHex(0),
    blinding: fieldHex(0),
    dataHash: fieldHex(0),
    ringDataHash: fieldHex(0),
    ringProgramId: fieldHex(0),
  })),
};

const EXPECTED_OPENING = {
  domain: fieldHex(0),
  treeId: fieldHex(0),
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
  treeSlot: 0,
  mode: 1,
  listId: 1,
  state: 1,
  absentBranch: 1,
  member: fieldHex(0),
  contentHash: fieldHex(0),
  version: 0,
  blinding: fieldHex(0),
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
  salt: "0x00000000000000000000000000000000",
  nIn: 2,
  nOut: 2,
  inputs: Array.from({ length: 5 }, () => EXPECTED_OPENING),
  outputs: Array.from({ length: 4 }, () => EXPECTED_OPENING),
  addressChain: fieldHex(0),
  externalDataHash: fieldHex(6),
  privateTxBlinding: fieldHex(7),
  sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: fieldHex(0) })),
  policyLen: 1,
  ruleEnc: Array.from({ length: 16 }, () => fieldHex(0)),
  inlineAssets: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineLimits: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineCount: 0,
  treeSlots: [{ id: `0x${"0".repeat(62)}03`, utxoRoot: fieldHex(8), nullifierRoot: fieldHex(9) }],
  addressTreeId: `0x${"0".repeat(62)}03`,
  windowSlots: 0,
  velocity: Array.from({ length: 8 }, () => ({
    asset: fieldHex(0),
    cap: fieldHex(0),
    cosignAbove: fieldHex(0),
  })),
  velocityCount: 0,
  ringId: fieldHex(10),
  namespaceOwnerHash: fieldHex(11),
  windowIndex: 0,
  approvalRequired: false,
  keyEscrow: false,
  keyRegistryRoot: fieldHex(0),
  record: {
    version: 0,
    window: 0,
    commitment: fieldHex(0),
    salt: fieldHex(0),
    assets: Array.from({ length: 8 }, () => fieldHex(0)),
    spent: Array.from({ length: 8 }, () => fieldHex(0)),
    nextSalt: fieldHex(0),
  },
  answers: Array.from({ length: 10 }, () => EXPECTED_RULE_ANSWER),
};

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
    const proofs = new ProverClient({ url: "https://prover.example", fetch });
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
    const proofs = new ProverClient({ url: "https://prover.example", fetch });
    await expect(proofs.proveMerge(incomplete)).rejects.toMatchObject({
      code: "CLIENT_MISSING_NULLIFIER_SECRET",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("expects the key of the circuit each transfer is proven by", async () => {
    const json = { "content-type": "application/json" };
    for (const [circuit, circuitType, keyName] of [
      ["transfer", "transfer-confidential", "transfer_confidential_1_1.key"],
      ["transferRing", "transfer-ring", "transfer_ring_1_1.key"],
      ["transferRingAuthority", "transfer-ring-authority", "transfer_ring_authority_1_1.key"],
    ] as const) {
      const inputs = { ...transferInputs(), circuit };
      let posted: unknown;
      const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
        posted = JSON.parse(String(init?.body));
        return new Response(JSON.stringify(proofFor(posted)), { headers: json });
      }) as typeof globalThis.fetch;
      await new ProverClient({ url: "https://prover.example", fetch }).prove(inputs);
      expect(posted).toMatchObject({ circuitType });

      if (circuitType === "transfer-confidential") continue;
      // A proof from the confidential key is refused for the ring circuits.
      const wrong = vi.fn(
        async () => new Response(JSON.stringify(TRANSFER_PROOF), { headers: json }),
      ) as typeof globalThis.fetch;
      await expect(
        new ProverClient({ url: "https://prover.example", fetch: wrong }).prove(inputs),
      ).rejects.toMatchObject({ code: "CLIENT_PROVING_KEY_MISMATCH", details: { keyName } });
    }
  });

  it("expects the merge-ring key for a merge inside a custom ring", async () => {
    const json = { "content-type": "application/json" };
    const ringMerge = { ...mergeInputs(), ringProgramId: asField(7n) };
    let posted: unknown;
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      posted = JSON.parse(String(init?.body));
      return new Response(JSON.stringify(proofFor(posted)), { headers: json });
    }) as typeof globalThis.fetch;
    await new ProverClient({ url: "https://prover.example", fetch }).proveMerge(ringMerge);
    expect(posted).toMatchObject({ circuitType: "merge-ring" });

    // A proof from the plain merge key is refused.
    const plainProof = proofFor({ ...(posted as Record<string, unknown>), circuitType: "merge" });
    const plain = vi.fn(
      async () => new Response(JSON.stringify(plainProof), { headers: json }),
    ) as typeof globalThis.fetch;
    await expect(
      new ProverClient({ url: "https://prover.example", fetch: plain }).proveMerge(ringMerge),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVING_KEY_MISMATCH",
      details: { keyName: "merge_ring_8_1.key" },
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
      return new Response(JSON.stringify(proofFor(JSON.parse(String(init?.body)))), {
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
      "addressTreeId",
      "answers",
      "approvalRequired",
      "auditorPk",
      "circuitType",
      "ephSk",
      "externalDataHash",
      "inlineAssets",
      "inlineCount",
      "inlineLimits",
      "inputs",
      "keyEscrow",
      "keyRegistryRoot",
      "nIn",
      "nOut",
      "namespaceOwnerHash",
      "outputs",
      "policyLen",
      "privateTxBlinding",
      "privateTxHash",
      "publicInputHash",
      "record",
      "ringId",
      "ruleEnc",
      "salt",
      "sources",
      "treeSlots",
      "txViewingSk",
      "velocity",
      "velocityCount",
      "windowIndex",
      "windowSlots",
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
    for (const treeSlots of [
      [],
      Array.from({ length: 6 }, () => ringRequest(auditorPublicKey).treeSlots[0]!),
    ]) {
      await expect(
        prover.proveCustomRingPolicy({ ...ringRequest(auditorPublicKey), treeSlots }),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_LENGTH" });
    }
    expect(raw).toHaveLength(1);
  });

  it("sends each escrowed output key beside its opening like Go `writeRegistryKey`", async () => {
    const auditorPublicKey = p256.getPublicKey(bytes(4), false);
    const key = {
      next: bytes(12),
      ctHash: bytes(13),
      index: 5n,
      path: Array.from({ length: 40 }, () => bytes(14)),
    };
    const request = ringRequest(auditorPublicKey);
    const escrowed = {
      ...request,
      keyRegistryRoot: bytes(15),
      outputs: request.outputs.map((opening, index) =>
        index === 1 ? { ...opening, key } : opening,
      ),
    };
    const body = customRingPolicyProofRequest(escrowed);
    expect(body).toMatchObject({ keyEscrow: true, keyRegistryRoot: fieldHex(15) });
    const outputs = body["outputs"] as Record<string, unknown>[];
    expect(outputs[0]).not.toHaveProperty("key");
    expect(outputs[1]?.["key"]).toEqual({
      next: fieldHex(12),
      ctHash: fieldHex(13),
      index: 5,
      path: Array.from({ length: 40 }, () => fieldHex(14)),
    });
    expect(() =>
      customRingPolicyProofRequest({
        ...escrowed,
        inputs: request.inputs.map((opening) => ({ ...opening, key })),
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }));
    expect(() =>
      customRingPolicyProofRequest({
        ...escrowed,
        outputs: request.outputs.map((opening) => ({
          ...opening,
          key: { ...key, index: 1n << 40n },
        })),
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_INTEGER" }));
  });

  it("encodes the base request byte for byte like Rust `CustomRingBaseProofRequest::body`", async () => {
    const raw: string[] = [];
    const deliveries: (string | null)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      raw.push(String(init?.body));
      deliveries.push(new Headers(init?.headers).get("X-Sync"));
      return new Response(JSON.stringify(proofFor(JSON.parse(String(init?.body)))), {
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
      "nOut",
      "outputs",
      "privateTxHash",
      "publicInputHash",
      "salt",
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
    const body = await sentBody((prover) => prover.proveMerge(mergeInputs()));
    const [input] = body["inputs"] as unknown[];

    expect(keysOf(body)).toEqual(
      [
        "circuitType",
        "inputs",
        "output",
        "treeSlots",
        "outputTreeId",
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
        "treeSlot",
        "nullifier",
      ].sort(),
    );
    expect(keysOf(body["output"])).toEqual(["ringDataHash", "hash"].sort());
    expectTreeSlotContract(body);
    // The merge circuit derives every blinding from userNullifierSecret, so
    // the transfer-only root seed is not part of this request.
    expect(body).not.toHaveProperty("blindingSeed");
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
        "treeSlots",
        "outputTreeId",
        "externalDataHash",
        "privateTxHash",
        "blindingSeed",
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
      return new Response(JSON.stringify({ status: "completed", result: TRANSFER_PROOF }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({ url: "https://prover.example", fetch });

    await prover.prove(transferInputs());

    expect(deliveries).toEqual(["true", null]);
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
    const prover = new ProverClient({ url: "https://prover.example", fetch });

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
      new ProverClient({ url: "https://prover.example", fetch: html }).prove(transferInputs()),
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
        : new Response(JSON.stringify({ status: "completed", result: TRANSFER_PROOF }), {
            headers: { "content-type": "application/json" },
          });
    }) as typeof globalThis.fetch;
    const prover = new ProverClient({
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch,
    });

    await prover.prove(transferInputs());

    expect(urls.map((url) => url.pathname)).toEqual(["/zolana/prove", "/zolana/prove/status"]);
    expect(urls[1]?.searchParams.get("api-key")).toBe("k+1");
    expect(urls[1]?.searchParams.get("tenant")).toBe("alpha");
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
    const prover = new ProverClient({ url: "https://prover.example", fetch });
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
          keyName: "transfer_confidential_1_1.key",
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
        details: { keyName: "transfer_confidential_1_1.key" },
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
    const prover = new ProverClient({ url: "https://prover.example", fetch });
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
    entry(report, "merge_8_1.key")["expectedSha256"] = "ab".repeat(32);
    entry(report, "custom_ring_base.key")["loadedSha256"] = "cd".repeat(32);

    expect(await check(report)).toMatchObject({
      code: "CLIENT_PROVER_PROVING_KEYS_MISMATCH",
      details: { keyNames: "custom_ring_base.key,merge_8_1.key" },
    });
  });

  it("reports a key the prover lacks or cannot load without failing", async () => {
    const report = matchingReport();
    report.keys = report.keys.filter((key) => key["name"] !== "merge_36_1.key");
    entry(report, "transfer_ring_36_2.key")["available"] = false;

    const result = (await check(report)) as {
      keys: { name: string; served: boolean; available: boolean }[];
    };
    expect(
      result.keys.filter((key) => ["merge_36_1.key", "transfer_ring_36_2.key"].includes(key.name)),
    ).toEqual([
      { name: "merge_36_1.key", served: false, available: false, loaded: false },
      { name: "transfer_ring_36_2.key", served: true, available: false, loaded: false },
    ]);
  });

  it("rejects a malformed report instead of skipping keys", async () => {
    const malformed: unknown[] = [
      [],
      { keys: [] },
      { prefix: "p", keys: {} },
      { prefix: "p", keys: [{ name: "merge_8_1.key", loadedSha256: null, available: true }] },
      {
        prefix: "p",
        keys: [
          {
            name: "merge_8_1.key",
            expectedSha256: "AB".repeat(32),
            loadedSha256: null,
            available: true,
          },
        ],
      },
      {
        prefix: "p",
        keys: [{ name: "merge_8_1.key", expectedSha256: null, loadedSha256: 7, available: true }],
      },
      {
        prefix: "p",
        keys: [
          { name: "merge_8_1.key", expectedSha256: null, loadedSha256: null, available: "yes" },
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
    const prover = new ProverClient({ url: "https://prover.example", fetch });
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
