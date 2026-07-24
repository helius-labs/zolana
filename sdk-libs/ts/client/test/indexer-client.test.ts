import { ZolanaApi } from "@zolana/api";
import { hash } from "@zolana/indexer-api";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import type { InputUtxoContext } from "@zolana/transaction";
import { afterEach, describe, expect, it, vi } from "vitest";

import rpcFixture from "../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import { type Rpc, type SpendProof, ZolanaClient, ZolanaIndexer } from "../src/index.js";
import { encodeBase58 } from "../src/internal.js";
import { ProverClient } from "../src/prover/index.js";
import { bytes, hex } from "./helpers/prover-vectors.js";

const HASH = "1".repeat(32);
const TREE = HASH as Address;
const SIGNATURE = "1".repeat(64) as Signature;
const WRONG_SIGNATURE = encodeBase58(new Uint8Array(64).fill(1)) as Signature;
const ZERO = new Uint8Array(32) as Bytes32;
const ONE = new Uint8Array(32).fill(1) as Bytes32;

function envelope(result: unknown): Response {
  return Response.json({ id: "test-account", jsonrpc: "2.0", result });
}

function merkle(leaf: string, path: readonly string[] = []): Record<string, unknown> {
  return {
    leaf,
    merkle_context: { tree_type: 1, tree: TREE },
    path,
    leaf_index: 7,
    root: HASH,
    root_seq: 8,
    root_index: 9,
  };
}

function nonInclusion(leaf: string): Record<string, unknown> {
  return {
    leaf,
    merkle_context: { tree_type: 1, tree: TREE },
    path: [],
    low_element: HASH,
    low_element_index: 3,
    high_element: HASH,
    high_element_index: 4,
    root: HASH,
    root_seq: 8,
    root_index: 9,
  };
}

function fakeRpc(overrides: Partial<Rpc> = {}): Rpc {
  const unsupported = (): Promise<never> => Promise.reject(new Error("unsupported"));
  return {
    getAccount: unsupported,
    getMultipleAccounts: unsupported,
    getBalance: unsupported,
    getLatestBlockhash: unsupported,
    sendTransaction: unsupported,
    confirmTransaction: unsupported,
    transactOutputViewTags: unsupported,
    getMerkleProofs: unsupported,
    getNonInclusionProofs: unsupported,
    getInputMerkleProofs: unsupported,
    ...overrides,
  };
}

function client(indexer: ZolanaIndexer, rpc: Rpc): ZolanaClient {
  return new ZolanaClient({
    rpc,
    indexer,
    prover: new ProverClient({
      url: "https://prover.example.test",
      fetch: vi.fn(() => Promise.reject(new Error("prover must not be called"))),
    }),
    tree: TREE,
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ZolanaIndexer and ZolanaClient", () => {
  it("converts every frozen Merkle and non-inclusion response field", async () => {
    const merkle = rpcFixture.expected.indexer.merkle;
    const nonInclusion = rpcFixture.expected.indexer.nonInclusion;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((request) => {
        const url = String(request);
        const proof = url.includes("get_non_inclusion_proofs")
          ? {
              leaf: encodeBase58(bytes(nonInclusion.leafBytes)),
              merkle_context: { tree_type: 2, tree: nonInclusion.tree },
              path: nonInclusion.pathBytes.map((value) => encodeBase58(bytes(value))),
              low_element: encodeBase58(bytes(nonInclusion.lowElementBytes)),
              low_element_index: Number(nonInclusion.lowElementIndex),
              high_element: encodeBase58(bytes(nonInclusion.highElementBytes)),
              high_element_index: Number(nonInclusion.highElementIndex),
              root: encodeBase58(bytes(nonInclusion.rootBytes)),
              root_seq: Number(nonInclusion.rootSeq),
              root_index: Number(nonInclusion.rootIndex),
            }
          : {
              leaf: encodeBase58(bytes(merkle.leafBytes)),
              merkle_context: { tree_type: 1, tree: merkle.tree },
              path: merkle.pathBytes.map((value) => encodeBase58(bytes(value))),
              leaf_index: Number(merkle.leafIndex),
              root: encodeBase58(bytes(merkle.rootBytes)),
              root_seq: Number(merkle.rootSeq),
              root_index: Number(merkle.rootIndex),
            };
        return Promise.resolve(envelope({ context: { block_time: 100 }, proofs: [proof] }));
      }),
    });
    const indexer = new ZolanaIndexer(api);
    const state = (
      await indexer.getMerkleProofs(merkle.tree as Address, [bytes(merkle.leafBytes) as Bytes32])
    ).proofs[0];
    const nullifier = (
      await indexer.getNonInclusionProofs(nonInclusion.tree as Address, [
        bytes(nonInclusion.leafBytes) as Bytes32,
      ])
    ).proofs[0];

    expect(
      state && {
        leafBytes: hex(state.leaf),
        pathBytes: state.path.map(hex),
        leafIndex: state.leafIndex.toString(),
        rootBytes: hex(state.root),
        rootSeq: state.rootSeq.toString(),
        rootIndex: state.rootIndex.toString(),
        tree: state.merkleContext.tree,
      },
    ).toEqual(merkle);
    expect(
      nullifier && {
        leafBytes: hex(nullifier.leaf),
        pathBytes: nullifier.path.map(hex),
        lowElementBytes: hex(nullifier.lowElement),
        lowElementIndex: nullifier.lowElementIndex.toString(),
        highElementBytes: hex(nullifier.highElement),
        highElementIndex: nullifier.highElementIndex.toString(),
        rootBytes: hex(nullifier.root),
        rootSeq: nullifier.rootSeq.toString(),
        rootIndex: nullifier.rootIndex.toString(),
        tree: nullifier.merkleContext.tree,
      },
    ).toEqual(nonInclusion);
  });

  it("uses the frozen capped retry schedule and reports lag", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(100_000);
    const calls: number[] = [];
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls.push(Date.now());
        return Promise.resolve(envelope({ context: { block_time: 99 }, proofs: [] }));
      }),
    });
    const pending = new ZolanaIndexer(api).getMerkleProofs(TREE, [ZERO], {
      waitForIndexer: true,
      poll: { numRetries: 4, delayMs: 5n, maxDelayMs: 12n },
    });
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({
        code: "CLIENT_INDEXER_NOT_CAUGHT_UP",
        details: { target: "100", latest: "99", attempts: 5 },
      }),
    );
    await vi.runAllTimersAsync();
    await rejection;

    expect(calls.slice(1).map((value, index) => value - (calls[index] ?? value))).toEqual(
      rpcFixture.expected.retry.delaysMs.map(Number),
    );
    expect(calls).toHaveLength(Number(rpcFixture.expected.retry.attempts));
  });

  it("strictly converts Merkle proof bytes and polls until every proof is available", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          envelope({
            context: { block_time: 123 },
            proofs: calls === 1 ? [] : [merkle(HASH, [HASH])],
          }),
        );
      }),
    });
    const pending = new ZolanaIndexer(api).getMerkleProofs(TREE, [ZERO]);
    await vi.advanceTimersByTimeAsync(500);
    const response = await pending;

    expect(calls).toBe(2);
    expect(response.context.blockTime).toBe(123n);
    expect(response.proofs[0]).toEqual({
      leaf: ZERO,
      merkleContext: { treeType: 1, tree: TREE },
      path: [ZERO],
      leafIndex: 7n,
      root: ZERO,
      rootSeq: 8n,
      rootIndex: 9,
    });
  });

  it("pairs state and nullifier proofs in input order and rejects reordered leaves", async () => {
    vi.useFakeTimers();
    let reverseState = false;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((request) => {
        const url =
          request instanceof Request
            ? request.url
            : request instanceof URL
              ? request.href
              : String(request);
        if (url.includes("get_non_inclusion_proofs")) {
          return Promise.resolve(
            envelope({
              context: { block_time: 1 },
              proofs: [nonInclusion(HASH), nonInclusion(encodeBase58(ONE))],
            }),
          );
        }
        return Promise.resolve(
          envelope({
            context: { block_time: 1 },
            proofs: reverseState
              ? [merkle(encodeBase58(ONE)), merkle(HASH)]
              : [merkle(HASH), merkle(encodeBase58(ONE))],
          }),
        );
      }),
    });
    const value = client(new ZolanaIndexer(api), fakeRpc());
    const inputs: readonly InputUtxoContext[] = [
      { index: 0, utxoHash: ZERO, nullifier: ZERO },
      { index: 1, utxoHash: ONE, nullifier: ONE },
    ];
    await expect(
      api.getMerkleProofs({ treeAccount: TREE, leaves: [hash(ZERO), hash(ONE)] }),
    ).resolves.toBeDefined();
    await expect(
      api.getNonInclusionProofs({ treeAccount: TREE, leaves: [hash(ZERO), hash(ONE)] }),
    ).resolves.toBeDefined();

    const first = value.getInputMerkleProofs(inputs);
    await vi.runAllTimersAsync();
    const proofs = await first;
    expect(proofs.map((proof: SpendProof) => proof.state.leaf)).toEqual([ZERO, ONE]);

    reverseState = true;
    const reordered = value.getInputMerkleProofs(inputs);
    const rejection = expect(reordered).rejects.toEqual(
      expect.objectContaining({ code: "CLIENT_STATE_PROOF_LEAF_MISMATCH" }),
    );
    await vi.runAllTimersAsync();
    await rejection;
  });

  it("requires Photon to return the submitted signature, not merely a matching tag", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          envelope({
            context: { block_time: 1 },
            transactions: [
              {
                slot: 1,
                tx_signature: calls === 1 ? WRONG_SIGNATURE : SIGNATURE,
                tx_viewing_pk: null,
                salt: null,
                output_slots: [],
                messages: [{ view_tag: HASH, payload: "" }],
                nullifiers: [],
                proofless: true,
              },
            ],
            next_cursor: null,
          }),
        );
      }),
    });
    const rpc = fakeRpc({
      confirmTransaction: () => Promise.resolve(true),
      transactOutputViewTags: () => Promise.resolve([ZERO]),
    });
    const pending = client(new ZolanaIndexer(api), rpc).confirmPrivateTransaction(SIGNATURE);
    await vi.advanceTimersByTimeAsync(400);

    await expect(pending).resolves.toBeUndefined();
    expect(calls).toBe(2);
  });

  it("rejects a wrong-signature Photon response after the bounded retry schedule", async () => {
    vi.useFakeTimers();
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          envelope({
            context: { block_time: 1 },
            transactions: [
              {
                slot: 1,
                tx_signature: WRONG_SIGNATURE,
                tx_viewing_pk: null,
                salt: null,
                output_slots: [],
                messages: [{ view_tag: HASH, payload: "" }],
                nullifiers: [],
                proofless: true,
              },
            ],
            next_cursor: null,
          }),
        ),
      ),
    });
    const rpc = fakeRpc({
      confirmTransaction: () => Promise.resolve(true),
      transactOutputViewTags: () => Promise.resolve([ZERO]),
    });
    const pending = client(new ZolanaIndexer(api), rpc).confirmPrivateTransaction(SIGNATURE);
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({ code: "CLIENT_INDEXER_TIMEOUT" }),
    );
    await vi.runAllTimersAsync();
    await rejection;
  });
});
