import { ZolanaApi } from "@zolana/api";
import { hash } from "@zolana/indexer-api";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import type { InputUtxoContext } from "@zolana/transaction";
import { afterEach, describe, expect, it, vi } from "vitest";

import rpcFixture from "../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import {
  ClientError,
  type Rpc,
  type SpendProof,
  ZolanaClient,
  ZolanaIndexer,
} from "../src/index.js";
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

  it("stops on the first attempt when the indexer rejects the request", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          Response.json({
            id: "test-account",
            jsonrpc: "2.0",
            error: { code: -32602, message: "unknown tree" },
          }),
        );
      }),
    });
    const pending = new ZolanaIndexer(api).getMerkleProofs(TREE, [ZERO], {
      waitForIndexer: true,
      poll: { numRetries: 4, delayMs: 5n, maxDelayMs: 12n },
    });
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({
        code: "CLIENT_INDEXER",
        details: { method: "getMerkleProofs", retryable: false },
      }),
    );
    await vi.runAllTimersAsync();
    await rejection;

    expect(calls).toBe(1);
  });

  it("keeps the timeout and its cause when every attempt fails transiently", async () => {
    vi.useFakeTimers();
    const secret = "queue depth 42 for account alice";
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(new Response(secret, { status: 503 }));
      }),
    });
    const pending = new ZolanaIndexer(api).getMerkleProofs(TREE, [ZERO], {
      waitForIndexer: true,
      poll: { numRetries: 2, delayMs: 5n, maxDelayMs: 12n },
    });
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({
        code: "CLIENT_POLL_TIMED_OUT",
        details: { attempts: 3, lastCause: { category: "indexer" } },
      }),
    );
    await vi.runAllTimersAsync();
    await rejection;

    expect(calls).toBe(3);
    expect(JSON.stringify(await pending.catch((cause: unknown) => cause))).not.toContain(secret);
  });

  // Blocking Rust polls until proofs.len() >= leaves.len() when wait_for_indexer
  // is unset. The async twin returns whatever arrived; so does Light. An
  // incomplete answer must stay incomplete after one request here.
  it("returns an incomplete proof set without polling for leaf coverage", async () => {
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          envelope({
            context: { block_time: 123 },
            proofs: [merkle(hash(ZERO))],
          }),
        );
      }),
    });
    const response = await new ZolanaIndexer(api).getMerkleProofs(TREE, [ZERO, ONE]);

    expect(calls).toBe(1);
    expect(response.context.blockTime).toBe(123n);
    expect(response.proofs).toHaveLength(1);
    expect(response.proofs[0]?.leaf).toEqual(ZERO);
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

  /// Rust finishes one proof before starting the other: state leaf, state tree,
  /// nullifier leaf, nullifier tree (`validate_spend_proofs`,
  /// `sdk-libs/client/src/client.rs`). TypeScript checked both leaves first, so a
  /// pair wrong in both ways named a different field than Rust names. Same
  /// accept/reject set either way; the divergence is only which error a caller
  /// sees, which is what a caller branches on.
  it("reports the field Rust reports when a pair is wrong in two ways", async () => {
    vi.useFakeTimers();
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((request) => {
        const url = request instanceof Request ? request.url : String(request);
        // Nullifier leaf is wrong: the input's nullifier is ZERO, not ONE.
        if (url.includes("get_non_inclusion_proofs")) {
          return Promise.resolve(
            envelope({
              context: { block_time: 1 },
              proofs: [nonInclusion(encodeBase58(ONE))],
            }),
          );
        }
        // State leaf is right, but it sits in a tree this client does not hold.
        return Promise.resolve(
          envelope({
            context: { block_time: 1 },
            proofs: [
              {
                ...merkle(HASH),
                merkle_context: { tree_type: 1, tree: encodeBase58(ONE) },
              },
            ],
          }),
        );
      }),
    });
    const value = client(new ZolanaIndexer(api), fakeRpc());
    const pending = value
      .getInputMerkleProofs([{ index: 0, utxoHash: ZERO, nullifier: ZERO }])
      .then(() => undefined)
      .catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    const rejection = await pending;
    expect(rejection).toBeInstanceOf(ClientError);
    expect((rejection as ClientError).code).toBe("CLIENT_STATE_PROOF_TREE_MISMATCH");
  });

  /// `finish_submission_unsigned` validates the fee payer before the tree
  /// (`sdk-libs/client/src/client.rs`). TypeScript had them the other way round,
  /// so a caller wrong in both ways was told to fix the tree while the fee payer
  /// they control was also wrong. Both orders reject; only one names the same
  /// field Rust names.
  it("names the fee payer before the tree, as Rust does", async () => {
    const value = client(new ZolanaIndexer(new ZolanaApi({ url: "https://x.test" })), fakeRpc());
    const rejection = await value
      .finishSubmissionUnsigned({
        // Neither the tree nor the payer hash matches, so the order decides.
        signed: {
          tree: encodeBase58(ONE) as Address,
          transaction: { payerPublicKeyHash: ONE },
        } as unknown as Parameters<typeof value.finishSubmissionUnsigned>[0]["signed"],
        feePayer: TREE,
        recentBlockhash: encodeBase58(ONE),
      })
      .then(() => undefined)
      .catch((error: unknown) => error);
    expect(rejection).toBeInstanceOf(ClientError);
    expect((rejection as ClientError).code).toBe("CLIENT_FEE_PAYER_MISMATCH");
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

  // `wait_for_indexed_transaction` in `sdk-libs/client/src/client.rs` accepts on
  // `item.tx_signature == signature` and looks at nothing else. Requiring every
  // requested tag to reappear in `output_slots`/`messages` made this reject a
  // record Rust confirms.
  it("confirms the record Rust confirms, without re-checking where the tags landed", async () => {
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
                tx_signature: SIGNATURE,
                tx_viewing_pk: null,
                salt: null,
                output_slots: [],
                messages: [],
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
      transactOutputViewTags: () => Promise.resolve([ZERO, ONE]),
    });
    const pending = client(new ZolanaIndexer(api), rpc).confirmPrivateTransaction(SIGNATURE);
    await vi.runAllTimersAsync();

    await expect(pending).resolves.toBeUndefined();
  });

  // `wait_for_indexed_transaction` passes `Some(50)`. Sending no limit left the
  // page size to the server.
  it("asks for the same page size the Rust confirmation asks for", async () => {
    vi.useFakeTimers();
    const bodies: unknown[] = [];
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((_url: unknown, init?: RequestInit) => {
        bodies.push(JSON.parse(typeof init?.body === "string" ? init.body : ""));
        return Promise.resolve(
          envelope({
            context: { block_time: 1 },
            transactions: [
              {
                slot: 1,
                tx_signature: SIGNATURE,
                tx_viewing_pk: null,
                salt: null,
                output_slots: [],
                messages: [],
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
    await vi.runAllTimersAsync();
    await pending;

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ params: { limit: 50 } });
  });

  // Rust polls `self.indexer_config.poll`, which `with_indexer_poll_config`
  // overrides. Confirmation used the hard-coded default here, so a caller who
  // configured a shorter schedule still waited out the default.
  it("honors the configured poll schedule rather than the default", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          envelope({
            context: { block_time: 1 },
            transactions: [],
            next_cursor: null,
          }),
        );
      }),
    });
    const rpc = fakeRpc({
      confirmTransaction: () => Promise.resolve(true),
      transactOutputViewTags: () => Promise.resolve([ZERO]),
    });
    const configured = new ZolanaClient({
      rpc,
      indexer: new ZolanaIndexer(api),
      prover: new ProverClient({
        url: "https://prover.example.test",
        fetch: vi.fn(() => Promise.reject(new Error("prover must not be called"))),
      }),
      tree: TREE,
      indexerConfig: {
        waitForIndexer: false,
        poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
      },
    });
    expect(configured.indexerConfig.poll.numRetries).toBe(1);

    const pending = configured.confirmPrivateTransaction(SIGNATURE);
    const rejection = expect(pending).rejects.toMatchObject({
      code: "CLIENT_INDEXER_TIMEOUT",
      details: { attempts: 2 },
    });
    await vi.runAllTimersAsync();
    await rejection;
    expect(calls).toBe(2);
  });

  // Every delegating indexer method in Rust passes
  // `Some(config.unwrap_or(self.indexer_config))`, so a caller who omits the
  // config gets the client's. Forwarding `undefined` handed the decision to
  // `ZolanaIndexer`, which applies its own default and ignores the client's
  // `waitForIndexer`.
  it("substitutes its own indexer config when the caller omits one", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        return Promise.resolve(
          envelope({ context: { block_time: 0 }, proofs: [merkle(HASH)] }),
        );
      }),
    });
    const configured = new ZolanaClient({
      rpc: fakeRpc(),
      indexer: new ZolanaIndexer(api),
      prover: new ProverClient({
        url: "https://prover.example.test",
        fetch: vi.fn(() => Promise.reject(new Error("prover must not be called"))),
      }),
      tree: TREE,
      // `wait_for_indexer` with a `block_time` of 0 never catches up, so the
      // client's config is observable: the call fails as not caught up instead
      // of returning the proof the indexer default would accept.
      indexerConfig: {
        waitForIndexer: true,
        poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
      },
    });

    const pending = configured.getMerkleProofs(TREE, [ZERO]);
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({ code: "CLIENT_INDEXER_NOT_CAUGHT_UP" }),
    );
    await vi.runAllTimersAsync();
    await rejection;
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
