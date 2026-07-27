import {
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  SolanaError,
  address,
  type Signature,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ClientError,
  ZolanaClient,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
} from "../src/client/index.js";
import { defaultSolanaRpcSubscriptionsUrl, runKitRpc } from "../src/client/kit.js";
import type { Bytes32 } from "../src/interface/index.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function client(fetch = vi.fn<typeof globalThis.fetch>()): ZolanaClient {
  return new ZolanaClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
    indexerUrl: "http://127.0.0.1:8784",
    proverUrl: "http://127.0.0.1:3001",
    tree: TREE,
    fetch,
    indexerConfig: {
      waitForIndexer: false,
      poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
    },
  });
}

describe("ZolanaClient", () => {
  it("uses Solana's adjacent WebSocket port for explicit local RPC ports", () => {
    expect(defaultSolanaRpcSubscriptionsUrl("http://127.0.0.1:8899/")).toBe("ws://127.0.0.1:8900/");
    expect(defaultSolanaRpcSubscriptionsUrl("https://api.devnet.solana.com/")).toBe(
      "wss://api.devnet.solana.com/",
    );
  });

  it("performs no eager network requests", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const instance = client(fetch);
    expect(instance.tree).toBe(TREE);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects malformed service URLs before any request", () => {
    expect(
      () =>
        new ZolanaClient({
          solanaRpcUrl: "file:///tmp/rpc",
          indexerUrl: "http://127.0.0.1:8784",
          proverUrl: "http://127.0.0.1:3001",
        }),
    ).toThrow(ClientError);
  });

  it("preserves unsupported RPC methods for feature fallbacks", async () => {
    await expect(
      runKitRpc("getProgramAccounts", undefined, async () => {
        throw new SolanaError(SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, {
          __serverMessage: "method not found",
        });
      }),
    ).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getProgramAccounts" },
    });
  });

  it("fetches state and nullifier proofs once and in parallel", async () => {
    const instance = client();
    const utxoHash = bytes(1);
    const nullifier = bytes(2);
    let resolveState!: (value: GetMerkleProofsResponse) => void;
    let resolveNullifier!: (value: GetNonInclusionProofsResponse) => void;
    const getMerkleProofs = vi
      .spyOn(instance, "getMerkleProofs")
      .mockImplementation(
        () => new Promise<GetMerkleProofsResponse>((resolve) => (resolveState = resolve)),
      );
    const getNonInclusionProofs = vi
      .spyOn(instance, "getNonInclusionProofs")
      .mockImplementation(
        () => new Promise<GetNonInclusionProofsResponse>((resolve) => (resolveNullifier = resolve)),
      );

    const pending = instance.getInputMerkleProofs([{ index: 0, utxoHash, nullifier }]);
    expect(getMerkleProofs).toHaveBeenCalledOnce();
    expect(getNonInclusionProofs).toHaveBeenCalledOnce();

    resolveState({
      context: { blockTime: 1n },
      proofs: [
        {
          leaf: utxoHash,
          merkleContext: { treeType: 1, tree: TREE },
          path: [],
          leafIndex: 0n,
          root: bytes(3),
          rootSeq: 1n,
          rootIndex: 4,
        },
      ],
    });
    resolveNullifier({
      context: { blockTime: 1n },
      proofs: [
        {
          leaf: nullifier,
          merkleContext: { treeType: 1, tree: TREE },
          path: [],
          lowElement: bytes(4),
          lowElementIndex: 0n,
          highElement: bytes(5),
          highElementIndex: 1n,
          root: bytes(6),
          rootSeq: 1n,
          rootIndex: 7,
        },
      ],
    });

    await expect(pending).resolves.toHaveLength(1);
  });

  it("polls Photon only until the submitted signature is visible", async () => {
    const instance = client();
    const getByTags = vi
      .spyOn(instance, "getShieldedTransactionsByTags")
      .mockResolvedValueOnce({
        context: { blockTime: 1n },
        transactions: [],
      })
      .mockResolvedValueOnce({
        context: { blockTime: 2n },
        transactions: [{ txSignature: SIGNATURE }] as never,
      });

    await instance.confirmPrivateTransaction(SIGNATURE, [bytes(9)]);
    expect(getByTags).toHaveBeenCalledTimes(2);
  });

  it("follows every Photon page while confirming a reused output tag", async () => {
    const instance = client();
    const cursor = Uint8Array.of(7);
    const getByTags = vi
      .spyOn(instance, "getShieldedTransactionsByTags")
      .mockResolvedValueOnce({
        context: { blockTime: 1n },
        transactions: Array.from({ length: 100 }, () => ({
          txSignature: "2".repeat(64) as Signature,
        })) as never,
        nextCursor: cursor,
      })
      .mockResolvedValueOnce({
        context: { blockTime: 2n },
        transactions: [{ txSignature: SIGNATURE }] as never,
      });

    await instance.confirmPrivateTransaction(SIGNATURE, [bytes(9)]);

    expect(getByTags).toHaveBeenCalledTimes(2);
    expect(getByTags).toHaveBeenLastCalledWith(
      { tags: [bytes(9)], limit: 100, cursor },
      {
        waitForIndexer: false,
        poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
      },
      undefined,
    );
  });
});
