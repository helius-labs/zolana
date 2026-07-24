import { describe, expect, it } from "vitest";

import { ZolanaApi } from "../src/index.js";

const HASH = "11111111111111111111111111111111";
const ADDRESS = HASH;

interface CapturedRequest {
  readonly body: string;
  readonly headers: Headers;
  readonly method: string;
  readonly url: string;
}

function jsonResponse(result: unknown): Response {
  return new Response(
    JSON.stringify({
      id: "test-account",
      jsonrpc: "2.0",
      result,
    }),
    { headers: { "content-type": "application/json" } },
  );
}

async function captureCall(
  invoke: (api: ZolanaApi) => Promise<unknown>,
  result: unknown,
): Promise<CapturedRequest> {
  let captured: CapturedRequest | undefined;
  const api = new ZolanaApi({
    url: "https://rpc.example.test/base?api-key=test-secret",
    fetch: (input, init) => {
      if (typeof init?.body !== "string") throw new Error("expected a string request body");
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      captured = {
        body: init.body,
        headers: new Headers(init.headers),
        method: init.method ?? "",
        url,
      };
      return Promise.resolve(jsonResponse(result));
    },
  });

  await invoke(api);
  if (captured === undefined) throw new Error("request was not captured");
  return captured;
}

describe("JSON-RPC request vectors", () => {
  it("sends the exact encrypted UTXO request", async () => {
    const request = await captureCall(
      (api) =>
        api.getEncryptedUtxosByTags({
          tags: [HASH],
          cursor: "AQ==",
          limit: 1000n,
        } as never),
      { context: { block_time: 1 }, matches: [], next_cursor: null },
    );

    expect(request).toEqual({
      body: '{"id":"test-account","jsonrpc":"2.0","method":"get_encrypted_utxos_by_tags","params":{"tags":["11111111111111111111111111111111"],"cursor":"AQ==","limit":1000}}',
      headers: new Headers({ "content-type": "application/json" }),
      method: "POST",
      url: "https://rpc.example.test/base/get_encrypted_utxos_by_tags?api-key=test-secret",
    });
  });

  it("sends the exact shielded transaction request", async () => {
    const request = await captureCall(
      (api) => api.getShieldedTransactionsByTags({ tags: [HASH] } as never),
      { context: { block_time: 2 }, transactions: [], next_cursor: null },
    );

    expect(request.body).toBe(
      '{"id":"test-account","jsonrpc":"2.0","method":"get_shielded_transactions_by_tags","params":{"tags":["11111111111111111111111111111111"]}}',
    );
    expect(request.url).toBe(
      "https://rpc.example.test/base/get_shielded_transactions_by_tags?api-key=test-secret",
    );
  });

  it("sends the exact Merkle proof request", async () => {
    const request = await captureCall(
      (api) => api.getMerkleProofs({ treeAccount: ADDRESS, leaves: [HASH] } as never),
      { context: { block_time: 3 }, proofs: [] },
    );

    expect(request.body).toBe(
      '{"id":"test-account","jsonrpc":"2.0","method":"get_merkle_proofs","params":{"tree_account":"11111111111111111111111111111111","leaves":["11111111111111111111111111111111"]}}',
    );
    expect(request.url).toBe("https://rpc.example.test/base/get_merkle_proofs?api-key=test-secret");
  });

  it("sends the exact non-inclusion proof request", async () => {
    const request = await captureCall(
      (api) => api.getNonInclusionProofs({ treeAccount: ADDRESS, leaves: [HASH] } as never),
      { context: { block_time: 4 }, proofs: [] },
    );

    expect(request.body).toBe(
      '{"id":"test-account","jsonrpc":"2.0","method":"get_non_inclusion_proofs","params":{"tree_account":"11111111111111111111111111111111","leaves":["11111111111111111111111111111111"]}}',
    );
    expect(request.url).toBe(
      "https://rpc.example.test/base/get_non_inclusion_proofs?api-key=test-secret",
    );
  });

  it("sends the exact nullifier queue request with its default sequence", async () => {
    const request = await captureCall(
      (api) => api.getNullifierQueueElements({ treeAccount: ADDRESS, limit: 1n } as never),
      { context: { block_time: 5 }, elements: [] },
    );

    expect(request.body).toBe(
      '{"id":"test-account","jsonrpc":"2.0","method":"get_nullifier_queue_elements","params":{"tree_account":"11111111111111111111111111111111","start_seq":0,"limit":1}}',
    );
    expect(request.url).toBe(
      "https://rpc.example.test/base/get_nullifier_queue_elements?api-key=test-secret",
    );
  });

  it("returns schema-owned bigint values unchanged by the transport", async () => {
    const api = new ZolanaApi({
      url: "https://rpc.example.test",
      fetch: () =>
        Promise.resolve(
          jsonResponse({
            context: { block_time: 17 },
            elements: [{ seq: 9, value: HASH }],
          }),
        ),
    });

    await expect(
      api.getNullifierQueueElements({
        treeAccount: ADDRESS,
        startSeq: 7n,
        limit: 2n,
      } as never),
    ).resolves.toEqual({
      context: { blockTime: 17n },
      elements: [{ seq: 9n, value: HASH }],
    });
  });
});
