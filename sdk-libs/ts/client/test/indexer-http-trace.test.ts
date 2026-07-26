import { ZolanaApi } from "@zolana/api";
import type { Address, Bytes32 } from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import { ZolanaIndexer } from "../src/index.js";

/**
 * Pins the disposition of Rust's `ZolanaIndexer::with_http_trace`, which has no
 * method of that name here.
 *
 * Rust's builder flips a flag its `post` reads to print the request and the
 * response body to stdout, and its only callers are a localnet integration
 * test. This package is browser-compatible and writes to no console, so the
 * capability is the caller's `fetch` instead: it sees the same two bodies, at
 * the same two points, and the caller decides where they go. The observation
 * has to survive `ZolanaIndexer` wrapping the API, which is what this checks.
 *
 * `ZolanaIndexer::api()` has no counterpart for a different reason: it exists
 * in Rust because `ZolanaIndexer::new(url)` builds the API internally and the
 * accessor is the only way back to it. Here the constructor takes the API, so
 * the caller already holds it. Nothing in the repository calls the Rust
 * accessor.
 */

const TREE = "1".repeat(32) as Address;
const HASH = "1".repeat(32);

interface Trace {
  readonly url: string;
  readonly requestBody: string;
  readonly responseBody: string;
}

function proofsResponse(): unknown {
  return {
    id: "test-account",
    jsonrpc: "2.0",
    result: {
      context: { block_time: 1 },
      proofs: [
        {
          leaf: HASH,
          merkle_context: { tree_type: 1, tree: TREE },
          path: [],
          leaf_index: 7,
          root: HASH,
          root_seq: 8,
          root_index: 9,
        },
      ],
    },
  };
}

describe("indexer HTTP tracing", () => {
  it("gives a caller both bodies through the fetch the API was built with", async () => {
    const traced: Trace[] = [];
    const body = JSON.stringify(proofsResponse());
    const tracingFetch = vi.fn(async (url: URL | RequestInfo, init?: RequestInit) => {
      const response = new Response(body, { headers: { "content-type": "application/json" } });
      traced.push({
        url: String(url),
        requestBody: typeof init?.body === "string" ? init.body : "",
        responseBody: await response.clone().text(),
      });
      return response;
    });
    const indexer = new ZolanaIndexer(
      new ZolanaApi({ url: "https://indexer.example.test", fetch: tracingFetch }),
    );

    const leaf = new Uint8Array(32).fill(1) as Bytes32;
    await indexer.getMerkleProofs(TREE, [leaf]);

    expect(traced).toHaveLength(1);
    const [trace] = traced;
    expect(trace?.url).toBe("https://indexer.example.test/get_merkle_proofs");
    expect(JSON.parse(trace?.requestBody ?? "null")).toMatchObject({
      method: "get_merkle_proofs",
      params: { tree_account: TREE },
    });
    expect(trace?.responseBody).toBe(body);
  });
});
