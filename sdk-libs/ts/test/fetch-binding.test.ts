import { describe, expect, it, vi } from "vitest";

import { ZolanaApi } from "../src/api/index.js";
import { ProverClient } from "../src/client/prover/client.js";
import { RingRpc } from "../src/ring/rpc.js";

// A browser's `fetch` throws "Illegal invocation" unless called on the global,
// which a stored method reference is not. The stub enforces the same rule.
function strictFetch() {
  const calls: unknown[] = [];
  const fetch: typeof globalThis.fetch = function (
    this: unknown,
    ...args: Parameters<typeof globalThis.fetch>
  ) {
    if (this !== globalThis && this !== undefined) throw new TypeError("Illegal invocation");
    calls.push(args[0]);
    return Promise.resolve(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { mode: "local", servicePubkey: "11111111111111111111111111111111" },
        }),
        {
          headers: { "content-type": "application/json" },
        },
      ),
    );
  };
  return { fetch, calls };
}

describe("fetch binding", () => {
  it("calls the global fetch on the global in every client", async () => {
    const { fetch, calls } = strictFetch();
    vi.stubGlobal("fetch", fetch);
    try {
      await new RingRpc("http://ring.example", { allowInsecureHttp: true }).health();
      await new ZolanaApi({ url: "https://indexer.example" })
        .getEncryptedUtxosByTags({ tags: [] } as never)
        .catch(() => undefined);
      new ProverClient({ url: "https://prover.example" });
      expect(calls.length).toBeGreaterThanOrEqual(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
