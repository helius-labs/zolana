import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { ApiError, ZolanaApi } from "../src/index.js";

const HASH = "11111111111111111111111111111111";
const REQUEST = { treeAccount: HASH, leaves: [HASH] } as never;

describe("transport properties", () => {
  it("classifies every HTTP error without retaining its body", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 400, max: 599 }),
        fc.stringMatching(/^s3cr3t_[A-Za-z]{16,64}$/),
        async (status, reflectedSecret) => {
          const api = new ZolanaApi({
            url: `https://rpc.example.test?api-key=${encodeURIComponent(reflectedSecret)}`,
            fetch: () =>
              Promise.resolve(
                new Response(reflectedSecret, {
                  status,
                  headers: { "content-type": "text/plain" },
                }),
              ),
          });

          try {
            await api.getMerkleProofs(REQUEST);
          } catch (error) {
            expect(error).toBeInstanceOf(ApiError);
            expect((error as ApiError).code).toBe("API_HTTP");
            expect((error as ApiError).details?.["retryable"]).toBe(
              status === 408 || status === 425 || status === 429 || status >= 500,
            );
            expect(JSON.stringify(error)).not.toContain(reflectedSecret);
            return;
          }
          throw new Error("expected HTTP failure");
        },
      ),
      { numRuns: 100 },
    );
  });

  it("does not retain unknown response field names", async () => {
    await fc.assert(
      fc.asyncProperty(fc.stringMatching(/^private_[A-Za-z0-9]{1,64}$/), async (field) => {
        const api = new ZolanaApi({
          url: "https://rpc.example.test",
          fetch: () =>
            Promise.resolve(
              new Response(
                JSON.stringify({
                  id: "test-account",
                  jsonrpc: "2.0",
                  result: {
                    context: { block_time: 0 },
                    proofs: [],
                    [field]: true,
                  },
                }),
                { headers: { "content-type": "application/json" } },
              ),
            ),
        });

        try {
          await api.getMerkleProofs(REQUEST);
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).code).toBe("API_INVALID_RESULT");
          expect(JSON.stringify(error)).not.toContain(field);
          return;
        }
        throw new Error("expected schema failure");
      }),
      { numRuns: 100 },
    );
  });
});
