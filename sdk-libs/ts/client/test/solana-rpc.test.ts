import {
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import proverFixture from "../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import rpcFixture from "../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import { ClientError, SolanaRpc } from "../src/index.js";
import { encodeBase58 } from "../src/internal.js";
import { bytes, hex } from "./helpers/prover-vectors.js";

const ZERO_ADDRESS = "1".repeat(32) as Address;
const ZERO_SIGNATURE = "1".repeat(64) as Signature;

function rpcResult(id: number, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<ClientError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return error as ClientError;
  }
  throw new Error("expected client call to fail");
}

describe("SolanaRpc", () => {
  it("sends exact JSON-RPC requests and converts integer results without precision loss", async () => {
    const fetch = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(init?.headers).toEqual({ "content-type": "application/json" });
      expect(JSON.parse(typeof init?.body === "string" ? init.body : "")).toEqual({
        jsonrpc: "2.0",
        id: 1,
        method: "getBalance",
        params: [ZERO_ADDRESS, { commitment: "confirmed" }],
      });
      return Promise.resolve(rpcResult(1, { value: Number.MAX_SAFE_INTEGER }));
    });
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });

    await expect(rpc.getBalance(ZERO_ADDRESS)).resolves.toBe(BigInt(Number.MAX_SAFE_INTEGER));
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("rejects malformed envelopes, unsafe integers, and account encoding", async () => {
    const responses = [
      Response.json({ jsonrpc: "2.0", id: 9, result: { value: 1 } }),
      rpcResult(2, { value: Number.MAX_SAFE_INTEGER + 1 }),
      rpcResult(3, {
        value: { owner: ZERO_ADDRESS, lamports: 1, data: ["AA==", "base58"] },
      }),
    ];
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() => Promise.resolve(responses.shift() ?? rpcResult(0, null))),
    });

    await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_RPC_ENVELOPE");
    await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_INVALID_RPC_RESPONSE");
    await expectCode(rpc.getAccount(ZERO_ADDRESS), "CLIENT_INVALID_RPC_RESPONSE");
  });

  it("serializes unsigned native transactions with zero signature slots", async () => {
    const fetch = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
        id: number;
        params: readonly [string, unknown];
      };
      const serialized = Uint8Array.from(globalThis.atob(body.params[0]), (character) =>
        character.charCodeAt(0),
      );
      expect(serialized).toEqual(Uint8Array.from([1, ...new Uint8Array(64), 9, 8, 7]));
      return Promise.resolve(rpcResult(body.id, ZERO_SIGNATURE));
    });
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
    const transaction: Transaction = {
      messageBytes: Uint8Array.of(9, 8, 7),
      signatures: [undefined],
    };

    await expect(rpc.sendTransaction(transaction)).resolves.toBe(ZERO_SIGNATURE);
  });

  it("distinguishes cancellation from timeout", async () => {
    const fetch = vi.fn(
      (_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
    const controller = new AbortController();
    const aborted = rpc.getBalance(ZERO_ADDRESS, { signal: controller.signal });
    controller.abort();

    await expectCode(aborted, "CLIENT_ABORTED");
    await expectCode(rpc.getBalance(ZERO_ADDRESS, { timeoutMs: 1 }), "CLIENT_TIMEOUT");
  });

  it("extracts the frozen sorted tags from direct and inner transact instructions", async () => {
    const shape = proverFixture.expected.rails[0]?.shapes.find(
      (value) => value.shape.inputs === "1" && value.shape.outputs === "2",
    );
    if (!shape) throw new Error("missing RPC fixture shape");
    const instruction = {
      programIdIndex: 0,
      accounts: [],
      data: encodeBase58(Uint8Array.from([0, ...bytes(shape.transactIxData.afterProofBytes)])),
    };
    const variants = [
      {
        transaction: {
          message: { accountKeys: [SHIELDED_POOL_PROGRAM_ID], instructions: [instruction] },
        },
        meta: { innerInstructions: [] },
      },
      {
        transaction: {
          message: { accountKeys: [SHIELDED_POOL_PROGRAM_ID], instructions: [] },
        },
        meta: { innerInstructions: [{ index: 0, instructions: [instruction] }] },
      },
    ];
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
        const request = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
          id: number;
        };
        return Promise.resolve(rpcResult(request.id, variants.shift()));
      }),
    });

    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.directTags,
    );
    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.innerTags,
    );
  });

  it("rejects a confirmed transaction without a transact instruction", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          rpcResult(1, {
            transaction: { message: { accountKeys: [ZERO_ADDRESS], instructions: [] } },
            meta: { innerInstructions: [] },
          }),
        ),
      ),
    });

    await expectCode(rpc.transactOutputViewTags(ZERO_SIGNATURE), "CLIENT_RPC_TRANSACT_NOT_FOUND");
    expect(rpcFixture.expected.confirmation.missingTransactError.code).toBe("Rpc");
  });
});
