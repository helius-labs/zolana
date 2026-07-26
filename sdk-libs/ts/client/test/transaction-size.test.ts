import type { Signature, Transaction } from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import { MAX_TRANSACTION_SIZE, SolanaRpc, transactionSize } from "../src/index.js";

const ZERO_SIGNATURE = "1".repeat(64) as Signature;

function rpcResult(id: number, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

/// Submits `transaction` and returns the byte length the RPC put on the wire.
async function submittedBytes(transaction: Transaction): Promise<number> {
  let submitted = 0;
  const fetch = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
    const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
      id: number;
      method: string;
      params: readonly [string, unknown];
    };
    if (body.method === "sendTransaction") {
      submitted = globalThis.atob(body.params[0]).length;
      return Promise.resolve(rpcResult(body.id, ZERO_SIGNATURE));
    }
    return Promise.resolve(
      rpcResult(body.id, { value: [{ err: null, confirmationStatus: "confirmed" }] }),
    );
  });

  const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
  await rpc.sendTransaction(transaction);
  return submitted;
}

function transaction(messageLength: number, signatureCount: number): Transaction {
  return {
    messageBytes: new Uint8Array(messageLength).fill(7),
    signatures: Array.from({ length: signatureCount }, () => undefined),
  };
}

describe("transaction size", () => {
  it("is the runtime's packet limit", () => {
    expect(MAX_TRANSACTION_SIZE).toBe(1232);
  });

  // 128 signatures is where the compact-u16 count grows to two bytes, so a
  // measurement that assumed one byte agrees below it and disagrees above.
  it.each([
    [3, 0],
    [3, 1],
    [200, 2],
    [200, 127],
    [200, 128],
  ])(
    "measures what the RPC puts on the wire for a %i-byte message with %i signatures",
    async (messageLength, signatureCount) => {
      const value = transaction(messageLength, signatureCount);

      expect(transactionSize(value)).toBe(await submittedBytes(value));
    },
  );

  // Rust compiles and submits an oversized transaction and lets the node refuse
  // it. Measuring the size must not turn that into a local refusal, or the port
  // would reject what the crate it ports accepts.
  it("measures an oversized transaction rather than refusing it", async () => {
    const value = transaction(MAX_TRANSACTION_SIZE, 1);

    expect(transactionSize(value)).toBeGreaterThan(MAX_TRANSACTION_SIZE);
    expect(await submittedBytes(value)).toBe(transactionSize(value));
  });
});
