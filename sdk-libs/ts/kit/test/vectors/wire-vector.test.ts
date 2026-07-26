import { getBase64EncodedWireTransaction } from "@solana/kit";
import { compileTransaction, SolanaRpc } from "@zolana/client";
import {
  encodeBase58,
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { describe, expect, it } from "vitest";

import { fromKitTransaction, toKitTransaction } from "../../src/index.js";

const PAYER = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const COSIGNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const BLOCKHASH = "9zc4tqzHYbHRfnGYTVQVEBnHmXfDMFdKCUYzGvLbNZcm";

function signature(seed: number): Signature {
  return encodeBase58(new Uint8Array(64).fill(seed)) as Signature;
}

/** Two required signers so a partial-sign case is visible. */
const MESSAGE_BYTES = compileTransaction({
  feePayer: PAYER,
  recentBlockhash: BLOCKHASH,
  instructions: [
    {
      programAddress: SHIELDED_POOL_PROGRAM_ID,
      accounts: [
        { address: PAYER, isSigner: true, isWritable: true },
        { address: COSIGNER, isSigner: true, isWritable: false },
      ],
      data: Uint8Array.of(7, 7, 7),
    },
  ],
}).messageBytes;

function transaction(signatures: readonly (Signature | undefined)[]): Transaction {
  return Object.freeze({
    messageBytes: new Uint8Array(MESSAGE_BYTES),
    signatures: Object.freeze(signatures),
  });
}

function jsonResponse(id: unknown, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, ...body }), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

/**
 * Base64 payload `SolanaRpc.sendTransaction` sends, captured via a stub
 * transport. Avoids exporting Zolana's serializer as a test oracle.
 */
async function zolanaWireTransaction(value: Transaction): Promise<string> {
  let captured: string | undefined;
  const stub = (_url: unknown, init?: Readonly<{ body?: string }>): Promise<Response> => {
    const request = JSON.parse(init?.body ?? "{}") as {
      id: unknown;
      method: string;
      params: readonly unknown[];
    };
    if (request.method === "sendTransaction") {
      captured = request.params[0] as string;
      return Promise.resolve(jsonResponse(request.id, { result: signature(9) }));
    }
    return Promise.resolve(
      jsonResponse(request.id, {
        result: {
          context: { slot: 1 },
          value: [{ slot: 1, confirmations: null, confirmationStatus: "finalized", err: null }],
        },
      }),
    );
  };
  const rpc = new SolanaRpc({
    url: "http://localhost:8899",
    fetch: stub as unknown as typeof globalThis.fetch,
  });
  await rpc.sendTransaction(value);
  if (captured === undefined) throw new Error("SolanaRpc never sent the transaction");
  return captured;
}

describe("wire byte parity", () => {
  const cases = [
    ["fully signed", transaction([signature(1), signature(2)])],
    ["partially signed", transaction([signature(1), undefined])],
    ["with both signer slots empty", transaction([undefined, undefined])],
  ] as const;

  for (const [name, value] of cases) {
    it(`serializes a transaction ${name} to the bytes Zolana sends`, async () => {
      expect(getBase64EncodedWireTransaction(toKitTransaction(value))).toBe(
        await zolanaWireTransaction(value),
      );
    });
  }

  it("round-trips each case back to the Zolana transaction", () => {
    for (const [, value] of cases) {
      expect(fromKitTransaction(toKitTransaction(value))).toEqual(value);
    }
  });
});
