import { address, assertIsFullySignedTransaction, type Blockhash } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { buildUnsignedTransaction, defaultSolanaRpcSubscriptionsUrl } from "../src/client/kit.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("11111111111111111111111111111111");

describe("Solana Kit transaction construction", () => {
  it("builds an unsigned transaction without taking a signer", () => {
    const transaction = buildUnsignedTransaction({
      feePayer: PAYER,
      instructions: [{ programAddress: PROGRAM }],
      lifetime: {
        blockhash: "11111111111111111111111111111111" as Blockhash,
        lastValidBlockHeight: 1n,
      },
    });

    expect(() => assertIsFullySignedTransaction(transaction)).toThrow();
    expect(Object.keys(transaction.signatures)).toEqual([PAYER]);
  });

  it("derives the adjacent WebSocket port for a local RPC", () => {
    expect(defaultSolanaRpcSubscriptionsUrl("http://127.0.0.1:8899/")).toBe("ws://127.0.0.1:8900/");
  });
});
