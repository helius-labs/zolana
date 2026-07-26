import {
  address,
  getBase58Encoder,
  type Blockhash,
  type Signature,
  type SignatureBytes,
  type TransactionSendingSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { signAndSendInstructions, type TransactionClient } from "../src/client/kit.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("11111111111111111111111111111111");
const SIGNATURE = "1".repeat(64) as Signature;

describe("Solana Kit transaction submission", () => {
  it("uses a sending-only fee payer signer", async () => {
    const signAndSendTransactions = vi.fn(async () => [
      getBase58Encoder().encode(SIGNATURE) as SignatureBytes,
    ]);
    const feePayer: TransactionSendingSigner = {
      address: PAYER,
      signAndSendTransactions,
    };
    const send = vi.fn(async () => ({
      value: {
        blockhash: "11111111111111111111111111111111" as Blockhash,
        lastValidBlockHeight: 1n,
      },
    }));
    const client = {
      rpc: { getLatestBlockhash: () => ({ send }) },
      rpcSubscriptions: {},
      commitment: "confirmed",
    } as unknown as TransactionClient;
    const onReadyToSubmit = vi.fn();

    const signature = await signAndSendInstructions(client, {
      feePayer,
      instructions: [{ programAddress: PROGRAM }],
      onReadyToSubmit,
    });

    expect(signature).toBe(SIGNATURE);
    expect(onReadyToSubmit).toHaveBeenCalledOnce();
    expect(signAndSendTransactions).toHaveBeenCalledOnce();
    expect(signAndSendTransactions.mock.invocationCallOrder[0]).toBeLessThan(
      onReadyToSubmit.mock.invocationCallOrder[0] as number,
    );
  });

  it("does not report submission when a sending-only signer rejects", async () => {
    const failure = new Error("user rejected");
    const feePayer: TransactionSendingSigner = {
      address: PAYER,
      signAndSendTransactions: vi.fn(async () => {
        throw failure;
      }),
    };
    const client = {
      rpc: {
        getLatestBlockhash: () => ({
          send: async () => ({
            value: {
              blockhash: "11111111111111111111111111111111" as Blockhash,
              lastValidBlockHeight: 1n,
            },
          }),
        }),
      },
      rpcSubscriptions: {},
      commitment: "confirmed",
    } as unknown as TransactionClient;
    const onReadyToSubmit = vi.fn();

    await expect(
      signAndSendInstructions(client, {
        feePayer,
        instructions: [{ programAddress: PROGRAM }],
        onReadyToSubmit,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_SOLANA_TRANSACTION_SIGNING" });
    expect(onReadyToSubmit).not.toHaveBeenCalled();
  });
});
