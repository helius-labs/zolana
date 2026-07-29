import { ed25519 } from "@noble/curves/ed25519.js";
import {
  address,
  createKeyPairSignerFromBytes,
  getBase58Encoder,
  type Blockhash,
  type Signature,
  type SignatureBytes,
  type TransactionSendingSigner,
} from "@solana/kit";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { signAndSendInstructions, type SolanaTransactionClient } from "../src/client/kit.js";

const sendWithoutConfirming = vi.hoisted(() => vi.fn());
const waitForConfirmation = vi.hoisted(() => vi.fn());

vi.mock("@solana/kit", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@solana/kit")>()),
  sendTransactionWithoutConfirmingFactory: () => sendWithoutConfirming,
}));

vi.mock("@solana/transaction-confirmation", () => ({
  createBlockHeightExceedencePromiseFactory: () => vi.fn(),
  createRecentSignatureConfirmationPromiseFactory: () => vi.fn(),
  waitForRecentTransactionConfirmation: waitForConfirmation,
}));

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("11111111111111111111111111111111");
const SIGNATURE = "1".repeat(64) as Signature;

async function signOnlySigner(seedByte: number) {
  const seed = new Uint8Array(32).fill(seedByte);
  return createKeyPairSignerFromBytes(Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)));
}

function signOnlyClient(): SolanaTransactionClient {
  return {
    solanaRpc: {
      getLatestBlockhash: () => ({
        send: async () => ({
          value: {
            blockhash: "11111111111111111111111111111111" as Blockhash,
            lastValidBlockHeight: 1n,
          },
        }),
      }),
    },
    solanaRpcSubscriptions: {},
    commitment: "confirmed",
  } as unknown as SolanaTransactionClient;
}

describe("Solana Kit transaction submission", () => {
  beforeEach(() => {
    sendWithoutConfirming.mockReset().mockResolvedValue(undefined);
    waitForConfirmation.mockReset().mockResolvedValue(undefined);
  });

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
      solanaRpc: { getLatestBlockhash: () => ({ send }) },
      solanaRpcSubscriptions: {},
      commitment: "confirmed",
    } as unknown as SolanaTransactionClient;
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
      solanaRpc: {
        getLatestBlockhash: () => ({
          send: async () => ({
            value: {
              blockhash: "11111111111111111111111111111111" as Blockhash,
              lastValidBlockHeight: 1n,
            },
          }),
        }),
      },
      solanaRpcSubscriptions: {},
      commitment: "confirmed",
    } as unknown as SolanaTransactionClient;
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

  it("reports a sign-only transaction after broadcast and before confirmation", async () => {
    const feePayer = await signOnlySigner(7);
    const onReadyToSubmit = vi.fn();

    await signAndSendInstructions(signOnlyClient(), {
      feePayer,
      instructions: [{ programAddress: PROGRAM }],
      onReadyToSubmit,
    });

    expect(sendWithoutConfirming).toHaveBeenCalledOnce();
    expect(onReadyToSubmit).toHaveBeenCalledOnce();
    expect(waitForConfirmation).toHaveBeenCalledOnce();
    expect(sendWithoutConfirming.mock.invocationCallOrder[0]).toBeLessThan(
      onReadyToSubmit.mock.invocationCallOrder[0] as number,
    );
    expect(onReadyToSubmit.mock.invocationCallOrder[0]).toBeLessThan(
      waitForConfirmation.mock.invocationCallOrder[0] as number,
    );
  });

  it("keeps the broadcast boundary committed when confirmation fails", async () => {
    const feePayer = await signOnlySigner(8);
    const onReadyToSubmit = vi.fn();
    waitForConfirmation.mockRejectedValueOnce(new Error("confirmation failed"));

    await expect(
      signAndSendInstructions(signOnlyClient(), {
        feePayer,
        instructions: [{ programAddress: PROGRAM }],
        onReadyToSubmit,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_RPC" });
    expect(onReadyToSubmit).toHaveBeenCalledOnce();
  });

  it("does not report submission when broadcast fails", async () => {
    const feePayer = await signOnlySigner(9);
    const onReadyToSubmit = vi.fn();
    sendWithoutConfirming.mockRejectedValueOnce(new Error("preflight failed"));

    await expect(
      signAndSendInstructions(signOnlyClient(), {
        feePayer,
        instructions: [{ programAddress: PROGRAM }],
        onReadyToSubmit,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_RPC" });
    expect(onReadyToSubmit).not.toHaveBeenCalled();
    expect(waitForConfirmation).not.toHaveBeenCalled();
  });
});
