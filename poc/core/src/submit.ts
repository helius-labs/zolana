/**
 * Signs, sends, and confirms a transaction the SDK built.
 *
 * The SDK is build-only: `build*Transaction` returns an unsigned transaction and
 * the caller owns submission, so this is the missing half of every flow step.
 * Mirrors `signSendAndConfirm` in the SDK's own e2e helpers rather than
 * inventing a different confirmation rule.
 */

import type { Rpc, SolanaRpcApi } from "@solana/kit";
import {
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Signature,
  type Transaction,
  type TransactionModifyingSigner,
  type TransactionPartialSigner,
} from "@solana/kit";

/**
 * The slice of `ZolanaClient` submission needs. The full Solana RPC surface,
 * because confirmation polls `getSignatureStatuses`, which the narrower
 * send-only type does not carry.
 */
export interface SubmitClient {
  readonly solanaRpc: Rpc<SolanaRpcApi>;
  readonly commitment: Parameters<
    ReturnType<typeof sendTransactionWithoutConfirmingFactory>
  >[1]["commitment"];
}

export type Signer = TransactionModifyingSigner | TransactionPartialSigner;

const POLL_INTERVAL_MS = 400;
const MAX_POLLS = 150;

export async function signSendAndConfirm(
  client: SubmitClient,
  transaction: Transaction,
  signers: readonly Signer[],
): Promise<Signature> {
  const signed = await signTransactionWithSigners(signers, transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  await waitForSignature(client, signature);
  return signature;
}

/**
 * Polls signature status rather than subscribing: the PoC runs against a local
 * validator where a dropped WebSocket would stall a benchmark run silently, and a
 * bounded poll fails loudly instead.
 */
async function waitForSignature(client: SubmitClient, signature: Signature): Promise<void> {
  for (let poll = 0; poll < MAX_POLLS; poll++) {
    const { value } = await client.solanaRpc.getSignatureStatuses([signature]).send();
    const status = value[0];
    if (status !== null && status !== undefined) {
      if (status.err !== null) {
        throw new Error(`transaction ${signature} failed: ${JSON.stringify(status.err)}`);
      }
      if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") {
        return;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(`transaction ${signature} was not confirmed in time`);
}
