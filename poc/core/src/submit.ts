/**
 * Signs, sends, and confirms a transaction the SDK built.
 *
 * The SDK is build-only: `build*Transaction` returns an unsigned transaction and
 * the caller owns submission, so this is the missing half of every flow step.
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

export interface SubmitClient {
  readonly solanaRpc: Rpc<SolanaRpcApi>;
  readonly commitment: Parameters<
    ReturnType<typeof sendTransactionWithoutConfirmingFactory>
  >[1]["commitment"];
  confirmTransaction(signature: Signature): Promise<bigint>;
}

export type Signer = TransactionModifyingSigner | TransactionPartialSigner;

export interface Landed {
  readonly signature: Signature;
  readonly slot: bigint;
}

export async function signSendAndConfirm(
  client: SubmitClient,
  transaction: Transaction,
  signers: readonly Signer[],
): Promise<Landed> {
  const signed = await signTransactionWithSigners(signers, transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  const slot = await client.confirmTransaction(signature);
  return { signature, slot };
}
