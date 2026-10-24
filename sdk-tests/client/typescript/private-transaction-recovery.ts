import {
  assertIsTransactionWithBlockhashLifetime,
  getSignatureFromTransaction,
  isSolanaError,
  sendTransactionWithoutConfirmingFactory,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  signTransactionWithSigners,
  type Signature,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  ClientError,
  type KitRpcAccess,
  type PrivateTransactionWaiter,
} from "@heliuslabs/zolana/client";

/** Store the height as decimal text if the application's store uses JSON. */
export interface PendingPrivateTransaction {
  readonly signature: Signature;
  readonly lastValidBlockHeight: bigint;
}

/**
 * Application orchestration for a deposit, transfer, withdrawal or merge.
 * Registration has no private event and must use ordinary chain confirmation.
 */
export async function sendPrivateTransaction(
  client: KitRpcAccess & PrivateTransactionWaiter,
  transaction: Transaction,
  signers: readonly TransactionPartialSigner[],
  savePending: (pending: PendingPrivateTransaction) => Promise<void>,
): Promise<PendingPrivateTransaction> {
  const signed = await signTransactionWithSigners(signers, transaction);
  assertIsTransactionWithBlockhashLifetime(signed);
  const pending = {
    signature: getSignatureFromTransaction(signed),
    lastValidBlockHeight: signed.lifetimeConstraint.lastValidBlockHeight,
  };
  // Save this before sending, together with the wallet's input reservations.
  // If saving fails, no transaction is sent. Do not log signed bytes or keys.
  await savePending(pending);
  try {
    await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
      commitment: "confirmed",
    });
  } catch (error) {
    // The RPC refused it in preflight, so it was never broadcast: report the
    // rejection, then discard the checkpoint and release the reservations.
    if (
      isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)
    )
      throw error;
    // Any other failure, such as a lost response, does not prove rejection.
    // Recover the same signature.
  }
  await client.waitForPrivateTransaction(pending.signature, pending.lastValidBlockHeight);
  return pending;
}

/** Call after restart with the checkpoint saved before the original send. */
export async function recoverPrivateTransaction(
  client: PrivateTransactionWaiter,
  pending: PendingPrivateTransaction,
): Promise<"indexed" | "expired" | "confirmed-awaiting-indexer" | "unknown"> {
  try {
    await client.waitForPrivateTransaction(pending.signature, pending.lastValidBlockHeight);
    return "indexed"; // Sync and persist the wallet before discarding the checkpoint.
  } catch (error) {
    if (!(error instanceof ClientError)) throw error;
    switch (error.code) {
      case "CLIENT_TRANSACTION_EXPIRED":
        return "expired"; // Sync before building a replacement.
      case "CLIENT_TRANSACTION_NOT_INDEXED":
        return "confirmed-awaiting-indexer";
      case "CLIENT_TRANSACTION_OUTCOME_UNKNOWN":
        return "unknown";
      default:
        // Keep the checkpoint. A chain failure (`CLIENT_TRANSACTION_FAILED`) and
        // cancellation end here, as does an RPC or indexer that cannot answer.
        throw error;
    }
  }
}
