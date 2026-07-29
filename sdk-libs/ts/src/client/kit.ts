import {
  addSignersToTransactionMessage,
  appendTransactionMessageInstructions,
  assertIsFullySignedTransaction,
  assertIsTransactionWithBlockhashLifetime,
  assertIsTransactionWithinSizeLimit,
  compileTransaction,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  getBase58Decoder,
  getSignatureFromTransaction,
  isSolanaError,
  isTransactionModifyingSigner,
  isTransactionMessageWithSingleSendingSigner,
  isTransactionPartialSigner,
  isTransactionSendingSigner,
  pipe,
  sendTransactionWithoutConfirmingFactory,
  setTransactionMessageFeePayer,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signAndSendTransactionMessageWithSigners,
  signTransactionMessageWithSigners,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Address,
  type Commitment,
  type Instruction,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type Transaction,
  type TransactionModifyingSigner,
  type TransactionPartialSigner,
  type TransactionSigner,
} from "@solana/kit";
import {
  createBlockHeightExceedencePromiseFactory,
  createRecentSignatureConfirmationPromiseFactory,
  waitForRecentTransactionConfirmation,
} from "@solana/transaction-confirmation";

import type { RequestContext } from "../interface/types.js";

import { ClientError, isClientError } from "./error.js";
import { composeSignal, type ComposedSignal } from "./internal.js";

export type SolanaRpc = Rpc<SolanaRpcApi>;
export type SolanaRpcSubscriptions = RpcSubscriptions<SolanaRpcSubscriptionsApi>;
export type TransactionSignOnlySigner = TransactionModifyingSigner | TransactionPartialSigner;

export function isTransactionSignOnlySigner(
  signer: TransactionSigner,
): signer is TransactionSignOnlySigner {
  return (
    !isTransactionSendingSigner(signer) &&
    (isTransactionModifyingSigner(signer) || isTransactionPartialSigner(signer))
  );
}

export interface SolanaTransactionClient {
  readonly solanaRpc: SolanaRpc;
  readonly solanaRpcSubscriptions: SolanaRpcSubscriptions;
  readonly commitment: Commitment;
}

export interface LatestBlockhash {
  readonly blockhash: Parameters<
    typeof setTransactionMessageLifetimeUsingBlockhash
  >[0]["blockhash"];
  readonly lastValidBlockHeight: bigint;
}

export function createKitClients(
  input: Readonly<{
    solanaRpcUrl: string | URL;
    solanaRpcSubscriptionsUrl?: string | URL;
  }>,
): Readonly<{ solanaRpc: SolanaRpc; solanaRpcSubscriptions: SolanaRpcSubscriptions }> {
  const rpcUrl = urlString(input.solanaRpcUrl, "solanaRpcUrl", ["http:", "https:"]);
  const subscriptionsUrl =
    input.solanaRpcSubscriptionsUrl === undefined
      ? defaultSolanaRpcSubscriptionsUrl(rpcUrl)
      : urlString(input.solanaRpcSubscriptionsUrl, "solanaRpcSubscriptionsUrl", ["ws:", "wss:"]);
  return Object.freeze({
    solanaRpc: createSolanaRpc(rpcUrl),
    solanaRpcSubscriptions: createSolanaRpcSubscriptions(subscriptionsUrl),
  });
}

export function buildUnsignedTransaction(
  input: Readonly<{
    feePayer: Address;
    instructions: readonly Instruction[];
    lifetime: LatestBlockhash;
  }>,
): Transaction {
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (transactionMessage) => setTransactionMessageFeePayer(input.feePayer, transactionMessage),
    (transactionMessage) =>
      setTransactionMessageLifetimeUsingBlockhash(input.lifetime, transactionMessage),
    (transactionMessage) =>
      appendTransactionMessageInstructions(input.instructions, transactionMessage),
  );
  return compileTransaction(message);
}

export function buildSignableTransactionMessage(
  input: Readonly<{
    feePayer: TransactionSigner;
    instructions: readonly Instruction[];
    lifetime: LatestBlockhash;
    additionalSigners?: readonly TransactionSigner[];
  }>,
) {
  return pipe(
    createTransactionMessage({ version: 0 }),
    (transactionMessage) => setTransactionMessageFeePayerSigner(input.feePayer, transactionMessage),
    (transactionMessage) =>
      setTransactionMessageLifetimeUsingBlockhash(input.lifetime, transactionMessage),
    (transactionMessage) =>
      appendTransactionMessageInstructions(input.instructions, transactionMessage),
    (transactionMessage) =>
      addSignersToTransactionMessage([...(input.additionalSigners ?? [])], transactionMessage),
  );
}

export async function signAndSendInstructions(
  client: SolanaTransactionClient,
  input: Readonly<{
    feePayer: TransactionSigner;
    instructions: readonly Instruction[];
    additionalSigners?: readonly TransactionSigner[];
    skipPreflight?: boolean;
    onReadyToSubmit?: () => void;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  const { value: lifetime } = await runKitRpc("getLatestBlockhash", context, (abortSignal) =>
    client.solanaRpc.getLatestBlockhash({ commitment: client.commitment }).send({ abortSignal }),
  );
  const message = buildSignableTransactionMessage({ ...input, lifetime });
  if (isTransactionMessageWithSingleSendingSigner(message)) {
    const signature = await sendMessage(message, context);
    // A sending-only signer owns the broadcast step, so its successful return
    // is the first point at which submission is known to have started.
    input.onReadyToSubmit?.();
    return signature;
  }
  const transaction = await signMessage(message, context);
  await sendAndConfirmTransaction(client, transaction, input, context);
  return getSignatureFromTransaction(transaction);
}

export async function sendAndConfirmTransaction(
  client: SolanaTransactionClient,
  transaction: Transaction,
  input: Readonly<{ skipPreflight?: boolean; onReadyToSubmit?: () => void }> = {},
  context?: RequestContext,
): Promise<Signature> {
  try {
    assertIsFullySignedTransaction(transaction);
    assertIsTransactionWithinSizeLimit(transaction);
    assertIsTransactionWithBlockhashLifetime(transaction);
  } catch (cause) {
    throw new ClientError("CLIENT_INVALID_TRANSACTION", { cause });
  }
  const signal = composeSignal(context, "sendTransaction");
  try {
    await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(transaction, {
      abortSignal: signal.signal,
      commitment: client.commitment,
      ...(input.skipPreflight === undefined ? {} : { skipPreflight: input.skipPreflight }),
    });
    input.onReadyToSubmit?.();
    await waitForRecentTransactionConfirmation({
      abortSignal: signal.signal,
      commitment: client.commitment,
      transaction,
      getBlockHeightExceedencePromise: createBlockHeightExceedencePromiseFactory({
        rpc: client.solanaRpc,
        rpcSubscriptions: client.solanaRpcSubscriptions,
      }),
      getRecentSignatureConfirmationPromise: createRecentSignatureConfirmationPromiseFactory({
        rpc: client.solanaRpc,
        rpcSubscriptions: client.solanaRpcSubscriptions,
      }),
    });
  } catch (cause) {
    throw operationError("sendTransaction", signal, cause);
  } finally {
    signal.cleanup();
  }
  return getSignatureFromTransaction(transaction);
}

export async function runKitRpc<T>(
  method: string,
  context: RequestContext | undefined,
  operation: (abortSignal: AbortSignal) => Promise<T>,
): Promise<T> {
  const signal = composeSignal(context, method);
  try {
    return await operation(signal.signal);
  } catch (cause) {
    throw operationError(method, signal, cause);
  } finally {
    signal.cleanup();
  }
}

async function sendMessage(
  message: Parameters<typeof signAndSendTransactionMessageWithSigners>[0],
  context: RequestContext | undefined,
): Promise<Signature> {
  const signal = composeSignal(context, "signAndSendTransaction");
  try {
    const signature = await signAndSendTransactionMessageWithSigners(message, {
      abortSignal: signal.signal,
    });
    return getBase58Decoder().decode(signature) as Signature;
  } catch (cause) {
    if (signal.timedOut() || signal.signal.aborted || isClientError(cause)) {
      throw operationError("signAndSendTransaction", signal, cause);
    }
    throw new ClientError("CLIENT_SOLANA_TRANSACTION_SIGNING", {
      details: { reason: "transaction sending signer failed" },
      cause,
    });
  } finally {
    signal.cleanup();
  }
}

async function signMessage(
  message: Parameters<typeof signTransactionMessageWithSigners>[0],
  context: RequestContext | undefined,
): ReturnType<typeof signTransactionMessageWithSigners> {
  const signal = composeSignal(context, "signTransaction");
  try {
    return await signTransactionMessageWithSigners(message, {
      abortSignal: signal.signal,
    });
  } catch (cause) {
    if (signal.timedOut() || signal.signal.aborted || isClientError(cause)) {
      throw operationError("signTransaction", signal, cause);
    }
    throw new ClientError("CLIENT_SOLANA_TRANSACTION_SIGNING", {
      details: { reason: "transaction signer failed" },
      cause,
    });
  } finally {
    signal.cleanup();
  }
}

function operationError(method: string, signal: ComposedSignal, cause: unknown): ClientError {
  if (isClientError(cause)) return cause;
  if (isSolanaError(cause, SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND)) {
    return new ClientError("CLIENT_UNSUPPORTED_RPC_METHOD", {
      details: { method },
      cause,
    });
  }
  if (signal.timedOut()) {
    return new ClientError("CLIENT_TIMEOUT", {
      details: { method, retryable: true },
      cause,
    });
  }
  if (signal.signal.aborted) {
    return new ClientError("CLIENT_ABORTED", {
      details: { method, retryable: false },
      cause,
    });
  }
  return new ClientError("CLIENT_RPC", {
    details: { method },
    cause,
  });
}

function urlString(value: string | URL, field: string, protocols: readonly string[]): string {
  let url: URL;
  try {
    url = new URL(value instanceof URL ? value.href : value);
  } catch {
    throw invalidUrl(field);
  }
  if (
    !protocols.includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  ) {
    throw invalidUrl(field);
  }
  return url.href;
}

export function defaultSolanaRpcSubscriptionsUrl(value: string): string {
  const url = new URL(value);
  if (url.port !== "") {
    const port = Number(url.port);
    if (!Number.isSafeInteger(port) || port >= 65_535) {
      throw invalidUrl("solanaRpcUrl");
    }
    url.port = String(port + 1);
  }
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  return url.href;
}

function invalidUrl(field: string): ClientError {
  return new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
}
