import {
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  isSolanaError,
  setTransactionMessageLifetimeUsingBlockhash,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Rpc,
  type RpcSubscriptions,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
} from "@solana/kit";

import type { RequestContext } from "../interface/types.js";

import { ClientError, isClientError } from "./error.js";
import { composeSignal, type ComposedSignal } from "./internal.js";

export type SolanaRpc = Rpc<SolanaRpcApi>;
export type SolanaRpcSubscriptions = RpcSubscriptions<SolanaRpcSubscriptionsApi>;

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
