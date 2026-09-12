import {
  createDefaultRpcTransport,
  createSolanaRpcFromTransport,
  createSolanaRpcSubscriptions,
  isJsonRpcPayload,
  isSolanaError,
  setTransactionMessageLifetimeUsingBlockhash,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Rpc,
  type RpcSubscriptions,
  type RpcTransport,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
} from "@solana/kit";

import type { RequestContext } from "../interface/types.js";
import { awaitWithSignal } from "../services/signal.js";

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
    solanaRpcTransport?: RpcTransport;
    solanaRpcRequestTimeoutMs?: number;
  }>,
): Readonly<{ solanaRpc: SolanaRpc; solanaRpcSubscriptions: SolanaRpcSubscriptions }> {
  const rpcUrl = urlString(input.solanaRpcUrl, "solanaRpcUrl", ["http:", "https:"]);
  const subscriptionsUrl =
    input.solanaRpcSubscriptionsUrl === undefined
      ? defaultSolanaRpcSubscriptionsUrl(rpcUrl)
      : urlString(input.solanaRpcSubscriptionsUrl, "solanaRpcSubscriptionsUrl", ["ws:", "wss:"]);
  const timeoutMs =
    input.solanaRpcRequestTimeoutMs === undefined ? 30_000 : input.solanaRpcRequestTimeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
    throw new ClientError("CLIENT_INVALID_CONFIG", {
      details: { field: "solanaRpcRequestTimeoutMs" },
    });
  }
  if (input.solanaRpcTransport !== undefined && typeof input.solanaRpcTransport !== "function") {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "solanaRpcTransport" } });
  }
  const source = input.solanaRpcTransport ?? createDefaultRpcTransport({ url: rpcUrl });
  const transport: RpcTransport = async <TResponse>(request: Parameters<RpcTransport>[0]) => {
    const method = isJsonRpcPayload(request.payload) ? request.payload.method : "rpc";
    const signal = composeSignal(
      { timeoutMs, ...(request.signal === undefined ? {} : { signal: request.signal }) },
      method,
    );
    try {
      return await awaitWithSignal(
        () => source<TResponse>({ ...request, signal: signal.signal }),
        signal.signal,
      );
    } catch (cause) {
      // Preserve native Kit errors on the raw RPC surface unless this request was cancelled.
      if (signal.signal.aborted) throw operationError(method, signal, cause);
      throw cause;
    } finally {
      signal.cleanup();
    }
  };
  return Object.freeze({
    solanaRpc: createSolanaRpcFromTransport(transport),
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
    return await awaitWithSignal(() => operation(signal.signal), signal.signal);
  } catch (cause) {
    throw operationError(method, signal, cause);
  } finally {
    signal.cleanup();
  }
}

function operationError(method: string, signal: ComposedSignal, cause: unknown): ClientError {
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
  if (isClientError(cause)) return cause;
  if (isSolanaError(cause, SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND)) {
    return new ClientError("CLIENT_UNSUPPORTED_RPC_METHOD", {
      details: { method },
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
