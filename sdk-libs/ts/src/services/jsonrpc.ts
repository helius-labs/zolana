import { jsonInteger } from "../interface/decode.js";
import type { RequestContext } from "../interface/types.js";

import { composeSignal } from "./signal.js";
import { TransportFailure, httpJson } from "./transport.js";

const JSON_RPC_VERSION = "2.0";
/** Solana's "minimum context slot has not been reached", which Photon also answers. */
export const JSON_RPC_MIN_CONTEXT_SLOT = -32016;

type JsonObject = Record<string, unknown>;

export interface JsonRpcCall {
  readonly fetch: typeof globalThis.fetch;
  readonly url: URL;
  readonly rpcMethod: string;
  readonly params: unknown;
  readonly id: string | number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
}

export async function postJsonRpc(call: JsonRpcCall, context?: RequestContext): Promise<unknown> {
  const composed = composeSignal(context);
  try {
    const body = JSON.stringify({
      id: call.id,
      jsonrpc: JSON_RPC_VERSION,
      method: call.rpcMethod,
      params: call.params,
    });
    const bodyBytes = new TextEncoder().encode(body).length;
    if (bodyBytes > call.maxRequestBytes) {
      throw new TransportFailure("requestTooLarge", "JSON-RPC request body is too large", {
        bodyBytes,
        maxBodyBytes: call.maxRequestBytes,
      });
    }
    const value = await httpJson({
      fetch: call.fetch,
      url: call.url,
      body,
      composed,
      maxResponseBytes: call.maxResponseBytes,
    });
    return resultOf(validateEnvelope(value, call.id));
  } finally {
    composed.cleanup();
  }
}

function validateEnvelope(value: unknown, id: string | number): JsonObject {
  if (!isObject(value)) return invalidEnvelope();
  const allowed = ["id", "jsonrpc", "result", "error"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return invalidEnvelope();
  if (value["jsonrpc"] !== JSON_RPC_VERSION || value["id"] !== id) return invalidEnvelope();

  const hasResult = Object.hasOwn(value, "result");
  const hasError = Object.hasOwn(value, "error") && value["error"] !== null;
  if (hasResult && hasError) return invalidEnvelope();
  if (hasError) throw jsonRpcError(value["error"]);
  if (!hasResult) {
    throw new TransportFailure("missingResult", "JSON-RPC response omitted its result", {
      retryable: false,
    });
  }
  return value;
}

function resultOf(envelope: JsonObject): unknown {
  return envelope["result"];
}

/**
 * Server text never enters the facts, only its type and length. A `-32016`
 * keeps the slot its `data.contextSlot` reports, as `spr-api` does.
 */
function jsonRpcError(value: unknown): TransportFailure {
  if (!isObject(value)) return invalidEnvelopeFailure();
  const allowed = ["code", "message", "data"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return invalidEnvelopeFailure();
  const code = value["code"];
  const message = value["message"];
  if (code !== undefined && (typeof code !== "number" || !Number.isSafeInteger(code))) {
    return invalidEnvelopeFailure();
  }
  if (message !== undefined && typeof message !== "string") return invalidEnvelopeFailure();
  const contextSlot =
    code === JSON_RPC_MIN_CONTEXT_SLOT ? minimumContextSlot(value["data"]) : undefined;
  return new TransportFailure("rpc", "server returned a JSON-RPC error", {
    retryable: false,
    ...(code === undefined ? {} : { rpcCode: code }),
    ...(contextSlot === undefined ? {} : { contextSlot }),
    ...(message === undefined ? {} : { rpcMessage: { type: "string", length: message.length } }),
  });
}

const U64_MAX = (1n << 64n) - 1n;

/** A decimal string, so the facts stay JSON-serializable like the other slot details. */
function minimumContextSlot(data: unknown): string | undefined {
  const slot = jsonInteger(isObject(data) ? data["contextSlot"] : undefined);
  return slot === undefined || slot < 0n || slot > U64_MAX ? undefined : slot.toString();
}

function invalidEnvelope(): never {
  throw invalidEnvelopeFailure();
}

function invalidEnvelopeFailure(): TransportFailure {
  return new TransportFailure("envelope", "response is not a valid JSON-RPC envelope", {
    retryable: false,
  });
}

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
