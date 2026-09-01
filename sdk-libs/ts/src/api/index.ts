import type { RequestContext } from "../interface/types.js";
import type {
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetRingsByNullifiersRequest,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureRequest,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
} from "../indexer/types.js";
import type { IndexerSchemaError } from "../indexer/scalars.js";
import {
  getEncryptedUtxosByTagsMethod,
  getMerkleProofsMethod,
  getNonInclusionProofsMethod,
  getShieldedTransactionsByNullifiersMethod,
  getShieldedTransactionsBySignatureMethod,
  getShieldedTransactionsByTagsMethod,
  type MethodDescriptor,
} from "../indexer/methods/index.js";
import { postJsonRpc } from "../services/jsonrpc.js";
import {
  TransportFailure,
  checkedEndpoint,
  checkedFetch,
  type TransportFailureKind,
} from "../services/transport.js";

const REQUEST_ID = "test-account";
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_API_KEY_LENGTH = 4096;

type JsonObject = Record<string, unknown>;

export class ApiError extends Error {
  readonly code: `API_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: `API_${string}`,
    message: string,
    options: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    if (options.details !== undefined) this.details = options.details;
    if (options.cause !== undefined) this.cause = options.cause;
  }
}

export interface ZolanaApiConfig {
  readonly url: URL | string;
  readonly apiKey?: string;
  readonly fetch?: typeof globalThis.fetch;
}

export class ZolanaApi {
  readonly #apiKey?: string;
  readonly #baseUrl: URL;
  readonly #fetch: typeof globalThis.fetch;

  constructor(config: ZolanaApiConfig) {
    const parsed = parseConfig(config);
    this.#baseUrl = parsed.url;
    this.#fetch = parsed.fetch;
    if (parsed.apiKey !== undefined) this.#apiKey = parsed.apiKey;
  }

  getEncryptedUtxosByTags(
    request: GetRingsByTagsRequest,
    context?: RequestContext,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    return this.#call(getEncryptedUtxosByTagsMethod, request, context);
  }

  getShieldedTransactionsByTags(
    request: GetRingsByTagsRequest,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    return this.#call(getShieldedTransactionsByTagsMethod, request, context);
  }

  getShieldedTransactionsByNullifiers(
    request: GetRingsByNullifiersRequest,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByNullifiersResponse> {
    return this.#call(getShieldedTransactionsByNullifiersMethod, request, context);
  }

  getShieldedTransactionsBySignature(
    request: GetShieldedTransactionsBySignatureRequest,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsBySignatureResponse> {
    return this.#call(getShieldedTransactionsBySignatureMethod, request, context);
  }

  getMerkleProofs(
    request: GetMerkleProofsRequest,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    return this.#call(getMerkleProofsMethod, request, context);
  }

  getNonInclusionProofs(
    request: GetNonInclusionProofsRequest,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    return this.#call(getNonInclusionProofsMethod, request, context);
  }

  async #call<Request, Response>(
    descriptor: MethodDescriptor<Request, Response>,
    request: Request,
    context?: RequestContext,
  ): Promise<Response> {
    let params: Readonly<Record<string, unknown>>;
    try {
      params = descriptor.encodeRequest(request);
    } catch (error) {
      throw schemaError("API_INVALID_REQUEST", descriptor.name, error);
    }

    const url = new URL(this.#baseUrl.href);
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}/${descriptor.name}`;
    if (this.#apiKey !== undefined) url.searchParams.set("api-key", this.#apiKey);

    let result: unknown;
    try {
      result = await postJsonRpc(
        {
          fetch: this.#fetch,
          url,
          rpcMethod: descriptor.name,
          params,
          id: REQUEST_ID,
          maxRequestBytes: MAX_BODY_BYTES,
          maxResponseBytes: MAX_BODY_BYTES,
        },
        context,
      );
    } catch (error) {
      throw apiFailure(error, descriptor.name);
    }

    try {
      return descriptor.decodeResponse(result);
    } catch (error) {
      throw schemaError("API_INVALID_RESULT", descriptor.name, error);
    }
  }
}

const API_CODE_BY_KIND: Record<TransportFailureKind, `API_${string}`> = {
  config: "API_INVALID_CONFIG",
  context: "API_INVALID_CONTEXT",
  aborted: "API_ABORTED",
  timeout: "API_TIMEOUT",
  request: "API_REQUEST",
  requestTooLarge: "API_REQUEST_TOO_LARGE",
  responseTooLarge: "API_RESPONSE_TOO_LARGE",
  http: "API_HTTP",
  contentType: "API_INVALID_CONTENT_TYPE",
  text: "API_INVALID_TEXT",
  json: "API_INVALID_JSON",
  envelope: "API_INVALID_ENVELOPE",
  missingResult: "API_MISSING_RESULT",
  rpc: "API_JSON_RPC",
};

const API_MESSAGE_BY_KIND: Record<TransportFailureKind, string> = {
  config: "API configuration is invalid",
  context: "Request timeout is invalid",
  aborted: "API request was aborted",
  timeout: "API request timed out",
  request: "API request failed",
  requestTooLarge: "JSON-RPC request body is too large",
  responseTooLarge: "API response body is too large",
  http: "API returned an HTTP error",
  contentType: "API response is not JSON",
  text: "API response is not valid UTF-8",
  json: "API response is not valid JSON",
  envelope: "API returned an invalid JSON-RPC envelope",
  missingResult: "JSON-RPC response omitted its result",
  rpc: "API returned a JSON-RPC error",
};

function apiFailure(error: unknown, method: string): unknown {
  if (!(error instanceof TransportFailure)) return error;
  return new ApiError(API_CODE_BY_KIND[error.kind], API_MESSAGE_BY_KIND[error.kind], {
    details: { method, ...error.facts },
  });
}

function parseConfig(config: unknown): {
  readonly apiKey?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly url: URL;
} {
  if (!isObject(config)) {
    throw new ApiError("API_INVALID_CONFIG", "API configuration must be an object", {
      details: { field: "config" },
    });
  }

  let url: URL;
  let fetchImplementation: typeof globalThis.fetch;
  try {
    url = checkedEndpoint(config["url"], { field: "url", allowInsecureHttp: true });
    fetchImplementation = checkedFetch(config["fetch"]);
  } catch (error) {
    if (!(error instanceof TransportFailure)) throw error;
    throw new ApiError("API_INVALID_CONFIG", "API configuration is invalid", {
      details: error.facts,
    });
  }

  const queryKeys = url.searchParams.getAll("api-key");
  if (queryKeys.length > 1) {
    throw new ApiError("API_INVALID_CONFIG", "API URL contains duplicate API keys", {
      details: { field: "apiKey" },
    });
  }
  const configuredApiKey = config["apiKey"];
  if (configuredApiKey !== undefined && typeof configuredApiKey !== "string") {
    throw new ApiError("API_INVALID_CONFIG", "API key is invalid", {
      details: { field: "apiKey" },
    });
  }
  if (configuredApiKey !== undefined && queryKeys.length !== 0) {
    throw new ApiError("API_INVALID_CONFIG", "API key must have one source", {
      details: { field: "apiKey" },
    });
  }
  const apiKey = configuredApiKey ?? queryKeys[0];
  if (queryKeys.length === 1) url.searchParams.delete("api-key");
  validateApiKey(apiKey);

  return {
    ...(apiKey === undefined ? {} : { apiKey }),
    fetch: fetchImplementation,
    url,
  };
}

function validateApiKey(apiKey: string | undefined): void {
  if (apiKey === undefined) return;
  if (apiKey.length === 0 || apiKey.length > MAX_API_KEY_LENGTH || hasControlCharacter(apiKey)) {
    throw new ApiError("API_INVALID_CONFIG", "API key is invalid", {
      details: { field: "apiKey" },
    });
  }
}

function schemaError(
  code: "API_INVALID_REQUEST" | "API_INVALID_RESULT",
  method: string,
  error: unknown,
): ApiError {
  const schema = error as Partial<IndexerSchemaError>;
  const schemaDetails = schema.details;
  const path =
    typeof schemaDetails?.["path"] === "string" ? safeSchemaPath(schemaDetails["path"]) : undefined;
  return new ApiError(
    code,
    code === "API_INVALID_REQUEST" ? "API request is invalid" : "API result is invalid",
    {
      details: {
        method,
        retryable: false,
        ...(typeof schema.code === "string" ? { schemaCode: schema.code } : {}),
        ...(path === undefined ? {} : { path }),
      },
    },
  );
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function safeSchemaPath(path: string): string | undefined {
  const knownField =
    "(?:blockTime|context|hash|highElement|highElementIndex|latest|leaf|leafIndex|leaves|limit|lowElement|lowElementIndex|matches|merkleContext|next|nullifiers|outputContext|outputSlot|outputSlots|path|payload|proofless|proofs|root|rootIndex|rootSeq|salt|signature|since|slot|tags|transactions|tree|treeAccount|treeType|txSignature|txViewingPk|viewTag)";
  const pattern = new RegExp(`^\\$(?:(?:\\.${knownField})|(?:\\[\\d+\\]))*$`, "u");
  return path.length <= 256 && pattern.test(path) ? path : undefined;
}
