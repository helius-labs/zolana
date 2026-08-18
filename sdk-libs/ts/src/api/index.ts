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

const JSON_RPC_VERSION = "2.0";
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

interface PreparedRequest {
  readonly body: string;
  readonly method: string;
  readonly url: URL;
}

interface ComposedSignal {
  readonly signal: AbortSignal;
  readonly timedOut: () => boolean;
  cleanup(): void;
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
    const prepared = this.#prepare(descriptor, request);
    const composed = composeSignal(context, descriptor.name);

    try {
      const response = await this.#send(prepared, composed);
      const envelope = await decodeEnvelope(response, descriptor.name, composed);
      return decodeResult(descriptor, envelope);
    } finally {
      composed.cleanup();
    }
  }

  #prepare<Request, Response>(
    descriptor: MethodDescriptor<Request, Response>,
    request: Request,
  ): PreparedRequest {
    let params: Readonly<Record<string, unknown>>;
    try {
      params = descriptor.encodeRequest(request);
    } catch (error) {
      throw schemaError("API_INVALID_REQUEST", descriptor.name, error);
    }

    const body = JSON.stringify({
      id: REQUEST_ID,
      jsonrpc: JSON_RPC_VERSION,
      method: descriptor.name,
      params,
    });
    const bodyBytes = new TextEncoder().encode(body).length;
    if (bodyBytes > MAX_BODY_BYTES) {
      throw new ApiError("API_REQUEST_TOO_LARGE", "JSON-RPC request body is too large", {
        details: { method: descriptor.name, bodyBytes, maxBodyBytes: MAX_BODY_BYTES },
      });
    }

    const url = new URL(this.#baseUrl.href);
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}/${descriptor.name}`;
    if (this.#apiKey !== undefined) url.searchParams.set("api-key", this.#apiKey);
    return { body, method: descriptor.name, url };
  }

  async #send(prepared: PreparedRequest, composed: ComposedSignal): Promise<Response> {
    try {
      return await this.#fetch(prepared.url, {
        body: prepared.body,
        headers: { "content-type": "application/json" },
        method: "POST",
        redirect: "error",
        signal: composed.signal,
      });
    } catch {
      throw requestFailure(prepared.method, composed);
    }
  }
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

  const configuredUrl = config["url"];
  if (typeof configuredUrl !== "string" && !(configuredUrl instanceof URL)) {
    throw new ApiError("API_INVALID_CONFIG", "API URL is invalid", {
      details: { field: "url" },
    });
  }
  let url: URL;
  try {
    url = new URL(configuredUrl instanceof URL ? configuredUrl.href : configuredUrl);
  } catch {
    throw new ApiError("API_INVALID_CONFIG", "API URL is invalid", {
      details: { field: "url" },
    });
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ApiError("API_INVALID_CONFIG", "API URL must use HTTP or HTTPS", {
      details: { field: "url", protocol: url.protocol },
    });
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new ApiError("API_INVALID_CONFIG", "API URL cannot contain credentials or a fragment", {
      details: { field: "url" },
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

  const fetchImplementation = config["fetch"] ?? globalThis.fetch;
  if (!isFetch(fetchImplementation)) {
    throw new ApiError("API_INVALID_CONFIG", "A fetch implementation is required", {
      details: { field: "fetch" },
    });
  }

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

function composeSignal(context: RequestContext | undefined, method: string): ComposedSignal {
  const timeoutMs = context?.timeoutMs;
  if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)) {
    throw new ApiError("API_INVALID_CONTEXT", "Request timeout is invalid", {
      details: { field: "timeoutMs", method },
    });
  }
  if (context?.signal?.aborted === true) {
    throw new ApiError("API_ABORTED", "API request was aborted", {
      details: { method, retryable: false },
    });
  }

  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let didTimeOut = false;
  const abortFromCaller = (): void => {
    controller.abort();
  };
  context?.signal?.addEventListener("abort", abortFromCaller, { once: true });
  if (timeoutMs !== undefined) {
    timeout = setTimeout(() => {
      didTimeOut = true;
      controller.abort();
    }, timeoutMs);
  }

  return {
    signal: controller.signal,
    timedOut: () => didTimeOut,
    cleanup(): void {
      if (timeout !== undefined) clearTimeout(timeout);
      context?.signal?.removeEventListener("abort", abortFromCaller);
    },
  };
}

function requestFailure(method: string, composed: ComposedSignal): ApiError {
  if (composed.timedOut()) {
    return new ApiError("API_TIMEOUT", "API request timed out", {
      details: { method, retryable: true },
    });
  }
  if (composed.signal.aborted) {
    return new ApiError("API_ABORTED", "API request was aborted", {
      details: { method, retryable: false },
    });
  }
  return new ApiError("API_REQUEST", "API request failed", {
    details: { method, retryable: true },
  });
}

async function decodeEnvelope(
  response: Response,
  method: string,
  composed: ComposedSignal,
): Promise<JsonObject> {
  let bytes: Uint8Array;
  try {
    bytes = await readBoundedBody(response, method);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw requestFailure(method, composed);
  }

  if (!response.ok) {
    throw new ApiError("API_HTTP", "API returned an HTTP error", {
      details: {
        method,
        status: response.status,
        retryable: isRetryableStatus(response.status),
        bodyBytes: bytes.length,
        contentType: contentTypeCategory(response.headers.get("content-type")),
      },
    });
  }

  const contentType = response.headers.get("content-type");
  if (!isJsonContentType(contentType)) {
    throw new ApiError("API_INVALID_CONTENT_TYPE", "API response is not JSON", {
      details: {
        method,
        bodyBytes: bytes.length,
        contentType: contentTypeCategory(contentType),
        retryable: false,
      },
    });
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ApiError("API_INVALID_TEXT", "API response is not valid UTF-8", {
      details: { method, bodyBytes: bytes.length, retryable: false },
    });
  }

  let value: unknown;
  try {
    value = JSON.parse(quoteUnsafeIntegers(text)) as unknown;
  } catch {
    throw new ApiError("API_INVALID_JSON", "API response is not valid JSON", {
      details: { method, bodyBytes: bytes.length, retryable: false },
    });
  }
  return validateEnvelope(value, method);
}

/**
 * The indexer serializes `u64` and `i64` as bare JSON numbers, so a value above
 * `Number.MAX_SAFE_INTEGER` would be rounded by `JSON.parse` before any decoder
 * could see it. Quoting those literals first hands the decoder the exact digits.
 * Numbers within the safe range keep their JSON type, so nothing else moves.
 */
function quoteUnsafeIntegers(text: string): string {
  let result = "";
  let copiedTo = 0;
  let index = 0;

  while (index < text.length) {
    const character = text[index] as string;

    if (character === '"') {
      index = endOfStringLiteral(text, index);
      continue;
    }

    if (character !== "-" && (character < "0" || character > "9")) {
      index += 1;
      continue;
    }

    const start = index;
    index = endOfNumberLiteral(text, index);
    const literal = text.slice(start, index);
    if (!isUnsafeIntegerLiteral(literal)) continue;

    result += text.slice(copiedTo, start) + '"' + literal + '"';
    copiedTo = index;
  }

  return copiedTo === 0 ? text : result + text.slice(copiedTo);
}

function endOfStringLiteral(text: string, start: number): number {
  let index = start + 1;
  while (index < text.length) {
    const character = text[index];
    if (character === "\\") {
      index += 2;
      continue;
    }
    index += 1;
    if (character === '"') break;
  }
  return index;
}

function endOfNumberLiteral(text: string, start: number): number {
  let index = start;
  if (text[index] === "-") index += 1;
  while (index < text.length && isNumberBody(text[index] as string)) index += 1;
  return index;
}

function isNumberBody(character: string): boolean {
  return (
    (character >= "0" && character <= "9") ||
    character === "." ||
    character === "e" ||
    character === "E" ||
    character === "+" ||
    character === "-"
  );
}

function isUnsafeIntegerLiteral(literal: string): boolean {
  if (!/^-?[0-9]+$/u.test(literal)) return false;
  return !Number.isSafeInteger(Number(literal));
}

async function readBoundedBody(response: Response, method: string): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^\d+$/u.test(contentLength)) {
    const bodyBytes = Number(contentLength);
    if (bodyBytes > MAX_BODY_BYTES) throw oversizedResponse(method, bodyBytes);
  }

  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    bodyBytes += next.value.length;
    if (bodyBytes > MAX_BODY_BYTES) {
      try {
        await reader.cancel();
      } catch {
        // The size limit remains the primary failure.
      }
      throw oversizedResponse(method, bodyBytes);
    }
    chunks.push(next.value);
  }

  const body = new Uint8Array(bodyBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function oversizedResponse(method: string, bodyBytes: number): ApiError {
  return new ApiError("API_RESPONSE_TOO_LARGE", "API response body is too large", {
    details: { method, bodyBytes, maxBodyBytes: MAX_BODY_BYTES, retryable: false },
  });
}

function validateEnvelope(value: unknown, method: string): JsonObject {
  if (!isObject(value)) return invalidEnvelope(method);
  const allowed = ["id", "jsonrpc", "result", "error"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return invalidEnvelope(method);
  if (value["jsonrpc"] !== JSON_RPC_VERSION || value["id"] !== REQUEST_ID) {
    return invalidEnvelope(method);
  }

  const hasResult = Object.hasOwn(value, "result");
  const hasError = Object.hasOwn(value, "error") && value["error"] !== null;
  if (hasResult && hasError) return invalidEnvelope(method);
  if (hasError) throw jsonRpcError(value["error"], method);
  if (!hasResult) {
    throw new ApiError("API_MISSING_RESULT", "JSON-RPC response omitted its result", {
      details: { method, retryable: false },
    });
  }
  return value;
}

function jsonRpcError(value: unknown, method: string): ApiError {
  if (!isObject(value)) return invalidEnvelope(method);
  const allowed = ["code", "message", "data"];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return invalidEnvelope(method);
  const code = value["code"];
  const message = value["message"];
  if (code !== undefined && (typeof code !== "number" || !Number.isSafeInteger(code))) {
    return invalidEnvelope(method);
  }
  if (message !== undefined && typeof message !== "string") return invalidEnvelope(method);
  return new ApiError("API_JSON_RPC", "API returned a JSON-RPC error", {
    details: {
      method,
      retryable: false,
      ...(code === undefined ? {} : { rpcCode: code }),
      ...(message === undefined ? {} : { rpcMessage: { type: "string", length: message.length } }),
    },
  });
}

function invalidEnvelope(method: string): never {
  throw new ApiError("API_INVALID_ENVELOPE", "API returned an invalid JSON-RPC envelope", {
    details: { method, retryable: false },
  });
}

function decodeResult<Request, Response>(
  descriptor: MethodDescriptor<Request, Response>,
  envelope: JsonObject,
): Response {
  try {
    return descriptor.decodeResponse(envelope["result"]);
  } catch (error) {
    throw schemaError("API_INVALID_RESULT", descriptor.name, error);
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

function isFetch(value: unknown): value is typeof globalThis.fetch {
  return typeof value === "function";
}

function isJsonContentType(contentType: string | null): boolean {
  if (contentType === null) return false;
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}

function contentTypeCategory(contentType: string | null): string {
  if (contentType === null) return "missing";
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType === "application/json" || mediaType?.endsWith("+json") === true) return "json";
  if (mediaType?.startsWith("text/") === true) return "text";
  return "binary";
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
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
    "(?:blockTime|context|hash|highElement|highElementIndex|leaf|leafIndex|leaves|limit|lowElement|lowElementIndex|matches|merkleContext|nextCursor|nullifiers|outputContext|outputSlot|outputSlots|path|payload|proofless|proofs|root|rootIndex|rootSeq|salt|scannedThrough|slot|tags|transactions|tree|treeAccount|treeType|txSignature|txViewingPk|viewTag)";
  const pattern = new RegExp(`^\\$(?:(?:\\.${knownField})|(?:\\[\\d+\\]))*$`, "u");
  return path.length <= 256 && pattern.test(path) ? path : undefined;
}
