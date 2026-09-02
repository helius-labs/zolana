import type { ComposedSignal } from "./signal.js";

export type TransportFailureKind =
  | "config"
  | "context"
  | "aborted"
  | "timeout"
  | "request"
  | "requestTooLarge"
  | "responseTooLarge"
  | "http"
  | "contentType"
  | "text"
  | "json"
  | "envelope"
  | "missingResult"
  | "rpc";

/** JSON-safe facts, never server text or a network cause. */
export class TransportFailure extends Error {
  readonly kind: TransportFailureKind;
  readonly facts: Readonly<Record<string, unknown>>;

  constructor(kind: TransportFailureKind, message: string, facts: Record<string, unknown> = {}) {
    super(message);
    this.name = "TransportFailure";
    this.kind = kind;
    this.facts = Object.freeze(facts);
  }
}

export interface EndpointPolicy {
  readonly field: string;
  /** Even loopback hosts need it for plain HTTP unless `allowLoopbackHttp` is set. */
  readonly allowInsecureHttp?: boolean;
  readonly allowLoopbackHttp?: boolean;
}

export function checkedEndpoint(value: unknown, policy: EndpointPolicy): URL {
  const invalid = (facts: Record<string, unknown> = {}) =>
    new TransportFailure("config", "endpoint URL is invalid", { field: policy.field, ...facts });
  if (typeof value !== "string" && !(value instanceof URL)) throw invalid();
  let url: URL;
  try {
    url = new URL(value instanceof URL ? value.href : value);
  } catch {
    throw invalid();
  }
  const httpAllowed =
    policy.allowInsecureHttp === true ||
    (policy.allowLoopbackHttp === true && isLoopbackHost(url.hostname));
  if (url.protocol !== "https:" && (url.protocol !== "http:" || !httpAllowed)) {
    throw invalid({ protocol: url.protocol });
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") throw invalid();
  return url;
}

// Browsers refuse `fetch` called with another receiver, so the global stays bound.
const boundFetch: typeof globalThis.fetch = (input, init) => globalThis.fetch(input, init);

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "[::1]" ||
    /^127(?:\.\d{1,3}){3}$/u.test(host)
  );
}

export function checkedFetch(value: unknown): typeof globalThis.fetch {
  if (value === undefined) return boundFetch;
  if (typeof value !== "function") {
    throw new TransportFailure("config", "a fetch implementation is required", {
      field: "fetch",
    });
  }
  return value as typeof globalThis.fetch;
}

export interface HttpJsonRequest {
  readonly fetch: typeof globalThis.fetch;
  readonly url: URL;
  readonly body: string;
  readonly composed: ComposedSignal;
  readonly maxResponseBytes: number;
}

export async function httpJson(request: HttpJsonRequest): Promise<unknown> {
  let response: Response;
  try {
    response = await request.fetch(request.url, {
      body: request.body,
      headers: { "content-type": "application/json" },
      method: "POST",
      redirect: "error",
      signal: request.composed.signal,
    });
  } catch {
    throw requestFailure(request.composed);
  }

  let bytes: Uint8Array;
  try {
    bytes = await readBoundedBody(response, request.maxResponseBytes);
  } catch (error) {
    if (error instanceof TransportFailure) throw error;
    throw requestFailure(request.composed);
  }

  if (!response.ok) {
    throw new TransportFailure("http", "HTTP request returned an error status", {
      status: response.status,
      retryable: isRetryableStatus(response.status),
      bodyBytes: bytes.length,
      contentType: contentTypeCategory(response.headers.get("content-type")),
    });
  }

  const contentType = response.headers.get("content-type");
  if (!isJsonContentType(contentType)) {
    throw new TransportFailure("contentType", "response is not JSON", {
      bodyBytes: bytes.length,
      contentType: contentTypeCategory(contentType),
      retryable: false,
    });
  }

  return decodeJson(bytes, quoteUnsafeIntegers);
}

/** No content-type check, no integer quoting. */
export async function readBoundedJson(response: Response, maxBodyBytes: number): Promise<unknown> {
  return decodeJson(await readBoundedBody(response, maxBodyBytes));
}

function decodeJson(bytes: Uint8Array, transform?: (text: string) => string): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TransportFailure("text", "response is not valid UTF-8", {
      bodyBytes: bytes.length,
      retryable: false,
    });
  }

  try {
    return JSON.parse(transform === undefined ? text : transform(text)) as unknown;
  } catch {
    throw new TransportFailure("json", "response is not valid JSON", {
      bodyBytes: bytes.length,
      retryable: false,
    });
  }
}

function requestFailure(composed: ComposedSignal): TransportFailure {
  if (composed.timedOut()) {
    return new TransportFailure("timeout", "request timed out", { retryable: true });
  }
  if (composed.signal.aborted) {
    return new TransportFailure("aborted", "request was aborted", { retryable: false });
  }
  return new TransportFailure("request", "request failed", { retryable: true });
}

async function readBoundedBody(response: Response, maxBodyBytes: number): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^\d+$/u.test(contentLength)) {
    const bodyBytes = Number(contentLength);
    if (bodyBytes > maxBodyBytes) throw oversizedResponse(bodyBytes, maxBodyBytes);
  }

  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bodyBytes = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    bodyBytes += next.value.length;
    if (bodyBytes > maxBodyBytes) {
      try {
        await reader.cancel();
      } catch {
        // The size limit remains the primary failure.
      }
      throw oversizedResponse(bodyBytes, maxBodyBytes);
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

function oversizedResponse(bodyBytes: number, maxBodyBytes: number): TransportFailure {
  return new TransportFailure("responseTooLarge", "response body is too large", {
    bodyBytes,
    maxBodyBytes,
    retryable: false,
  });
}

/**
 * The services serialize `u64` and `i64` as bare JSON numbers, so a value above
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
