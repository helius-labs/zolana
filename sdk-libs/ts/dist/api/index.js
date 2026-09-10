import { getEncryptedUtxosByTagsMethod, getMerkleProofsMethod, getNonInclusionProofsMethod, getShieldedTransactionsByNullifiersMethod, getShieldedTransactionsBySignatureMethod, getShieldedTransactionsByTagsMethod, } from "../indexer/methods/index.js";
const JSON_RPC_VERSION = "2.0";
const REQUEST_ID = "test-account";
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_API_KEY_LENGTH = 4096;
export class ApiError extends Error {
    code;
    details;
    cause;
    constructor(code, message, options = {}) {
        super(message);
        this.name = "ApiError";
        this.code = code;
        if (options.details !== undefined)
            this.details = options.details;
        if (options.cause !== undefined)
            this.cause = options.cause;
    }
}
export class ZolanaApi {
    #apiKey;
    #baseUrl;
    #fetch;
    constructor(config) {
        const parsed = parseConfig(config);
        this.#baseUrl = parsed.url;
        this.#fetch = parsed.fetch;
        if (parsed.apiKey !== undefined)
            this.#apiKey = parsed.apiKey;
    }
    getEncryptedUtxosByTags(request, context) {
        return this.#call(getEncryptedUtxosByTagsMethod, request, context);
    }
    getShieldedTransactionsByTags(request, context) {
        return this.#call(getShieldedTransactionsByTagsMethod, request, context);
    }
    getShieldedTransactionsByNullifiers(request, context) {
        return this.#call(getShieldedTransactionsByNullifiersMethod, request, context);
    }
    getShieldedTransactionsBySignature(request, context) {
        return this.#call(getShieldedTransactionsBySignatureMethod, request, context);
    }
    getMerkleProofs(request, context) {
        return this.#call(getMerkleProofsMethod, request, context);
    }
    getNonInclusionProofs(request, context) {
        return this.#call(getNonInclusionProofsMethod, request, context);
    }
    async #call(descriptor, request, context) {
        const prepared = this.#prepare(descriptor, request);
        const composed = composeSignal(context, descriptor.name);
        try {
            const response = await this.#send(prepared, composed);
            const envelope = await decodeEnvelope(response, descriptor.name, composed);
            return decodeResult(descriptor, envelope);
        }
        finally {
            composed.cleanup();
        }
    }
    #prepare(descriptor, request) {
        let params;
        try {
            params = descriptor.encodeRequest(request);
        }
        catch (error) {
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
        if (this.#apiKey !== undefined)
            url.searchParams.set("api-key", this.#apiKey);
        return { body, method: descriptor.name, url };
    }
    async #send(prepared, composed) {
        try {
            return await this.#fetch(prepared.url, {
                body: prepared.body,
                headers: { "content-type": "application/json" },
                method: "POST",
                redirect: "error",
                signal: composed.signal,
            });
        }
        catch {
            throw requestFailure(prepared.method, composed);
        }
    }
}
function parseConfig(config) {
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
    let url;
    try {
        url = new URL(configuredUrl instanceof URL ? configuredUrl.href : configuredUrl);
    }
    catch {
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
    if (queryKeys.length === 1)
        url.searchParams.delete("api-key");
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
function validateApiKey(apiKey) {
    if (apiKey === undefined)
        return;
    if (apiKey.length === 0 || apiKey.length > MAX_API_KEY_LENGTH || hasControlCharacter(apiKey)) {
        throw new ApiError("API_INVALID_CONFIG", "API key is invalid", {
            details: { field: "apiKey" },
        });
    }
}
function composeSignal(context, method) {
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
    let timeout;
    let didTimeOut = false;
    const abortFromCaller = () => {
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
        cleanup() {
            if (timeout !== undefined)
                clearTimeout(timeout);
            context?.signal?.removeEventListener("abort", abortFromCaller);
        },
    };
}
function requestFailure(method, composed) {
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
async function decodeEnvelope(response, method, composed) {
    let bytes;
    try {
        bytes = await readBoundedBody(response, method);
    }
    catch (error) {
        if (error instanceof ApiError)
            throw error;
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
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch {
        throw new ApiError("API_INVALID_TEXT", "API response is not valid UTF-8", {
            details: { method, bodyBytes: bytes.length, retryable: false },
        });
    }
    let value;
    try {
        value = JSON.parse(quoteUnsafeIntegers(text));
    }
    catch {
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
function quoteUnsafeIntegers(text) {
    let result = "";
    let copiedTo = 0;
    let index = 0;
    while (index < text.length) {
        const character = text[index];
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
        if (!isUnsafeIntegerLiteral(literal))
            continue;
        result += text.slice(copiedTo, start) + '"' + literal + '"';
        copiedTo = index;
    }
    return copiedTo === 0 ? text : result + text.slice(copiedTo);
}
function endOfStringLiteral(text, start) {
    let index = start + 1;
    while (index < text.length) {
        const character = text[index];
        if (character === "\\") {
            index += 2;
            continue;
        }
        index += 1;
        if (character === '"')
            break;
    }
    return index;
}
function endOfNumberLiteral(text, start) {
    let index = start;
    if (text[index] === "-")
        index += 1;
    while (index < text.length && isNumberBody(text[index]))
        index += 1;
    return index;
}
function isNumberBody(character) {
    return ((character >= "0" && character <= "9") ||
        character === "." ||
        character === "e" ||
        character === "E" ||
        character === "+" ||
        character === "-");
}
function isUnsafeIntegerLiteral(literal) {
    if (!/^-?[0-9]+$/u.test(literal))
        return false;
    return !Number.isSafeInteger(Number(literal));
}
async function readBoundedBody(response, method) {
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && /^\d+$/u.test(contentLength)) {
        const bodyBytes = Number(contentLength);
        if (bodyBytes > MAX_BODY_BYTES)
            throw oversizedResponse(method, bodyBytes);
    }
    if (response.body === null)
        return new Uint8Array();
    const reader = response.body.getReader();
    const chunks = [];
    let bodyBytes = 0;
    for (;;) {
        const next = await reader.read();
        if (next.done)
            break;
        bodyBytes += next.value.length;
        if (bodyBytes > MAX_BODY_BYTES) {
            try {
                await reader.cancel();
            }
            catch {
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
function oversizedResponse(method, bodyBytes) {
    return new ApiError("API_RESPONSE_TOO_LARGE", "API response body is too large", {
        details: { method, bodyBytes, maxBodyBytes: MAX_BODY_BYTES, retryable: false },
    });
}
function validateEnvelope(value, method) {
    if (!isObject(value))
        return invalidEnvelope(method);
    const allowed = ["id", "jsonrpc", "result", "error"];
    if (Object.keys(value).some((key) => !allowed.includes(key)))
        return invalidEnvelope(method);
    if (value["jsonrpc"] !== JSON_RPC_VERSION || value["id"] !== REQUEST_ID) {
        return invalidEnvelope(method);
    }
    const hasResult = Object.hasOwn(value, "result");
    const hasError = Object.hasOwn(value, "error") && value["error"] !== null;
    if (hasResult && hasError)
        return invalidEnvelope(method);
    if (hasError)
        throw jsonRpcError(value["error"], method);
    if (!hasResult) {
        throw new ApiError("API_MISSING_RESULT", "JSON-RPC response omitted its result", {
            details: { method, retryable: false },
        });
    }
    return value;
}
function jsonRpcError(value, method) {
    if (!isObject(value))
        return invalidEnvelope(method);
    const allowed = ["code", "message", "data"];
    if (Object.keys(value).some((key) => !allowed.includes(key)))
        return invalidEnvelope(method);
    const code = value["code"];
    const message = value["message"];
    if (code !== undefined && (typeof code !== "number" || !Number.isSafeInteger(code))) {
        return invalidEnvelope(method);
    }
    if (message !== undefined && typeof message !== "string")
        return invalidEnvelope(method);
    return new ApiError("API_JSON_RPC", "API returned a JSON-RPC error", {
        details: {
            method,
            retryable: false,
            ...(code === undefined ? {} : { rpcCode: code }),
            ...(message === undefined ? {} : { rpcMessage: { type: "string", length: message.length } }),
        },
    });
}
function invalidEnvelope(method) {
    throw new ApiError("API_INVALID_ENVELOPE", "API returned an invalid JSON-RPC envelope", {
        details: { method, retryable: false },
    });
}
function decodeResult(descriptor, envelope) {
    try {
        return descriptor.decodeResponse(envelope["result"]);
    }
    catch (error) {
        throw schemaError("API_INVALID_RESULT", descriptor.name, error);
    }
}
function schemaError(code, method, error) {
    const schema = error;
    const schemaDetails = schema.details;
    const path = typeof schemaDetails?.["path"] === "string" ? safeSchemaPath(schemaDetails["path"]) : undefined;
    return new ApiError(code, code === "API_INVALID_REQUEST" ? "API request is invalid" : "API result is invalid", {
        details: {
            method,
            retryable: false,
            ...(typeof schema.code === "string" ? { schemaCode: schema.code } : {}),
            ...(path === undefined ? {} : { path }),
        },
    });
}
function isObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isFetch(value) {
    return typeof value === "function";
}
function isJsonContentType(contentType) {
    if (contentType === null)
        return false;
    const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
    return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}
function contentTypeCategory(contentType) {
    if (contentType === null)
        return "missing";
    const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType === "application/json" || mediaType?.endsWith("+json") === true)
        return "json";
    if (mediaType?.startsWith("text/") === true)
        return "text";
    return "binary";
}
function isRetryableStatus(status) {
    return status === 408 || status === 425 || status === 429 || status >= 500;
}
function hasControlCharacter(value) {
    for (const character of value) {
        const code = character.charCodeAt(0);
        if (code <= 31 || code === 127)
            return true;
    }
    return false;
}
function safeSchemaPath(path) {
    const knownField = "(?:block_time|context|hash|high_element|high_element_index|leaf|leaf_index|leaves|limit|low_element|low_element_index|matches|merkle_context|next_cursor|nullifiers|output_context|output_slot|output_slots|path|payload|proofless|proofs|root|root_index|root_seq|salt|slot|tags|transactions|tree|tree_account|tree_type|tx_signature|tx_viewing_pk|view_tag)";
    const pattern = new RegExp(`^\\$(?:(?:\\.${knownField})|(?:\\[\\d+\\]))*$`, "u");
    return path.length <= 256 && pattern.test(path) ? path : undefined;
}
