// Test infrastructure only. No wallets, attestation trust or HPKE secrets live here.
import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { Transform } from "node:stream";

export const PREFIX = "/v1/zolana";
export const KEY_ID = "zolana-tee-key-id";
const ATTESTATION = "/tee/v1/attestation";
const MAX_BODY = 64 * 1024 * 1024 + 16;
const REQUEST_HEADERS = [
  "content-type",
  "zolana-tee",
  "zolana-tee-enc",
  "zolana-tee-ciphertext",
  KEY_ID,
  "x-sync",
  "x-async",
  "x-prover-timing",
  "x-request-id",
];
const RESPONSE_HEADERS = [
  "content-type",
  "zolana-tee",
  "retry-after",
  "server-timing",
  "x-prover-timing",
  "x-request-id",
];

export function recipientId(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error("expected a 32-byte HPKE public key");
  }
  return createHash("sha256")
    .update("zolana/prover-tee/v1/recipient")
    .update(publicKey)
    .digest("hex");
}

function checkedTimeout(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 600_000) {
    throw new Error("timeout must be 1–600000 milliseconds");
  }
  return value;
}

function endpoint(value) {
  const url = new URL(value);
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  ) {
    throw new Error("origin must be HTTPS or loopback HTTP, without credentials or a path");
  }
  return url;
}

function route(request) {
  const target = request.url ?? "";
  const separator = target.indexOf("?");
  const path = separator < 0 ? target : target.slice(0, separator);
  const query = separator < 0 ? "" : target.slice(separator + 1);
  // GK trims trailing slashes. Reject encoded paths and ambiguous path forms.
  const normalized = path?.replace(/\/+$/u, "");
  const bare = normalized?.startsWith(`${PREFIX}/`) ? normalized.slice(PREFIX.length) : undefined;
  const metadata = bare === ATTESTATION || bare === "/proving-keys" || bare === "/health";
  const get = metadata || /^\/prove\/[a-zA-Z0-9_-]{1,128}\/status$/u.test(bare ?? "");
  const post = /^\/prove\/[a-zA-Z0-9_-]{1,128}(?:\/indexed)?$/u.test(bare ?? "");
  if (!bare || !((request.method === "GET" && get) || (request.method === "POST" && post))) {
    return undefined;
  }
  return { path: `${PREFIX}${bare}`, query, bare, metadata };
}

function fail(response, status, code) {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify({ code }));
}

function singleHeader(request, name) {
  const values = request.headersDistinct[name];
  return values?.length === 1 ? values[0] : undefined;
}

function selectedHeaders(source, allow, drop = new Set()) {
  const headers = {};
  for (const name of allow) {
    if (drop.has(name)) continue;
    const value = source[name];
    if (typeof value === "string") headers[name] = value;
  }
  return headers;
}

function forward(request, response, origin, path, options) {
  if (request.headers["content-encoding"] && request.headers["content-encoding"] !== "identity") {
    fail(response, 400, "mock_content_encoding");
    return;
  }
  // Reject duplicates instead of silently joining protocol or delivery headers.
  if (REQUEST_HEADERS.some((name) => (request.headersDistinct[name]?.length ?? 0) > 1)) {
    fail(response, 400, "mock_duplicate_header");
    return;
  }
  const length = request.headers["content-length"];
  if (length && (!/^\d+$/u.test(length) || Number(length) > MAX_BODY)) {
    fail(response, 413, "mock_body_limit");
    return;
  }
  const headers = selectedHeaders(request.headers, REQUEST_HEADERS, options.dropRequest);
  if (options.apiKey !== undefined) headers["x-api-key"] = options.apiKey;
  const upstream = (origin.protocol === "https:" ? https : http).request({
    protocol: origin.protocol,
    hostname: origin.hostname.replace(/^\[|\]$/gu, ""),
    port: origin.port || undefined,
    method: request.method,
    path,
    headers,
  });
  let bytes = 0;
  const limit = new Transform({
    transform(chunk, _encoding, next) {
      bytes += chunk.length;
      if (bytes > MAX_BODY) {
        fail(response, 413, "mock_body_limit");
        next(new Error("body limit"));
      } else next(null, chunk);
    },
  });
  // Never retry a request: the upstream may already have consumed its body.
  const timer = setTimeout(() => {
    fail(response, 504, "mock_upstream_timeout");
    upstream.destroy();
  }, options.timeoutMs);
  timer.unref();
  const stop = () => {
    clearTimeout(timer);
    upstream.destroy();
    limit.destroy();
  };
  response.once("close", stop);
  request.once("aborted", stop);
  request.once("error", stop);
  limit.once("error", () => upstream.destroy());
  upstream.once("error", () => fail(response, 502, "mock_upstream_unavailable"));
  upstream.once("response", (incoming) => {
    const outgoing = selectedHeaders(incoming.headers, RESPONSE_HEADERS, options.dropResponse);
    outgoing["cache-control"] = "no-store";
    response.writeHead(incoming.statusCode ?? 502, outgoing);
    incoming.once("aborted", () => response.destroy());
    incoming.once("error", () => response.destroy());
    incoming.pipe(response);
  });
  request.pipe(limit).pipe(upstream);
}

/** Small GK stand-in: fixed origin, API-key authentication and header/CORS policy. */
export function createMockGateway({ apiKey, origin, allowedOrigins = [], timeoutMs = 600_000 }) {
  if (typeof apiKey !== "string" || !apiKey) throw new Error("a test API key is required");
  checkedTimeout(timeoutMs);
  if (
    !Array.isArray(allowedOrigins) ||
    allowedOrigins.some((value) => {
      try {
        const url = new URL(value);
        return !["http:", "https:"].includes(url.protocol) || url.origin !== value;
      } catch {
        return true;
      }
    })
  )
    throw new Error("expected exact HTTP(S) browser origins");
  const target = endpoint(origin);
  const expected = createHash("sha256").update(apiKey).digest();
  const origins = new Set(allowedOrigins);
  const faults = { dropRequest: new Set(), dropResponse: new Set() };
  const stats = { forwarded: 0, rejected: 0, preflights: 0 };
  const handler = (request, response) => {
    const originHeader = singleHeader(request, "origin");
    if (request.headers.origin && (!originHeader || !origins.has(originHeader))) {
      fail(response, 403, "mock_origin_refused");
      return;
    }
    if (originHeader) {
      response.setHeader("access-control-allow-origin", originHeader);
      response.setHeader("vary", "Origin");
      response.setHeader("access-control-expose-headers", RESPONSE_HEADERS.join(", "));
    }
    if (request.method === "OPTIONS") {
      const method = singleHeader(request, "access-control-request-method");
      const allowed = route({ url: request.url, method });
      const requested = (singleHeader(request, "access-control-request-headers") ?? "")
        .toLowerCase()
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      if (!originHeader || !allowed || requested.some((name) => !REQUEST_HEADERS.includes(name))) {
        fail(response, 403, "mock_preflight_refused");
        return;
      }
      stats.preflights++;
      response.writeHead(204, {
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": REQUEST_HEADERS.join(", "),
        "access-control-max-age": "0",
        "cache-control": "no-store",
      });
      response.end();
      return;
    }
    const matched = route(request);
    if (!matched) {
      fail(response, 404, "mock_route_unknown");
      return;
    }
    const keys = new URLSearchParams(matched.query).getAll("api-key");
    if (
      keys.length !== 1 ||
      !timingSafeEqual(expected, createHash("sha256").update(keys[0]).digest())
    ) {
      stats.rejected++;
      fail(response, 401, "mock_api_key_refused");
      return;
    }
    // Preserve the original non-credential query bytes: HPKE authenticates them.
    const query = matched.query
      .split("&")
      .filter((pair) => pair && !new URLSearchParams(pair).has("api-key"))
      .join("&");
    stats.forwarded++;
    forward(request, response, target, matched.path + (query ? `?${query}` : ""), {
      ...faults,
      timeoutMs,
    });
  };
  return { handler, stats, faults };
}

/** Test recipient router: attestation may choose a region; ciphertext never does. */
export function createRecipientRouter({ deployments, timeoutMs = 600_000 }) {
  checkedTimeout(timeoutMs);
  if (!Array.isArray(deployments) || deployments.length < 1 || deployments.length > 32) {
    throw new Error("expected 1–32 deployments");
  }
  const entries = deployments.map((entry) => {
    if (
      !/^[a-zA-Z0-9_-]{1,128}$/u.test(entry.id) ||
      !/^[0-9a-f]{64}$/u.test(entry.recipientId) ||
      typeof entry.region !== "string" ||
      !entry.region ||
      (entry.apiKey !== undefined &&
        (typeof entry.apiKey !== "string" || !/^[\x21-\x7e]{1,4096}$/u.test(entry.apiKey)))
    )
      throw new Error("invalid deployment");
    return { ...entry, origin: endpoint(entry.origin), available: true, draining: false };
  });
  if (
    new Set(entries.map((e) => e.id)).size !== entries.length ||
    new Set(entries.map((e) => e.recipientId)).size !== entries.length
  ) {
    throw new Error("duplicate deployment or recipient");
  }
  let next = 0;
  const stats = {
    attestations: 0,
    unavailable: 0,
    forwarded: Object.fromEntries(entries.map((e) => [e.id, 0])),
  };
  const handler = (request, response) => {
    const matched = route(request);
    if (!matched) {
      fail(response, 404, "mock_route_unknown");
      return;
    }
    const encrypted = singleHeader(request, "zolana-tee") !== undefined;
    let entry;
    if (encrypted) {
      if (singleHeader(request, "zolana-tee") !== "v1") {
        fail(response, 400, "tee_version_unsupported");
        return;
      }
      const id = singleHeader(request, KEY_ID);
      if (!id || !/^[0-9a-f]{64}$/u.test(id)) {
        fail(response, 400, "tee_recipient_required");
        return;
      }
      entry = entries.find((e) => e.recipientId === id && e.available);
    } else {
      if (!matched.metadata) {
        fail(response, 400, "tee_required");
        return;
      }
      const available = entries.filter((e) => e.available && !e.draining);
      entry = available[next++ % available.length];
      if (matched.bare === ATTESTATION) stats.attestations++;
    }
    if (!entry) {
      // This response is emitted only BEFORE forwarding; re-attest + re-encrypt is safe.
      stats.unavailable++;
      fail(response, 503, "tee_generation_unavailable");
      return;
    }
    stats.forwarded[entry.id]++;
    forward(
      request,
      response,
      entry.origin,
      matched.path + (matched.query ? `?${matched.query}` : ""),
      { timeoutMs, apiKey: entry.apiKey },
    );
  };
  return {
    handler,
    stats,
    setAvailable(id, available) {
      const entry = entries.find((e) => e.id === id);
      if (!entry || typeof available !== "boolean")
        throw new Error("unknown deployment or availability");
      entry.available = available;
    },
    setDraining(id, draining) {
      const entry = entries.find((e) => e.id === id);
      if (!entry || typeof draining !== "boolean")
        throw new Error("unknown deployment or drain state");
      entry.draining = draining;
    },
  };
}

export async function listen(handler, port = 0) {
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error("invalid TCP port");
  const server = http.createServer({ maxHeaderSize: 32 * 1024 }, handler);
  server.requestTimeout = 610_000;
  server.headersTimeout = 10_000;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing listener address");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeIdleConnections();
      }),
  };
}
