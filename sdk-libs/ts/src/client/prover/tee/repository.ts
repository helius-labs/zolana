import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { checkedEndpoint, checkedFetch } from "../../../services/transport.js";
import { requestError, type ComposedSignal } from "../../internal.js";
import { uniqueJson } from "./json.js";
import { invalidPolicy, refused } from "./platform.js";

export const LIMITS = {
  root: 512_000,
  timestamp: 16_384,
  snapshot: 2 << 20,
  targets: 2 << 20,
} as const;
export const MAX_POLICY_BYTES = 1 << 20;

export function repositoryUrl(value: string | URL): URL {
  let url: URL;
  try {
    url = checkedEndpoint(value, { field: "tee.source.url", allowLoopbackHttp: true });
  } catch {
    throw invalidPolicy("source.url");
  }
  if (url.search) throw invalidPolicy("source.url");
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

export function sourceFetch(value: unknown): typeof globalThis.fetch {
  try {
    return checkedFetch(value);
  } catch {
    throw invalidPolicy("source.fetch");
  }
}

export function checkAbort(request: ComposedSignal): void {
  if (request.signal.aborted) throw requestError("attest", request);
}

export function digest(value: string | Uint8Array): string {
  return bytesToHex(sha256(typeof value === "string" ? utf8ToBytes(value) : value));
}

export function text(bytes: Uint8Array): string {
  // Preserve BOMs so JSON validation cannot silently rewrite signed bytes.
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

export function parseJson(bytes: Uint8Array): unknown {
  try {
    return uniqueJson(text(bytes));
  } catch {
    throw refused("policy_json");
  }
}
