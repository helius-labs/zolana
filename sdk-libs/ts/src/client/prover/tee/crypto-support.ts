import { HpkeError, NotSupportedError } from "@hpke/core";

import { ClientError } from "../../error.js";

/**
 * The JavaScript runtime and its version, such as `bun 1.2.22`, `deno 2.4.0`
 * or `node 24.1.0`, `browser` in a browser, and undefined when it cannot be
 * told. Bun and Deno also report a Node version, so they are read first.
 */
export function runtimeName(): string | undefined {
  const bun = property(property(globalThis, "Bun"), "version");
  if (typeof bun === "string") return `bun ${bun}`;
  const deno = property(property(property(globalThis, "Deno"), "version"), "deno");
  if (typeof deno === "string") return `deno ${deno}`;
  const node = property(property(property(globalThis, "process"), "versions"), "node");
  if (typeof node === "string") return `node ${node}`;
  if (
    typeof property(globalThis, "document") === "object" ||
    typeof property(globalThis, "WorkerGlobalScope") === "function"
  ) {
    return "browser";
  }
  return undefined;
}

function cryptoUnsupported(algorithm: string): ClientError {
  const runtime = runtimeName();
  return new ClientError("CLIENT_CRYPTO_UNSUPPORTED", {
    details: runtime === undefined ? { algorithm } : { algorithm, runtime },
  });
}

// One probe per WebCrypto implementation: a runtime does not gain or lose an algorithm.
const x25519Probes = new WeakMap<X25519Api, Promise<void>>();

/**
 * Generates an X25519 key pair and derives a shared secret with it once per
 * runtime, so a runtime that can make X25519 keys but not agree on a secret
 * with them, such as Bun 1.2, fails with `CLIENT_CRYPTO_UNSUPPORTED` before
 * the first encrypted request instead of inside it.
 */
export function ensureX25519(): Promise<void> {
  const subtle = property(property(globalThis, "crypto"), "subtle");
  if (!isSubtleCrypto(subtle)) return Promise.reject(cryptoUnsupported("X25519"));
  let probe = x25519Probes.get(subtle);
  if (probe === undefined) {
    probe = probeX25519(subtle);
    x25519Probes.set(subtle, probe);
  }
  return probe;
}

type X25519Api = Pick<SubtleCrypto, "generateKey" | "deriveBits">;

async function probeX25519(subtle: X25519Api): Promise<void> {
  try {
    const pair = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    if (!("privateKey" in pair)) throw new TypeError("X25519 generateKey returned one key");
    await subtle.deriveBits({ name: "X25519", public: pair.publicKey }, pair.privateKey, 256);
  } catch {
    throw cryptoUnsupported("X25519");
  }
}

function isSubtleCrypto(value: unknown): value is X25519Api {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof property(value, "generateKey") === "function" &&
    typeof property(value, "deriveBits") === "function"
  );
}

/**
 * `CLIENT_CRYPTO_UNSUPPORTED` when `error` says the runtime lacks the
 * algorithm. WebCrypto throws a `NotSupportedError` DOMException; @hpke/core
 * rethrows it as its own `NotSupportedError`, or wraps it in another
 * `HpkeError` that keeps only the message, such as Bun's `EncapError` "The
 * algorithm is not supported".
 */
export function unsupportedCrypto(error: unknown, algorithm: string): ClientError | undefined {
  if (error instanceof NotSupportedError) return cryptoUnsupported(algorithm);
  if (!(error instanceof Error)) return undefined;
  if (error.name === "NotSupportedError") return cryptoUnsupported(algorithm);
  if (error instanceof HpkeError && UNSUPPORTED_MESSAGE.test(error.message)) {
    return cryptoUnsupported(algorithm);
  }
  return undefined;
}

const UNSUPPORTED_MESSAGE = /not supported|unrecognized algorithm/iu;

function property(value: unknown, key: string): unknown {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    return undefined;
  }
  return Reflect.get(value, key);
}
