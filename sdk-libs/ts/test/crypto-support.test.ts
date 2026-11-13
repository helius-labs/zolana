import { hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientError, fromClientCause } from "../src/client/error.js";
import { ensureX25519, runtimeName } from "../src/client/prover/tee/crypto-support.js";
import { encryptRequest } from "../src/client/prover/tee/encryption.js";
import { attestedProver } from "./helpers/attested-prover.js";

const notSupported = (): DOMException =>
  new DOMException("The algorithm is not supported", "NotSupportedError");

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a runtime without WebCrypto X25519 derivation", () => {
  it("fails an encrypted prover request with CLIENT_CRYPTO_UNSUPPORTED", async () => {
    const { prover, requests, restore } = attestedProver(() => new Response(null, { status: 503 }));
    try {
      // The first call passes the runtime probe and attests; the second fails
      // while encrypting, after the probe has already been answered.
      await expect(prover.health()).rejects.toMatchObject({ code: "CLIENT_PROVER_HTTP" });
      const deriveBits = vi
        .spyOn(globalThis.crypto.subtle, "deriveBits")
        .mockRejectedValue(notSupported());
      const error = await prover.health().then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(error).toBeInstanceOf(ClientError);
      expect(error).toMatchObject({
        code: "CLIENT_CRYPTO_UNSUPPORTED",
        details: { algorithm: "X25519", runtime: runtimeName() },
      });
      expect(deriveBits).toHaveBeenCalled();
      expect(requests.map((request) => request.path)).toEqual(["/attestation", "/health"]);
    } finally {
      restore();
    }
  });

  it("maps the error @hpke/core wraps around the DOMException", async () => {
    vi.spyOn(globalThis.crypto.subtle, "deriveBits").mockRejectedValue(notSupported());
    const key = hexToBytes("9fed9f6a7a3f0a7e1b8e0d5bd5ad4b0a8b8c5e2f3a6c7d8e9f0a1b2c3d4e5f60");
    await expect(
      encryptRequest(key, "POST", "/prove/merge", new Uint8Array()),
    ).rejects.toMatchObject({
      code: "CLIENT_CRYPTO_UNSUPPORTED",
      details: { algorithm: "X25519" },
    });
  });

  it("keeps any other encryption failure as it is", async () => {
    const failure = new TypeError("boom");
    vi.spyOn(globalThis.crypto.subtle, "deriveBits").mockRejectedValue(failure);
    const key = hexToBytes("9fed9f6a7a3f0a7e1b8e0d5bd5ad4b0a8b8c5e2f3a6c7d8e9f0a1b2c3d4e5f60");
    const error = await encryptRequest(key, "POST", "/prove/merge", new Uint8Array()).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).not.toBeInstanceOf(ClientError);
    expect(error).toMatchObject({ name: "EncapError" });
  });
});

describe("an unknown error cause", () => {
  it("keeps the class name of an unknown error but not its message", () => {
    const error = fromClientCause(new TypeError("seed 1234 leaked into a message"));
    expect(error.code).toBe("CLIENT_UNEXPECTED");
    expect(error.cause).toEqual({ category: "external", name: "TypeError" });
    expect(JSON.stringify(error.cause)).not.toContain("1234");
  });

  it("keeps a code next to the name", () => {
    const failure = Object.assign(new Error("connect ECONNREFUSED 10.0.0.1"), {
      code: "ECONNREFUSED",
    });
    expect(fromClientCause(failure).cause).toEqual({
      category: "external",
      code: "ECONNREFUSED",
      name: "Error",
    });
  });

  it("keeps a DOMException message unless it names a secret", () => {
    expect(fromClientCause(notSupported()).cause).toEqual({
      category: "external",
      name: "NotSupportedError",
      message: "The algorithm is not supported",
    });
    expect(fromClientCause(new DOMException("bad private key bytes", "DataError")).cause).toEqual({
      category: "external",
      name: "DataError",
    });
  });

  it("drops a name that is not an identifier or names a secret", () => {
    const odd = new Error("x");
    odd.name = "Error: api-key=abc";
    expect(fromClientCause(odd).cause).toEqual({ category: "external" });
    const secret = new Error("x");
    secret.name = "SecretKeyError";
    expect(fromClientCause(secret).cause).toEqual({ category: "external" });
    expect(fromClientCause("plain string").cause).toEqual({ category: "external" });
  });
});

describe("the X25519 runtime probe", () => {
  const real = globalThis.crypto;

  function stubCrypto(deriveBits: () => Promise<ArrayBuffer>) {
    const generateKey = vi.fn(() =>
      real.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]),
    );
    vi.stubGlobal("crypto", {
      getRandomValues: real.getRandomValues.bind(real),
      subtle: { generateKey, deriveBits: vi.fn(deriveBits) },
    });
    return generateKey;
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("refuses before the prover hears anything when deriveBits is unsupported", async () => {
    const generateKey = stubCrypto(() => Promise.reject(notSupported()));
    const { prover, requests, restore } = attestedProver(() => Response.json({}));
    try {
      for (let call = 0; call < 2; call++) {
        await expect(prover.health()).rejects.toMatchObject({
          code: "CLIENT_CRYPTO_UNSUPPORTED",
          details: { algorithm: "X25519", runtime: runtimeName() },
        });
      }
      expect(requests).toEqual([]);
      // The probe runs once per runtime.
      expect(generateKey).toHaveBeenCalledTimes(1);
    } finally {
      restore();
    }
  });

  it("refuses when key generation fails or WebCrypto is missing", async () => {
    vi.stubGlobal("crypto", {
      getRandomValues: real.getRandomValues.bind(real),
      subtle: {
        generateKey: () => Promise.reject(notSupported()),
        deriveBits: () => Promise.reject(notSupported()),
      },
    });
    await expect(ensureX25519()).rejects.toMatchObject({ code: "CLIENT_CRYPTO_UNSUPPORTED" });
    vi.stubGlobal("crypto", { getRandomValues: real.getRandomValues.bind(real) });
    await expect(ensureX25519()).rejects.toMatchObject({ code: "CLIENT_CRYPTO_UNSUPPORTED" });
  });

  it("passes on this runtime", async () => {
    await expect(ensureX25519()).resolves.toBeUndefined();
  });
});

describe("runtimeName", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("names Bun and Deno before the Node version they also report", () => {
    if ("Bun" in globalThis) {
      // Bun's own global cannot be replaced.
      expect(runtimeName()).toBe(`bun ${process.versions["bun"]}`);
      return;
    }
    vi.stubGlobal("Bun", { version: "1.2.22" });
    expect(runtimeName()).toBe("bun 1.2.22");
    vi.unstubAllGlobals();
    vi.stubGlobal("Deno", { version: { deno: "2.4.0" } });
    expect(runtimeName()).toBe("deno 2.4.0");
    vi.unstubAllGlobals();
    expect(runtimeName()).toBe(`node ${process.versions.node}`);
  });
});
