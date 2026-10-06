import { readFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import { ProverClient } from "../src/client/prover/client.js";
import {
  decryptResponse,
  requestAad,
  encryptRequest,
} from "../src/client/prover/tee/encryption.js";
import { TeeSession, encryptedInit, type ProverCall } from "../src/client/prover/tee/session.js";
import { composeSignal } from "../src/client/internal.js";
import { attestationRetryDelayMs } from "../src/client/prover/retry.js";
import { DEFAULT_TEE_POLICY_FILE } from "../src/client/prover/tee/default.js";
import {
  defaultTeePolicy,
  teePolicyFromJson,
  type TeePolicy,
} from "../src/client/prover/tee/policy.js";
import { reportData, verifyAttestation } from "../src/client/prover/tee/verify.js";
import { wireDecoder } from "../src/interface/decode.js";

const json = (path: string): unknown =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const decode = wireDecoder((path) => new Error(`fixture ${path}`));

const probe = decode.record(json("../../../prover/tee/testdata/probe_attestation.json"), "probe");
const probeAttestation = decode.record(probe["attestation"], "attestation");
const capturedAt = Number(decode.integer(probe["captured_at"], "captured_at"));
const probePolicyJson = decode.record(
  json("../../../prover/tee/testdata/probe_policy.json"),
  "policy",
);
const livePolicy = teePolicyFromJson(
  decode.record(json("../../../prover/tee/testdata/live_policy.json"), "live_policy")["deployment"],
);
const vectors = decode.record(json("../../../prover/tee/testdata/vectors.json"), "vectors");
const vector = (field: string): string => decode.string(vectors[field], field);

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

function check(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    if (error instanceof ClientError && error.code === "CLIENT_PROVER_TEE_ATTESTATION") {
      return decode.string(decode.record(error.details, "details")["check"], "check");
    }
    throw error;
  }
  return undefined;
}

describe("TEE policy", () => {
  it("mirrors the Rust SDK's pinned policy file", () => {
    expect(DEFAULT_TEE_POLICY_FILE).toEqual(json("../../client/src/prover/tee/policy.json"));
  });

  it("accepts the archived deployment attestation", () => {
    const live = decode.record(json("../../../prover/tee/testdata/live_attestation.json"), "live");
    const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
    const at = Number(decode.integer(live["captured_at"], "captured_at"));
    const prover = verifyAttestation(live["attestation"], livePolicy, nonce, at);
    expect(prover.gpuVerified).toBe(true);
    expect(
      check(() => verifyAttestation(live["attestation"], livePolicy, new Uint8Array(32), at)),
    ).toBe("report_data");
  });

  it("loads the release pin or refuses its absence", () => {
    if (DEFAULT_TEE_POLICY_FILE.deployment === null) {
      expect(check(defaultTeePolicy)).toBe("no_default_deployment");
    } else {
      expect(defaultTeePolicy()).toEqual(teePolicyFromJson(DEFAULT_TEE_POLICY_FILE.deployment));
    }
  });

  it("rejects a malformed policy", () => {
    expect(() => teePolicyFromJson({ ...probePolicyJson, app_id: "00" })).toThrow(ClientError);
    expect(() => teePolicyFromJson({ ...probePolicyJson, gpu: "sometimes" })).toThrow(ClientError);
  });
});

describe("attestation verification", () => {
  const policy = teePolicyFromJson(probePolicyJson);

  it("passes a real quote through every check before report_data", () => {
    expect(
      check(() => verifyAttestation(probeAttestation, policy, new Uint8Array(32), capturedAt)),
    ).toBe("report_data");
  });

  const cases: readonly (readonly [string, Partial<TeePolicy>, number])[] = [
    ["tcb_status", { tcbStatuses: [] }, 0],
    ["quote", {}, 400 * 86_400],
    ["measurement", { measurements: [] }, 0],
    ["app_id", { appId: "00".repeat(20) }, 0],
    ["compose_hash", { composeHashes: [] }, 0],
    ["os_image", { osImageHashes: [] }, 0],
    ["key_provider", { keyProviderId: "" }, 0],
    ["hpke_key", { hpkePublicKey: "11".repeat(32) }, 0],
  ];
  it.each(cases)("refuses with %s", (expected, policyEdit, skew) => {
    expect(
      check(() =>
        verifyAttestation(
          probeAttestation,
          { ...policy, ...policyEdit },
          new Uint8Array(32),
          capturedAt + skew,
        ),
      ),
    ).toBe(expected);
  });

  it("refuses a payload swapped under a digest that still replays", () => {
    const events = decode.list(probeAttestation["event_log"], "event_log").map((entry) => {
      const event = decode.record(entry, "event");
      if (event["event"] !== "compose-hash") return event;
      const payload = decode.string(event["event_payload"], "payload");
      return { ...event, event_payload: `${payload[0] === "0" ? "1" : "0"}${payload.slice(1)}` };
    });
    expect(
      check(() =>
        verifyAttestation(
          { ...probeAttestation, event_log: events },
          policy,
          new Uint8Array(32),
          capturedAt,
        ),
      ),
    ).toBe("event_log");
  });

  it("computes report_data as the Go prover does", () => {
    const nonce = hexToBytes(vector("nonce"));
    const key = hexToBytes(vector("hpke_public_key"));
    expect(bytesToHex(reportData(nonce, key, utf8ToBytes(vector("gpu_token"))))).toBe(
      vector("report_data"),
    );
    expect(bytesToHex(reportData(nonce, key, undefined))).toBe(vector("report_data_no_gpu"));
  });
});

describe("encryption", () => {
  it("rejects tampered and truncated responses", () => {
    const key = hexToBytes(vector("response_key"));
    const encrypted = hexToBytes(vector("encrypted_response"));
    expect(encrypted.length).toBe(12 + 2 + utf8ToBytes(vector("response_body")).length + 16);
    const reject = (body: Uint8Array, responseKey = key): void => {
      expect(() => decryptResponse(responseKey, body)).toThrow(
        expect.objectContaining({ code: "CLIENT_PROVER_TEE_ENCRYPTION" }),
      );
    };
    for (const offset of [0, 12, encrypted.length - 1]) {
      const tampered = encrypted.slice();
      tampered.set([tampered[offset]! ^ 1], offset);
      reject(tampered);
    }
    for (let end = 0; end < encrypted.length; end++) reject(encrypted.subarray(0, end));
    reject(encrypted.subarray(12));
    const wrongKey = key.slice();
    wrongKey.set([wrongKey[0]! ^ 1]);
    reject(encrypted, wrongKey);
  });

  async function recipient(enc: Uint8Array) {
    const pair = await suite.kem.deriveKeyPair(hexToBytes(vector("ikm")));
    expect(bytesToHex(new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)))).toBe(
      vector("hpke_public_key"),
    );
    return suite.createRecipientContext({
      recipientKey: pair,
      enc,
      info: utf8ToBytes("zolana/prover-tee/v1"),
    });
  }

  it("interoperates with the Go prover", async () => {
    const context = await recipient(hexToBytes(vector("enc")));
    const aad = utf8ToBytes(requestAad(vector("method"), vector("request_uri")));
    const plaintext = new Uint8Array(await context.open(hexToBytes(vector("ciphertext")), aad));
    expect(new TextDecoder().decode(plaintext)).toBe(vector("plaintext"));
    const responseKey = new Uint8Array(
      await context.export(utf8ToBytes("zolana/prover-tee/v1/response"), 32),
    );
    expect(bytesToHex(responseKey)).toBe(vector("response_key"));
    const opened = decryptResponse(responseKey, hexToBytes(vector("encrypted_response")));
    expect(opened.status).toBe(Number(decode.integer(vectors["response_status"], "status")));
    expect(new TextDecoder().decode(opened.body)).toBe(vector("response_body"));
  });

  it("drops every credential from the AAD as the Go prover does", () => {
    const cases = decode.list(vectors["aad_cases"], "aad_cases");
    expect(cases.length).toBeGreaterThan(0);
    for (const entry of cases) {
      const c = decode.record(entry, "case");
      expect(
        requestAad(
          decode.string(c["method"], "method"),
          decode.string(c["request_target"], "target"),
        ),
      ).toBe(decode.string(c["aad"], "aad"));
    }
  });

  it("opens only on the route it was encrypted for", async () => {
    const encrypted = await encryptRequest(
      hexToBytes(vector("hpke_public_key")),
      "GET",
      "/prove/merge/status?jobId=a",
      new Uint8Array(),
    );
    const opensOn = async (uri: string): Promise<boolean> => {
      const context = await recipient(hexToBytes(encrypted.enc));
      return context.open(encrypted.body, utf8ToBytes(`GET ${uri}`)).then(
        () => true,
        () => false,
      );
    };
    expect(await opensOn("/prove/merge/status?jobId=a")).toBe(true);
    expect(await opensOn("/prove/merge/status?jobId=b")).toBe(false);
  });
});

describe("encrypted request shape", () => {
  const call = (method: "GET" | "POST"): ProverCall => ({
    fetch: globalThis.fetch,
    attestationUrl: new URL("https://prover.example/tee/v1/attestation"),
    url: new URL("https://prover.example/prove/merge/status?jobId=a"),
    method,
    headers: { "X-Sync": "true" },
    signal: composeSignal(undefined, "test"),
    maxResponseBytes: 1024,
  });
  const encrypted = {
    enc: "ab",
    body: new Uint8Array([1, 2]),
    decrypt: () => ({ status: 200, body: new Uint8Array() }),
  };

  it("puts a GET's encrypted bytes in a header, fetch refuses a GET body", () => {
    const init = encryptedInit(call("GET"), encrypted);
    expect(init.body).toBeUndefined();
    expect(init.headers).toMatchObject({
      "Zolana-Tee": "v1",
      "Zolana-Tee-Enc": "ab",
      "Zolana-Tee-Ciphertext": "0102",
    });
  });

  it("keeps a POST's encrypted bytes in the body", () => {
    const init = encryptedInit(call("POST"), encrypted);
    expect(init.body).toEqual(new Uint8Array([1, 2]));
    expect(init.headers).not.toHaveProperty("Zolana-Tee-Ciphertext");
  });
});

describe("a TEE prover client", () => {
  it.each([
    ["no endpoint", () => new Response("404 page not found", { status: 404 })],
    ["junk attestation", () => Response.json({ quote: "00" })],
  ])("sends nothing but the attestation request to a prover with %s", async (_name, answer) => {
    const requested: string[] = [];
    const prover = new ProverClient({
      url: "https://prover.example",
      tee: teePolicyFromJson(probePolicyJson),
      fetch: (input) => {
        requested.push(new URL(String(input)).pathname);
        return Promise.resolve(answer());
      },
    });
    await expect(prover.checkProvingKeys()).rejects.toThrow(ClientError);
    expect(requested).toEqual(["/tee/v1/attestation"]);
  });
});

it("keeps the cached key independent of the attestation report", async () => {
  const live = decode.record(json("../../../prover/tee/testdata/live_attestation.json"), "live");
  const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
  const at = Number(decode.integer(live["captured_at"], "captured_at"));
  const random = vi.spyOn(globalThis.crypto, "getRandomValues");
  random.mockImplementationOnce((bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce buffer");
    bytes.set(nonce);
    return bytes;
  });
  const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
  const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(live["attestation"]));
  const signal = composeSignal(undefined, "attest");
  try {
    const session = new TeeSession(livePolicy);
    const url = new URL("https://prover.invalid/prove/merge");
    const attestationUrl = new URL("https://prover.invalid/tee/v1/attestation");
    const report = await session.attest(fetch, attestationUrl, signal);
    const substituted = await suite.kem.deriveKeyPair(new Uint8Array(32).fill(42));
    report.hpkePublicKey.set(
      new Uint8Array(await suite.kem.serializePublicKey(substituted.publicKey)),
    );
    const prepared = await session.encrypt({
      fetch,
      attestationUrl,
      url,
      method: "POST",
      headers: {},
      body: "private-witness-marker",
      signal,
      maxResponseBytes: 1024,
    });
    const headers = new Headers(prepared.init.headers);
    const enc = hexToBytes(decode.string(headers.get("Zolana-Tee-Enc"), "enc"));
    const receiver = await suite.createRecipientContext({
      recipientKey: substituted,
      enc,
      info: utf8ToBytes("zolana/prover-tee/v1"),
    });
    const body = prepared.init.body;
    if (!(body instanceof Uint8Array)) throw new Error("unexpected encrypted body");
    await expect(receiver.open(body, utf8ToBytes("POST /prove/merge"))).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  } finally {
    signal.cleanup();
    random.mockRestore();
    now.mockRestore();
  }
});

describe("attestation retries", () => {
  it("waits only on busy and unavailable answers", () => {
    expect(attestationRetryDelayMs(429, "3")).toBe(3_000n);
    expect(attestationRetryDelayMs(429, "86400")).toBe(30_000n);
    expect(attestationRetryDelayMs(429, "Wed, 21 Oct 2026 07:28:00 GMT")).toBe(2_000n);
    expect(attestationRetryDelayMs(429, null)).toBe(2_000n);
    expect(attestationRetryDelayMs(503, null)).toBe(2_000n);
    for (const status of [400, 401, 404, 500]) {
      expect(attestationRetryDelayMs(status, null)).toBeUndefined();
    }
  });

  it("retries a busy prover after its Retry-After", async () => {
    const answers = [
      () => new Response("busy", { status: 429, headers: { "Retry-After": "0" } }),
      () => Response.json({ quote: "00" }),
    ];
    const requested: string[] = [];
    const prover = new ProverClient({
      url: "https://prover.example",
      tee: teePolicyFromJson(probePolicyJson),
      fetch: (input) => {
        requested.push(new URL(String(input)).pathname);
        const answer = answers.shift();
        if (answer === undefined) throw new Error("unexpected request");
        return Promise.resolve(answer());
      },
    });
    const error = await prover.attest().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ClientError);
    if (!(error instanceof ClientError)) return;
    expect(error.details).toEqual({ check: "malformed_attestation" });
    expect(requested).toEqual(["/tee/v1/attestation", "/tee/v1/attestation"]);
  });

  it("shares one attestation between concurrent calls", async () => {
    const live = decode.record(json("../../../prover/tee/testdata/live_attestation.json"), "live");
    const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
    const at = Number(decode.integer(live["captured_at"], "captured_at"));
    const random = vi.spyOn(globalThis.crypto, "getRandomValues");
    random.mockImplementationOnce((bytes) => {
      if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce buffer");
      bytes.set(nonce);
      return bytes;
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(live["attestation"]));
    const signal = composeSignal(undefined, "attest");
    try {
      const session = new TeeSession(livePolicy);
      const attestationUrl = new URL("https://prover.invalid/tee/v1/attestation");
      const provers = await Promise.all(
        [0, 1, 2, 3].map(() => session.attest(fetch, attestationUrl, signal)),
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(new Set(provers.map((prover) => bytesToHex(prover.hpkePublicKey))).size).toBe(1);
    } finally {
      signal.cleanup();
      random.mockRestore();
      now.mockRestore();
    }
  });
});
