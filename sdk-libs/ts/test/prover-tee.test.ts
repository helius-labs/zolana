import { readFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { p384 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  BasicConstraints,
  Certificate,
  Extension,
  Extensions,
  KeyUsage,
  KeyUsageFlags,
  Name,
  RelativeDistinguishedName,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
  id_ce_basicConstraints,
  id_ce_keyUsage,
} from "@peculiar/asn1-x509";
import { Tagged, encode as encodeCbor } from "cborg";
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
import { defaultTeePolicy, teePolicyFromJson } from "../src/client/prover/tee/policy.js";
import {
  PLATFORMS,
  type DstackTdxPolicy,
  type PlatformTable,
} from "../src/client/prover/tee/registry.js";
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
const livePolicy = dstackPolicy(
  decode.record(json("../../../prover/tee/testdata/live_policy.json"), "live_policy")["deployment"],
);
const vectors = decode.record(json("../../../prover/tee/testdata/vectors.json"), "vectors");
const vector = (field: string): string => decode.string(vectors[field], field);

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

function dstackPolicy(policyJson: unknown): DstackTdxPolicy {
  const policy = teePolicyFromJson(policyJson);
  if (policy.platform !== "dstack-tdx") throw new Error("fixture platform");
  return policy;
}

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
    expect(prover).toMatchObject({
      platform: "dstack-tdx",
      tcbStatus: "UpToDate",
      gpuVerified: true,
    });
    expect([bytesToHex(prover.imageId)]).toEqual(livePolicy.composeHashes);
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
    const field = (policyJson: unknown): unknown => {
      try {
        teePolicyFromJson(policyJson);
      } catch (error) {
        if (error instanceof ClientError && error.code === "CLIENT_INVALID_CONFIG") {
          return decode.record(error.details, "details")["field"];
        }
        throw error;
      }
      return undefined;
    };
    const measurement = decode.record(
      decode.list(probePolicyJson["measurements"], "measurements")[0],
      "measurement",
    );
    expect(field({ ...probePolicyJson, app_id: "00" })).toBe("tee.app_id");
    expect(field({ ...probePolicyJson, gpu: "sometimes" })).toBe("tee.gpu");
    expect(field({ ...probePolicyJson, platform: "sev-snp" })).toBe("tee.platform");
    expect(field({ ...probePolicyJson, platform: undefined })).toBe("tee.platform");
    expect(field({ ...probePolicyJson, pcr0: "00" })).toBe("tee.pcr0");
    expect(field({ ...probePolicyJson, measurements: [{ ...measurement, rtmr3: "00" }] })).toBe(
      "tee.rtmr3",
    );
    expect(field({ ...probePolicyJson, platform: "aws-nitro" })).toBe("tee.pcr0");
  });
});

describe("attestation verification", () => {
  const policy = dstackPolicy(probePolicyJson);

  it("passes a real quote through every check before report_data", () => {
    expect(
      check(() => verifyAttestation(probeAttestation, policy, new Uint8Array(32), capturedAt)),
    ).toBe("report_data");
  });

  const cases: readonly (readonly [string, Partial<DstackTdxPolicy>, number])[] = [
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
    const evidence = decode.record(probeAttestation["evidence"], "evidence");
    const events = decode.list(evidence["event_log"], "event_log").map((entry) => {
      const event = decode.record(entry, "event");
      if (event["event"] !== "compose-hash") return event;
      const payload = decode.string(event["event_payload"], "payload");
      return { ...event, event_payload: `${payload[0] === "0" ? "1" : "0"}${payload.slice(1)}` };
    });
    expect(
      check(() =>
        verifyAttestation(
          { ...probeAttestation, evidence: { ...evidence, event_log: events } },
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
  const sent: RequestInit[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
    if (init?.method === undefined) return Response.json(live["attestation"]);
    sent.push(init);
    return new Response(null, { status: 503 });
  });
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
    await session.send({
      fetch,
      attestationUrl,
      url,
      method: "POST",
      headers: {},
      body: "private-witness-marker",
      signal,
      maxResponseBytes: 1024,
    });
    const [init] = sent;
    if (init === undefined) throw new Error("no encrypted call");
    const headers = new Headers(init.headers);
    const enc = hexToBytes(decode.string(headers.get("Zolana-Tee-Enc"), "enc"));
    const receiver = await suite.createRecipientContext({
      recipientKey: substituted,
      enc,
      info: utf8ToBytes("zolana/prover-tee/v1"),
    });
    const body = init.body;
    if (!(body instanceof Uint8Array)) throw new Error("unexpected encrypted body");
    await expect(receiver.open(body, utf8ToBytes("POST /prove/merge"))).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(2);
  } finally {
    signal.cleanup();
    random.mockRestore();
    now.mockRestore();
  }
});

it("keeps a concurrent attestation report out of an encrypted request", async () => {
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
  const sent: RequestInit[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
    if (init?.method === undefined) return Response.json(live["attestation"]);
    sent.push(init);
    return new Response(null, { status: 503 });
  });
  const signal = composeSignal(undefined, "attest");
  try {
    const session = new TeeSession(livePolicy);
    const attestationUrl = new URL("https://prover.invalid/tee/v1/attestation");
    const substituted = await suite.kem.deriveKeyPair(new Uint8Array(32).fill(42));
    const key = new Uint8Array(await suite.kem.serializePublicKey(substituted.publicKey));
    const report = session.attest(fetch, attestationUrl, signal).then((prover) => {
      prover.hpkePublicKey.set(key);
    });
    const request = session.send({
      fetch,
      attestationUrl,
      url: new URL("https://prover.invalid/prove/merge"),
      method: "POST",
      headers: {},
      body: "private-witness-marker",
      signal,
      maxResponseBytes: 1024,
    });
    await Promise.all([report, request]);
    const [init] = sent;
    if (init === undefined) throw new Error("no encrypted call");
    const headers = new Headers(init.headers);
    const enc = hexToBytes(decode.string(headers.get("Zolana-Tee-Enc"), "enc"));
    const receiver = await suite.createRecipientContext({
      recipientKey: substituted,
      enc,
      info: utf8ToBytes("zolana/prover-tee/v1"),
    });
    const body = init.body;
    if (!(body instanceof Uint8Array)) throw new Error("unexpected encrypted body");
    await expect(receiver.open(body, utf8ToBytes("POST /prove/merge"))).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(2);
  } finally {
    signal.cleanup();
    random.mockRestore();
    now.mockRestore();
  }
});

describe("attestation retries", () => {
  it("waits only on busy and unavailable answers", () => {
    const now = Date.parse("Wed, 21 Oct 2026 07:28:00 GMT");
    const delay = (status: number, retryAfter: string | null) =>
      attestationRetryDelayMs(status, retryAfter, now);
    expect(delay(429, "3")).toBe(3_000n);
    expect(delay(429, "86400")).toBe(30_000n);
    expect(delay(429, "99999999999999999999999")).toBe(30_000n);
    expect(delay(429, "Wed, 21 Oct 2026 07:28:10 GMT")).toBe(10_000n);
    expect(delay(429, "Wed, 21 Oct 2026 07:27:00 GMT")).toBe(0n);
    expect(delay(429, "Wed, 21 Oct 2026 08:28:00 GMT")).toBe(30_000n);
    for (const garbage of [
      "soon",
      "+3",
      "-3",
      "Thu, 21 Oct 2026 07:28:10 GMT",
      "Wed, 31 Feb 2026 07:28:10 GMT",
      "Wed, 31 Dec 1969 23:59:59 GMT",
      "Wednesday, 21-Oct-26 07:28:10 GMT",
      "Wed Oct 21 07:28:10 2026",
    ]) {
      expect(delay(429, garbage)).toBe(2_000n);
    }
    expect(delay(429, null)).toBe(2_000n);
    expect(delay(503, null)).toBe(2_000n);
    for (const status of [400, 401, 404, 500]) {
      expect(delay(status, null)).toBeUndefined();
    }
  });

  it("retries a busy prover after its Retry-After", async () => {
    vi.useFakeTimers();
    const answers = [
      () => new Response("busy", { status: 429, headers: { "Retry-After": "5" } }),
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
    try {
      const attempt = prover.attest().catch((caught: unknown) => caught);
      await vi.advanceTimersByTimeAsync(4_999);
      expect(requested).toEqual(["/tee/v1/attestation"]);
      await vi.advanceTimersByTimeAsync(1);
      const error = await attempt;
      expect(error).toBeInstanceOf(ClientError);
      if (!(error instanceof ClientError)) return;
      expect(error.details).toEqual({ check: "malformed_attestation" });
      expect(requested).toEqual(["/tee/v1/attestation", "/tee/v1/attestation"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("lets a joining call time out while the shared attestation hangs", async () => {
    const hung = vi.fn<typeof globalThis.fetch>(() => new Promise<Response>(() => undefined));
    const session = new TeeSession(livePolicy);
    const attestationUrl = new URL("https://prover.invalid/tee/v1/attestation");
    const owner = composeSignal(undefined, "attest");
    const joiner = composeSignal({ timeoutMs: 20 }, "attest");
    try {
      void session.attest(hung, attestationUrl, owner).catch(() => undefined);
      const error = await session
        .attest(hung, attestationUrl, joiner)
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ClientError);
      if (!(error instanceof ClientError)) return;
      expect(error.code).toBe("CLIENT_TIMEOUT");
      expect(hung).toHaveBeenCalledTimes(1);
    } finally {
      owner.cleanup();
      joiner.cleanup();
    }
  });

  it("restarts the attestation when the call that started it cancels", async () => {
    const urls: string[] = [];
    const fetch = vi.fn<typeof globalThis.fetch>((input, init) => {
      urls.push(String(input));
      if (urls.length > 1) return Promise.resolve(Response.json({ quote: "00" }));
      return new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    });
    const session = new TeeSession(livePolicy);
    const attestationUrl = new URL("https://prover.invalid/tee/v1/attestation");
    const controller = new AbortController();
    const owner = composeSignal({ signal: controller.signal }, "attest");
    const joiner = composeSignal(undefined, "attest");
    try {
      const first = session.attest(fetch, attestationUrl, owner).catch((caught: unknown) => caught);
      const second = session
        .attest(fetch, attestationUrl, joiner)
        .catch((caught: unknown) => caught);
      controller.abort();
      expect(await first).toMatchObject({ code: "CLIENT_ABORTED" });
      expect(await second).toMatchObject({ details: { check: "malformed_attestation" } });
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      owner.cleanup();
      joiner.cleanup();
    }
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
      const otherKey = provers[1]!.hpkePublicKey.slice();
      const otherImage = provers[1]!.imageId.slice();
      provers[0]!.hpkePublicKey.fill(0);
      provers[0]!.imageId.fill(0);
      expect(provers[1]!.hpkePublicKey).toEqual(otherKey);
      expect(provers[1]!.imageId).toEqual(otherImage);
    } finally {
      signal.cleanup();
      random.mockRestore();
      now.mockRestore();
    }
  });
});

describe("a prover that lost the attested key", () => {
  const fixtures = {
    "aws-nitro": ["nitro_live_attestation.json", "nitro_live_policy.json"],
    "dstack-tdx": ["live_attestation.json", "live_policy.json"],
  } as const;

  /** Each prover call's path and whether it went out encrypted. */
  async function calls(
    platform: keyof typeof fixtures,
    answer: () => Response,
    outcome: Readonly<Record<string, unknown>>,
  ): Promise<readonly (readonly [string, boolean])[]> {
    const [attestationFile, policyFile] = fixtures[platform];
    const testdata = (file: string): unknown => json(`../../../prover/tee/testdata/${file}`);
    const live = decode.record(testdata(attestationFile), "live");
    const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
    const at = Number(decode.integer(live["captured_at"], "captured_at"));
    const fill = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((bytes) => {
      if (!(bytes instanceof Uint8Array) || bytes.length !== nonce.length) return fill(bytes);
      bytes.set(nonce);
      return bytes;
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
    const requested: (readonly [string, boolean])[] = [];
    const prover = new ProverClient({
      url: "https://prover.invalid",
      tee: teePolicyFromJson(decode.record(testdata(policyFile), "policy")["deployment"]),
      fetch: (input, init) => {
        const path = new URL(String(input)).pathname;
        const headers = new Headers(init?.headers);
        requested.push([
          path,
          headers.get("Zolana-Tee") === "v1" &&
            /^[0-9a-f]{64}$/u.test(headers.get("Zolana-Tee-Enc") ?? "") &&
            headers.has("Zolana-Tee-Ciphertext"),
        ]);
        return Promise.resolve(
          path === "/tee/v1/attestation" ? Response.json(live["attestation"]) : answer(),
        );
      },
    });
    try {
      await expect(prover.health()).rejects.toMatchObject(outcome);
      return requested;
    } finally {
      random.mockRestore();
      now.mockRestore();
    }
  }

  const refusal = (code: string) => () => Response.json({ code }, { status: 400 });
  const refusedWith = (code: string): Readonly<Record<string, unknown>> => ({
    code: "CLIENT_PROVER_HTTP",
    details: { method: "health", status: 400, reason: code },
  });
  const attestation = ["/tee/v1/attestation", false] as const;
  const health = ["/health", true] as const;

  it("re-attests a Nitro enclave once and resends encrypted", async () => {
    expect(
      await calls(
        "aws-nitro",
        refusal("tee_decryption_failed"),
        refusedWith("tee_decryption_failed"),
      ),
    ).toEqual([attestation, health, attestation, health]);
  });

  it.each([
    ["a dstack key loss, its key is pinned", "dstack-tdx", "tee_decryption_failed"],
    ["a malformed request", "aws-nitro", "tee_request_malformed"],
  ] as const)("does not resend %s", async (_name, platform, code) => {
    expect(await calls(platform, refusal(code), refusedWith(code))).toEqual([attestation, health]);
  });

  it("reads an unreadable refusal as no key loss", async () => {
    const broken = (): Response =>
      new Response(
        new ReadableStream({
          pull: (controller) => controller.error(new TypeError("stream broke")),
        }),
        { status: 400 },
      );
    expect(
      await calls("aws-nitro", broken, { code: expect.stringMatching(/^CLIENT_PROVER_/u) }),
    ).toEqual([attestation, health]);
  });
});

describe("AWS Nitro attestation", () => {
  const nowSecs = 1_800_000_000;
  const at = (secs: number): Date => new Date(secs * 1000);
  const pcr = (byte: number): Uint8Array => new Uint8Array(48).fill(byte);
  const nonce = new Uint8Array(32).fill(7);
  const hpkePublicKey = new Uint8Array(32).fill(9);
  const keys = (): Readonly<{ secretKey: Uint8Array; publicKey: Uint8Array }> => {
    const secretKey = p384.utils.randomSecretKey();
    return { secretKey, publicKey: p384.getPublicKey(secretKey, false) };
  };
  const root = keys();
  const intermediate = keys();
  const leaf = keys();
  const policy = teePolicyFromJson({
    platform: "aws-nitro",
    measurements: [
      { pcr0: bytesToHex(pcr(1)), pcr1: bytesToHex(pcr(2)), pcr2: bytesToHex(pcr(3)) },
    ],
    gpu: "optional",
    max_age_secs: 600,
  });

  type CertificateSpec = Readonly<{
    subject: string;
    issuer: string;
    publicKey: Uint8Array;
    signer: Uint8Array;
    ca: boolean;
    notBefore?: number;
    notAfter?: number;
    keyUsage?: KeyUsageFlags;
  }>;

  function certificate(spec: CertificateSpec): Uint8Array {
    const name = (cn: string): Name =>
      new Name([
        new RelativeDistinguishedName([
          new AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new AttributeValue({ utf8String: cn }),
          }),
        ]),
      ]);
    const ecdsaSha384 = (): AlgorithmIdentifier =>
      new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.3" });
    const tbsCertificate = new TBSCertificate({
      version: Version.v3,
      serialNumber: new Uint8Array([1]).buffer,
      signature: ecdsaSha384(),
      issuer: name(spec.issuer),
      validity: new Validity({
        notBefore: at(spec.notBefore ?? nowSecs - 3600),
        notAfter: at(spec.notAfter ?? nowSecs + 3600),
      }),
      subject: name(spec.subject),
      subjectPublicKeyInfo: new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
          algorithm: "1.2.840.10045.2.1",
          parameters: Uint8Array.of(0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22).buffer,
        }),
        subjectPublicKey: new Uint8Array(spec.publicKey).buffer,
      }),
      extensions: new Extensions([
        new Extension({
          extnID: id_ce_basicConstraints,
          critical: true,
          extnValue: new OctetString(AsnConvert.serialize(new BasicConstraints({ cA: spec.ca }))),
        }),
        ...(spec.keyUsage === undefined
          ? []
          : [
              new Extension({
                extnID: id_ce_keyUsage,
                critical: true,
                extnValue: new OctetString(AsnConvert.serialize(new KeyUsage(spec.keyUsage))),
              }),
            ]),
      ]),
    });
    const tbs = new Uint8Array(AsnConvert.serialize(tbsCertificate));
    const signature = p384.sign(tbs, spec.signer, { format: "der" });
    return new Uint8Array(
      AsnConvert.serialize(
        new Certificate({
          tbsCertificate,
          signatureAlgorithm: ecdsaSha384(),
          signatureValue: new Uint8Array(signature).buffer,
        }),
      ),
    );
  }

  const rootCertificate = certificate({
    subject: "root",
    issuer: "root",
    publicKey: root.publicKey,
    signer: root.secretKey,
    ca: true,
  });
  const withNitroRoot = (root: Uint8Array): PlatformTable => ({
    ...PLATFORMS,
    "aws-nitro": { ...PLATFORMS["aws-nitro"], anchors: [root] },
  });
  const platforms = withNitroRoot(rootCertificate);

  /** Its value already CBOR encoded. */
  type Entry = readonly [string, Uint8Array];
  type Pair = readonly [Uint8Array, Uint8Array];
  const cborMap = (pairs: readonly Pair[]): Uint8Array =>
    concatBytes(
      pairs.length < 24 ? Uint8Array.of(0xa0 | pairs.length) : Uint8Array.of(0xb8, pairs.length),
      ...pairs.flat(),
    );
  const float64 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(9);
    bytes[0] = 0xfb;
    new DataView(bytes.buffer).setFloat64(1, value);
    return bytes;
  };
  const pcrPairs = (pcr0: Uint8Array, key0: Uint8Array = encodeCbor(0), count = 4): Pair[] => [
    [key0, encodeCbor(pcr0)],
    [encodeCbor(1), encodeCbor(pcr(2))],
    [encodeCbor(2), encodeCbor(pcr(3))],
    ...Array.from({ length: count - 3 }, (_, i): Pair => [encodeCbor(i + 3), encodeCbor(pcr(0))]),
  ];
  const pcrs = (pcr0: Uint8Array, key0?: Uint8Array, count?: number): Uint8Array =>
    cborMap(pcrPairs(pcr0, key0, count));
  const extras = (count: number): Pair[] =>
    Array.from({ length: count }, (_, i): Pair => [encodeCbor(`extra${i}`), encodeCbor(i)]);
  const replaced =
    (key: string, value: Uint8Array) =>
    (entries: readonly Entry[]): readonly Entry[] =>
      entries.map((entry): Entry => (entry[0] === key ? [key, value] : entry));
  const without =
    (key: string) =>
    (entries: readonly Entry[]): readonly Entry[] =>
      entries.filter(([name]) => name !== key);

  type DocumentSpec = Partial<{
    alg: number;
    tagged: boolean;
    pcr0: Uint8Array;
    nonce: Uint8Array;
    publicKey: Uint8Array;
    userData: Uint8Array;
    leafNotBefore: number;
    leafNotAfter: number;
    leafKeyUsage: KeyUsageFlags;
    intermediateIsCa: boolean;
    leafSigner: Uint8Array;
    tamperSignature: boolean;
    payload: (entries: readonly Entry[]) => readonly Entry[];
    extra: readonly Pair[];
    cabundle: number;
    trailing: "document" | "payload";
  }>;

  function attestation(spec: DocumentSpec = {}, gpu: string | null = null): unknown {
    const intermediateCertificate = certificate({
      subject: "intermediate",
      issuer: "root",
      publicKey: intermediate.publicKey,
      signer: root.secretKey,
      ca: spec.intermediateIsCa ?? true,
    });
    const leafCertificate = certificate({
      subject: "leaf",
      issuer: "intermediate",
      publicKey: leaf.publicKey,
      signer: spec.leafSigner ?? intermediate.secretKey,
      ca: false,
      ...(spec.leafNotBefore === undefined ? {} : { notBefore: spec.leafNotBefore }),
      ...(spec.leafNotAfter === undefined ? {} : { notAfter: spec.leafNotAfter }),
      ...(spec.leafKeyUsage === undefined ? {} : { keyUsage: spec.leafKeyUsage }),
    });
    const protectedHeader = encodeCbor(new Map([[1, spec.alg ?? -35]]));
    const entries: readonly Entry[] = [
      ["module_id", encodeCbor("i-0123-enc0123")],
      ["digest", encodeCbor("SHA384")],
      ["timestamp", encodeCbor(nowSecs * 1000)],
      ["pcrs", pcrs(spec.pcr0 ?? pcr(1))],
      ["certificate", encodeCbor(leafCertificate)],
      [
        "cabundle",
        encodeCbor([
          rootCertificate,
          ...Array.from({ length: (spec.cabundle ?? 2) - 2 }, () => rootCertificate),
          intermediateCertificate,
        ]),
      ],
      ["public_key", encodeCbor(spec.publicKey ?? hpkePublicKey)],
      ["user_data", encodeCbor(spec.userData ?? reportData(nonce, hpkePublicKey, undefined))],
      ["nonce", encodeCbor(spec.nonce ?? nonce)],
    ];
    const payload = concatBytes(
      cborMap([
        ...(spec.payload?.(entries) ?? entries).map(([key, value]): Pair => [
          encodeCbor(key),
          value,
        ]),
        ...(spec.extra ?? []),
      ]),
      spec.trailing === "payload" ? Uint8Array.of(0) : new Uint8Array(),
    );
    const signed = encodeCbor(["Signature1", protectedHeader, new Uint8Array(0), payload]);
    const signature = p384.sign(signed, leaf.secretKey);
    if (spec.tamperSignature === true) signature.set([signature[0]! ^ 1]);
    const message = [protectedHeader, new Map(), payload, signature];
    const document = concatBytes(
      encodeCbor(spec.tagged === false ? message : new Tagged(18, message)),
      spec.trailing === "document" ? Uint8Array.of(0) : new Uint8Array(),
    );
    return {
      platform: "aws-nitro",
      hpke_public_key: bytesToHex(hpkePublicKey),
      gpu,
      evidence: { document: bytesToHex(document) },
    };
  }

  const verify = (attested: unknown): ReturnType<typeof verifyAttestation> =>
    verifyAttestation(attested, policy, nonce, nowSecs, platforms);

  it("embeds the AWS Nitro Enclaves root G1", () => {
    expect(PLATFORMS["aws-nitro"].anchors.map((root) => bytesToHex(sha256(root)))).toEqual([
      "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b",
    ]);
  });

  it("accepts a document an allowed image signed through the trusted chain", () => {
    for (const tagged of [true, false]) {
      const prover = verify(attestation({ tagged }));
      expect(prover).toEqual({
        platform: "aws-nitro",
        hpkePublicKey,
        imageId: pcr(1),
        gpuVerified: false,
      });
    }
  });

  const accepted: readonly (readonly [string, DocumentSpec])[] = [
    ["a leaf valid from the skew limit", { leafNotBefore: nowSecs + 300 }],
    ["a leaf valid until now", { leafNotAfter: nowSecs }],
    ["a leaf usable for signatures", { leafKeyUsage: KeyUsageFlags.digitalSignature }],
    [
      "integers and lengths in more bytes than needed",
      {
        payload: (entries) =>
          replaced(
            "module_id",
            concatBytes(Uint8Array.of(0x78, 14), utf8ToBytes("i-0123-enc0123")),
          )(replaced("pcrs", pcrs(pcr(1), Uint8Array.of(0x18, 0)))(entries)),
      },
    ],
    ["a document of 16 entries", { extra: extras(7) }],
    ["32 PCRs", { payload: replaced("pcrs", pcrs(pcr(1), undefined, 32)) }],
  ];
  it.each(accepted)("accepts %s", (_name, spec) => {
    expect(verify(attestation(spec)).imageId).toEqual(pcr(1));
  });

  it("refuses a chain to any root but the embedded one by default", () => {
    expect(check(() => verifyAttestation(attestation(), policy, nonce, nowSecs))).toBe("root");
  });

  const cases: readonly (readonly [string, DocumentSpec])[] = [
    ["signature", { tamperSignature: true }],
    ["certificate_validity", { leafNotAfter: nowSecs - 1 }],
    ["certificate_validity", { leafNotBefore: nowSecs + 301 }],
    ["certificate_chain", { leafKeyUsage: KeyUsageFlags.keyCertSign }],
    ["certificate_chain", { intermediateIsCa: false }],
    ["certificate_chain", { leafSigner: leaf.secretKey }],
    ["alg", { alg: -7 }],
    ["measurement", { pcr0: pcr(4) }],
    ["debug_enclave", { pcr0: pcr(0) }],
    ["nonce", { nonce: new Uint8Array(32) }],
    ["public_key", { publicKey: new Uint8Array(32) }],
    ["report_data", { userData: reportData(nonce, new Uint8Array(32), undefined) }],
    ["malformed_attestation", { payload: (entries) => [...entries, ["nonce", encodeCbor(nonce)]] }],
    [
      "malformed_attestation",
      {
        payload: replaced(
          "pcrs",
          cborMap([...pcrPairs(pcr(1)), [encodeCbor(0), encodeCbor(pcr(1))]]),
        ),
      },
    ],
    ["malformed_attestation", { payload: without("module_id") }],
    ["malformed_attestation", { payload: replaced("module_id", encodeCbor("")) }],
    ["malformed_attestation", { payload: without("timestamp") }],
    ["malformed_attestation", { payload: replaced("timestamp", encodeCbor(-1)) }],
    ["malformed_attestation", { payload: replaced("timestamp", encodeCbor(1.5)) }],
    ["malformed_attestation", { payload: replaced("timestamp", float64(nowSecs * 1000)) }],
    [
      "malformed_attestation",
      { payload: replaced("timestamp", concatBytes(Uint8Array.of(0xc1), encodeCbor(nowSecs))) },
    ],
    ["malformed_attestation", { payload: replaced("pcrs", pcrs(pcr(1), float64(0))) }],
    ["malformed_attestation", { payload: replaced("nonce", encodeCbor(bytesToHex(nonce))) }],
    ["malformed_attestation", { payload: replaced("module_id", encodeCbor(utf8ToBytes("i-0"))) }],
    ["malformed_attestation", { extra: extras(8) }],
    ["malformed_attestation", { payload: replaced("pcrs", pcrs(pcr(1), undefined, 33)) }],
    [
      "malformed_attestation",
      {
        payload: replaced(
          "pcrs",
          cborMap([...pcrPairs(pcr(1), undefined, 3), [encodeCbor(32), encodeCbor(pcr(0))]]),
        ),
      },
    ],
    ["malformed_attestation", { cabundle: 9 }],
    [
      "malformed_attestation",
      {
        extra: [
          [encodeCbor(utf8ToBytes("k")), encodeCbor(0)],
          [encodeCbor(utf8ToBytes("k")), encodeCbor(1)],
        ],
      },
    ],
    [
      "malformed_attestation",
      {
        extra: [
          [
            encodeCbor("deep"),
            concatBytes(
              Uint8Array.of(0x81),
              cborMap([
                [encodeCbor(1), encodeCbor(0)],
                [encodeCbor(1), encodeCbor(1)],
              ]),
            ),
          ],
        ],
      },
    ],
    ["malformed_attestation", { extra: [[encodeCbor("tagged"), encodeCbor(new Tagged(18, [0]))]] }],
    ["malformed_attestation", { trailing: "document" }],
    ["malformed_attestation", { trailing: "payload" }],
  ];
  it.each(cases)("refuses with %s", (expected, spec) => {
    expect(check(() => verify(attestation(spec)))).toBe(expected);
  });

  it("refuses a chain to another root", () => {
    const other = keys();
    const otherRoot = certificate({
      subject: "root",
      issuer: "root",
      publicKey: other.publicKey,
      signer: other.secretKey,
      ca: true,
    });
    expect(
      check(() =>
        verifyAttestation(attestation(), policy, nonce, nowSecs, withNitroRoot(otherRoot)),
      ),
    ).toBe("root");
  });

  it("refuses GPU evidence from an enclave without a GPU before its pins", () => {
    expect(check(() => verify(attestation({}, "[]")))).toBe("gpu");
    expect(check(() => verify(attestation({ pcr0: pcr(4) }, "[]")))).toBe("gpu");
  });

  it("refuses an attestation without a gpu field", () => {
    const { gpu: _gpu, ...withoutGpu } = decode.record(attestation(), "attestation");
    expect(check(() => verify(withoutGpu))).toBe("malformed_attestation");
  });

  it("refuses an attestation of a platform the policy does not name", () => {
    expect(check(() => verify(probeAttestation))).toBe("platform");
    expect(
      check(() =>
        verifyAttestation(attestation(), dstackPolicy(probePolicyJson), nonce, nowSecs, platforms),
      ),
    ).toBe("platform");
  });

  it("refuses a policy with another platform's pins", () => {
    expect(() =>
      teePolicyFromJson({
        platform: "aws-nitro",
        measurements: [],
        app_id: probePolicyJson["app_id"],
        gpu: "optional",
        max_age_secs: 600,
      }),
    ).toThrow(expect.objectContaining({ details: { field: "tee.app_id" } }));
  });

  it("refuses a Nitro policy that requires a GPU", () => {
    expect(() =>
      teePolicyFromJson({
        platform: "aws-nitro",
        measurements: [],
        gpu: "required",
        max_age_secs: 600,
      }),
    ).toThrow(expect.objectContaining({ details: { field: "tee.gpu" } }));
  });
});

describe("the shared Nitro CBOR cases", () => {
  const shared = decode.record(
    json("../../../prover/tee/testdata/nitro_cbor_cases.json"),
    "shared",
  );
  const hex = (field: string): Uint8Array => hexToBytes(decode.string(shared[field], field));
  const leafKey = hex("leaf_key");
  const nonce = hex("nonce");
  const nowSecs = Number(decode.integer(shared["now"], "now"));
  const policy = teePolicyFromJson(shared["policy"]);
  const platforms: PlatformTable = {
    ...PLATFORMS,
    "aws-nitro": { ...PLATFORMS["aws-nitro"], anchors: [hex("root")] },
  };
  const protectedHeader = encodeCbor(new Map([[1, -35]]));
  const signed = (payload: Uint8Array): Uint8Array => {
    const signature = p384.sign(
      encodeCbor(["Signature1", protectedHeader, new Uint8Array(0), payload]),
      leafKey,
    );
    return encodeCbor(new Tagged(18, [protectedHeader, new Map(), payload, signature]));
  };
  const cases = decode.list(shared["cases"], "cases").map((entry) => {
    const sharedCase = decode.record(entry, "case");
    const bytes = (field: string): Uint8Array =>
      hexToBytes(decode.string(sharedCase[field], field));
    return [
      decode.string(sharedCase["name"], "name"),
      sharedCase["payload"] === undefined ? bytes("cose") : signed(bytes("payload")),
      decode.string(sharedCase["expect"], "expect"),
    ] as const;
  });

  it.each(cases)("%s", (_name, document, expected) => {
    const verdict = check(() =>
      verifyAttestation(
        {
          platform: "aws-nitro",
          hpke_public_key: decode.string(shared["hpke_public_key"], "hpke_public_key"),
          gpu: null,
          evidence: { document: bytesToHex(document) },
        },
        policy,
        nonce,
        nowSecs,
        platforms,
      ),
    );
    expect(verdict).toBe(expected === "accept" ? undefined : "malformed_attestation");
  });
});

describe("a live AWS Nitro attestation", () => {
  const live = decode.record(
    json("../../../prover/tee/testdata/nitro_live_attestation.json"),
    "live",
  );
  const policy = teePolicyFromJson(
    decode.record(json("../../../prover/tee/testdata/nitro_live_policy.json"), "policy")[
      "deployment"
    ],
  );
  const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
  const at = Number(decode.integer(live["captured_at"], "captured_at"));

  it("passes the real AWS chain and the pinned image at capture time", () => {
    const prover = verifyAttestation(live["attestation"], policy, nonce, at);
    expect(prover.platform).toBe("aws-nitro");
    expect(prover.gpuVerified).toBe(false);
  });

  it("refuses the same document for another nonce", () => {
    expect(() => verifyAttestation(live["attestation"], policy, new Uint8Array(32), at)).toThrow(
      ClientError,
    );
  });
});
