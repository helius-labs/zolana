import { readFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import { ClientError } from "../src/client/error.js";
import { ProverClient } from "../src/client/prover/client.js";
import { openResponse, sealRequest } from "../src/client/prover/tee/seal.js";
import { sealedInit, type ProverCall } from "../src/client/prover/tee/session.js";
import { composeSignal } from "../src/client/internal.js";
import { PINNED_TEE_POLICY_FILE } from "../src/client/prover/tee/pinned.js";
import {
  pinnedTeePolicy,
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
    expect(PINNED_TEE_POLICY_FILE).toEqual(json("../../client/src/prover/tee/policy.json"));
  });

  it("accepts the live attestation of the deployment this release pins", () => {
    const live = decode.record(json("../../../prover/tee/testdata/live_attestation.json"), "live");
    const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
    const at = Number(decode.integer(live["captured_at"], "captured_at"));
    const prover = verifyAttestation(live["attestation"], pinnedTeePolicy(), nonce, at);
    expect(prover.gpuVerified).toBe(true);
    expect(
      check(() =>
        verifyAttestation(live["attestation"], pinnedTeePolicy(), new Uint8Array(32), at),
      ),
    ).toBe("report_data");
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

describe("sealing", () => {
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
    const aad = utf8ToBytes(`${vector("method")} ${vector("request_uri")}`);
    const plaintext = new Uint8Array(await context.open(hexToBytes(vector("ciphertext")), aad));
    expect(new TextDecoder().decode(plaintext)).toBe(vector("plaintext"));
    const responseKey = new Uint8Array(
      await context.export(utf8ToBytes("zolana/prover-tee/v1/response"), 32),
    );
    expect(bytesToHex(responseKey)).toBe(vector("response_key"));
    const opened = openResponse(responseKey, hexToBytes(vector("sealed_response")));
    expect(opened.status).toBe(Number(decode.integer(vectors["response_status"], "status")));
    expect(new TextDecoder().decode(opened.body)).toBe(vector("response_body"));
  });

  it("opens only on the route it was sealed for", async () => {
    const sealed = await sealRequest(
      hexToBytes(vector("hpke_public_key")),
      "GET",
      "/prove/merge/status?jobId=a",
      new Uint8Array(),
    );
    const opensOn = async (uri: string): Promise<boolean> => {
      const context = await recipient(hexToBytes(sealed.enc));
      return context.open(sealed.body, utf8ToBytes(`GET ${uri}`)).then(
        () => true,
        () => false,
      );
    };
    expect(await opensOn("/prove/merge/status?jobId=a")).toBe(true);
    expect(await opensOn("/prove/merge/status?jobId=b")).toBe(false);
  });
});

describe("sealed request shape", () => {
  const call = (method: "GET" | "POST"): ProverCall => ({
    fetch: globalThis.fetch,
    attestationUrl: new URL("https://prover.example/tee/v1/attestation"),
    url: new URL("https://prover.example/prove/merge/status?jobId=a"),
    method,
    headers: { "X-Sync": "true" },
    signal: composeSignal(undefined, "test"),
    maxResponseBytes: 1024,
  });
  const sealed = {
    enc: "ab",
    body: new Uint8Array([1, 2]),
    open: () => ({ status: 200, body: new Uint8Array() }),
  };

  it("puts a GET's sealed bytes in a header, fetch refuses a GET body", () => {
    const init = sealedInit(call("GET"), sealed);
    expect(init.body).toBeUndefined();
    expect(init.headers).toMatchObject({
      "Zolana-Tee": "v1",
      "Zolana-Tee-Enc": "ab",
      "Zolana-Tee-Seal": "0102",
    });
  });

  it("keeps a POST's sealed bytes in the body", () => {
    const init = sealedInit(call("POST"), sealed);
    expect(init.body).toEqual(new Uint8Array([1, 2]));
    expect(init.headers).not.toHaveProperty("Zolana-Tee-Seal");
  });
});

describe("a TEE prover client", () => {
  it.each([
    ["no endpoint", () => new Response("404 page not found", { status: 404 })],
    ["junk evidence", () => Response.json({ quote: "00" })],
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
