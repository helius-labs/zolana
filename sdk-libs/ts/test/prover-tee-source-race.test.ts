import { readFileSync } from "node:fs";
import { hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, expect, it, vi } from "vitest";
import vector from "../../../test-vectors/tee_fleet_policy.json" with { type: "json" };
import { ProverClient } from "../src/client/prover/client.js";
import { TeePolicySource, type TeePolicyDocument } from "../src/client/prover/tee/source.js";
import { wireDecoder } from "../src/interface/decode.js";
import { expectedProvingKey } from "../src/interface/proving-keys.js";

const gate = vi.hoisted((): { afterEncrypt?: () => Promise<void> } => ({}));
vi.mock("../src/client/prover/tee/encryption.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client/prover/tee/encryption.js")>();
  return {
    ...actual,
    encryptRequest: async (...args: Parameters<typeof actual.encryptRequest>) => {
      const request = await actual.encryptRequest(...args);
      await gate.afterEncrypt?.();
      return request;
    },
  };
});

afterEach(() => {
  delete gate.afterEncrypt;
  vi.restoreAllMocks();
});

it("does not transmit a prepared encrypted request after observing revocation during encryption", async () => {
  const first = vector.cases[0];
  if (first === undefined) throw new Error("missing fixture");
  const decode = wireDecoder((path) => new Error(`fixture ${path}`));
  const json: unknown = JSON.parse(
    readFileSync(new URL(`../../../prover/tee/testdata/${first.fixture}`, import.meta.url), "utf8"),
  );
  const archive = decode.record(json, "attestation");
  const at = Number(decode.integer(archive["captured_at"], "time")) * 1000;
  const now = vi.spyOn(Date, "now").mockReturnValue(at);
  const nonce = hexToBytes(decode.string(archive["nonce"], "nonce"));
  vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
    bytes.set(nonce);
    return bytes;
  });
  let approved: TeePolicyDocument = { policy: vector.policy, validUntil: vector.policy.expires_at };
  const source = new TeePolicySource({
    network: "fixture",
    refreshIntervalMs: 10,
    load: async () => approved,
  });
  let quotes = 0;
  let posts = 0;
  const client = new ProverClient({
    url: "https://prover.example",
    tee: source,
    fetch: async (input) => {
      if (new URL(String(input)).pathname.endsWith("attestation")) {
        quotes++;
        return Response.json(archive["attestation"]);
      }
      posts++;
      return new Response(null, { status: 400 });
    },
  });
  await client.attest();
  gate.afterEncrypt = async () => {
    approved = {
      policy: { ...vector.policy, revision: 2, deployments: vector.policy.deployments.slice(1) },
      validUntil: vector.policy.expires_at,
    };
    now.mockReturnValue(at + 20);
    await source.resolve();
  };
  await expect(
    client.send(
      "synthetic-private-inputs",
      "sync",
      expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 }),
    ),
  ).rejects.toThrow(
    expect.objectContaining({
      code: "CLIENT_PROVER_TEE_ATTESTATION",
      details: { check: "policy_changed" },
    }),
  );
  expect(quotes).toBe(1);
  expect(posts).toBe(0);
});
