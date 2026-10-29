import { readFileSync } from "node:fs";
import gatewayContract from "../../../test-vectors/prover_gateway_routes.json" with { type: "json" };

import { hexToBytes } from "@noble/hashes/utils.js";
import { expect, it, vi } from "vitest";

import { ProverClient } from "../src/client/prover/client.js";
import { teePolicyFromJson } from "../src/client/prover/tee/policy.js";
import { wireDecoder } from "../src/interface/decode.js";
import { expectedProvingKey } from "../src/interface/proving-keys.js";
import { readTeePolicy } from "./helpers/tee-policy.js";

// Records the AAD of every request the client seals, the live enclave's key
// being the only one the attestation fixture admits.
const sealed = vi.hoisted((): string[] => []);
vi.mock("../src/client/prover/tee/encryption.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client/prover/tee/encryption.js")>();
  return {
    ...actual,
    encryptRequest: (...args: Parameters<typeof actual.encryptRequest>) => {
      sealed.push(actual.requestAad(args[1], args[2]));
      return actual.encryptRequest(...args);
    },
  };
});

const json = (path: string): unknown =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const decode = wireDecoder((path) => new Error(`fixture ${path}`));

it.each(
  gatewayContract.base_urls.flatMap(
    (base) =>
      [
        { base, route: "sync", path: gatewayContract.routes.complete },
        { base, route: "indexed", path: gatewayContract.routes.indexed },
      ] as const,
  ),
)("attests and encrypts the $route proof route at $base", async ({ base, route, path }) => {
  const live = decode.record(
    json("../../../prover/tee/testdata/mainnet_tee_2_attestation.json"),
    "live",
  );
  const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
  const at = Number(decode.integer(live["captured_at"], "captured_at"));
  const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce buffer");
    bytes.set(nonce);
    return bytes;
  });
  const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
  const sent: string[] = [];
  sealed.length = 0;
  try {
    const prover = new ProverClient({
      url: `${base}&flag&tenant=a%20b`,
      tee: readTeePolicy(
        new URL("../../../prover/tee/deployments/mainnet-v0.6.0-alpha.json", import.meta.url),
      ),
      fetch: async (input, init) => {
        const url = new URL(String(input));
        sent.push(url.pathname);
        expect(url.searchParams.get("api-key")).toBe("fixture-key");
        if (url.pathname === gatewayContract.routes.attestation) {
          expect(url.searchParams.get("nonce")).toBe(decode.string(live["nonce"], "nonce"));
          return Response.json(live["attestation"]);
        }
        const headers = new Headers(init?.headers);
        expect(headers.get("Zolana-Tee")).toBe("v1");
        expect(headers.get("Zolana-Tee-Enc")).toMatch(/^[0-9a-f]{64}$/u);
        expect(headers.get("Content-Type")).toBe("application/octet-stream");
        expect(init?.body).toBeInstanceOf(Uint8Array);
        return new Response(null, { status: 404 });
      },
    });
    const key = expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 });
    await expect(prover.send('{"private":"synthetic"}', route, key)).rejects.toThrow();
    expect(sent).toEqual([gatewayContract.routes.attestation, path]);
    expect(sealed).toEqual([`POST ${path.replace("/v1/zolana", "")}?flag&tenant=a%20b`]);
  } finally {
    random.mockRestore();
    now.mockRestore();
  }
});

it("seals the route below a prover URL that a proxy serves under its own path", async () => {
  sealed.length = 0;
  const live = decode.record(json("../../../prover/tee/testdata/live_attestation.json"), "live");
  const policy = decode.record(json("../../../prover/tee/testdata/live_policy.json"), "policy");
  const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
  const at = Number(decode.integer(live["captured_at"], "captured_at"));
  const random = vi.spyOn(globalThis.crypto, "getRandomValues");
  random.mockImplementationOnce((bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce buffer");
    bytes.set(nonce);
    return bytes;
  });
  const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
  const sent: string[] = [];
  try {
    const prover = new ProverClient({
      url: "https://app.example/api/tvc/zolana/prover/?api-key=k",
      tee: teePolicyFromJson(policy["deployment"]),
      fetch: (input, init) => {
        if (init?.method === undefined) return Promise.resolve(Response.json(live["attestation"]));
        sent.push(new URL(String(input)).pathname);
        return Promise.resolve(new Response(null, { status: 404 }));
      },
    });
    await expect(prover.checkProvingKeys()).rejects.toThrow();
    expect(sent).toEqual(["/api/tvc/zolana/prover/proving-keys"]);
    expect(sealed).toEqual(["GET /proving-keys"]);
  } finally {
    random.mockRestore();
    now.mockRestore();
  }
});
