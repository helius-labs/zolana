import { readFileSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";
import { expect, it, vi } from "vitest";

import { ProverClient } from "../src/client/prover/client.js";
import { teePolicyFromJson } from "../src/client/prover/tee/policy.js";
import { wireDecoder } from "../src/interface/decode.js";

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

it("seals the route below a prover URL that a proxy serves under its own path", async () => {
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
