import { describe, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import { ProverClient } from "../src/client/prover/client.js";
import { DEFAULT_TEE_PROVER_ENDPOINT } from "../src/endpoint.js";
import { MAINNET_TEE_PROVER_ENDPOINT } from "../src/endpoint.js";
import { readFileSync } from "node:fs";
import { hexToBytes } from "@noble/hashes/utils.js";
import { wireDecoder } from "../src/interface/decode.js";
import { defaultTeePolicy } from "../src/client/prover/tee/policy.js";

/** Records every request and fails it, so `attest()` shows where it would go. */
function recordingFetch(): { fetch: typeof globalThis.fetch; urls: string[] } {
  const urls: string[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>((input) => {
    urls.push(String(input instanceof Request ? input.url : input));
    return Promise.resolve(new Response(null, { status: 404 }));
  });
  return { fetch, urls };
}

async function attestationRequest(
  prover: ProverClient,
  urls: string[],
): Promise<string | undefined> {
  await prover.attest().catch(() => undefined);
  return urls.find((url) => url.includes("/tee/v1/attestation"));
}

describe("default TEE", () => {
  it("selects the mainnet policy for explicit and inherited endpoints before sending encrypted requests", async () => {
    const decode = wireDecoder((path) => new Error(`fixture ${path}`));
    const value: unknown = JSON.parse(
      readFileSync(
        new URL("../../../prover/tee/testdata/mainnet_tee_2_attestation.json", import.meta.url),
        "utf8",
      ),
    );
    const fixture = decode.record(value, "fixture");
    const nonce = hexToBytes(decode.string(fixture["nonce"], "nonce"));
    const at = Number(decode.integer(fixture["captured_at"], "captured_at"));
    const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((bytes) => {
      if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce buffer");
      bytes.set(nonce);
      return bytes;
    });
    try {
      for (const inherited of [false, true]) {
        const sent: string[] = [];
        const fetch: typeof globalThis.fetch = async (input, init) => {
          const url = new URL(String(input));
          sent.push(url.pathname);
          expect(url.origin).toBe(MAINNET_TEE_PROVER_ENDPOINT);
          expect(url.searchParams.has("api-key")).toBe(false);
          if (url.pathname === "/tee/v1/attestation") return Response.json(fixture["attestation"]);
          expect(new Headers(init?.headers).get("Zolana-Tee")).toBe("v1");
          return new Response(null, { status: 404 });
        };
        const client = new ZolanaClient({
          solanaRpcUrl: "https://mainnet.helius-rpc.com/?api-key=rpc-secret",
          ...(inherited ? {} : { proverUrl: MAINNET_TEE_PROVER_ENDPOINT }),
          fetch,
        });
        expect(client.proofDataSource).toBe("prover");
        await expect(client.attestProver()).resolves.toMatchObject({ platform: "aws-nitro" });
        const prover = new ProverClient({ url: MAINNET_TEE_PROVER_ENDPOINT, fetch });
        await expect(prover.checkProvingKeys()).rejects.toThrow();
        expect(sent).toEqual(["/tee/v1/attestation", "/tee/v1/attestation", "/proving-keys"]);
        sent.length = 0;
        const overridden = new ProverClient({
          url: MAINNET_TEE_PROVER_ENDPOINT,
          tee: defaultTeePolicy(),
          fetch,
        });
        await expect(overridden.checkProvingKeys()).rejects.toMatchObject({
          code: "CLIENT_PROVER_TEE_ATTESTATION",
          details: expect.objectContaining({ check: "measurement" }),
        });
        expect(sent).toEqual(["/tee/v1/attestation"]);
      }
    } finally {
      now.mockRestore();
      random.mockRestore();
    }
  });
  it("attests a remote prover to the pinned deployment by default", async () => {
    const remote = recordingFetch();
    const prover = new ProverClient({
      url: "https://prover.example",
      fetch: remote.fetch,
    });
    expect(await attestationRequest(prover, remote.urls)).toMatch(
      /^https:\/\/prover\.example\/tee\/v1\/attestation\?nonce=[0-9a-f]{64}$/u,
    );
  });

  it("rejects a runtime plaintext opt out", () => {
    expect(() =>
      Reflect.construct(ProverClient, [{ url: "https://prover.example", tee: false }]),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "tee.platform" },
      }),
    );
  });

  it("permits plaintext only for loopback development", async () => {
    for (const url of ["http://127.0.0.1:3001", "http://localhost:3001"]) {
      const { fetch, urls } = recordingFetch();
      await expect(new ProverClient({ url, fetch }).attest()).rejects.toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "tee" },
      });
      expect(urls).toEqual([]);
    }
  });

  it("keeps gateway keys and raw query encoding on prefixed attestation calls", async () => {
    const { fetch, urls } = recordingFetch();
    const endpoint = new URL(
      "https://prover.example/base/?flag&x=a%20b&y=~&nonce=stale&api-key=k%2B1",
    );
    const original = endpoint.href;
    const prover = new ProverClient({ url: endpoint, fetch });
    await prover.attest().catch(() => undefined);
    expect(endpoint.href).toBe(original);
    expect(urls.find((url) => url.includes("/tee/v1/attestation"))).toMatch(
      /^https:\/\/prover\.example\/base\/tee\/v1\/attestation\?flag&x=a%20b&y=~&api-key=k%2B1&nonce=[0-9a-f]{64}$/u,
    );
  });

  it("has an indexed route on the default TEE prover but not the Helius gateway", () => {
    for (const [url, indexed] of [
      ["https://prover.example", true],
      ["http://127.0.0.1:3001", true],
      ["https://devnet.helius-rpc.com/v1/zolana?api-key=k", false],
      [DEFAULT_TEE_PROVER_ENDPOINT, true],
    ] as const) {
      expect(new ProverClient({ url, fetch: vi.fn() }).hasIndexedRoute, url).toBe(indexed);
    }
  });

  it("proves through the default TEE prover with server proof data on Helius devnet", async () => {
    const { fetch, urls } = recordingFetch();
    const client = new ZolanaClient({
      solanaRpcUrl: "https://devnet.helius-rpc.com/?api-key=k",
      fetch,
    });
    expect(client.proofDataSource).toBe("prover");
    await client.attestProver().catch(() => undefined);
    expect(urls.find((url) => url.includes("/tee/v1/attestation"))).toMatch(
      new RegExp(
        `^${DEFAULT_TEE_PROVER_ENDPOINT.replace(/[.]/gu, "\\.")}/tee/v1/attestation\\?nonce=`,
        "u",
      ),
    );
    for (const proofDataSource of ["client", "prover"] as const) {
      expect(
        new ZolanaClient({
          solanaRpcUrl: "https://devnet.helius-rpc.com/?api-key=k",
          proofDataSource,
        }).proofDataSource,
      ).toBe(proofDataSource);
    }
  });
});
