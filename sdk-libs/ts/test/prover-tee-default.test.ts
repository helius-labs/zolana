import { describe, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import { ProverClient } from "../src/client/prover/client.js";
import { DEFAULT_TEE_PROVER_ENDPOINT } from "../src/endpoint.js";

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

  it("has no indexed route on the Helius gateway or the default TEE prover", () => {
    for (const [url, indexed] of [
      ["https://prover.example", true],
      ["http://127.0.0.1:3001", true],
      ["https://devnet.helius-rpc.com/v1/zolana?api-key=k", false],
      [DEFAULT_TEE_PROVER_ENDPOINT, false],
    ] as const) {
      expect(new ProverClient({ url, fetch: vi.fn() }).hasIndexedRoute, url).toBe(indexed);
    }
  });

  it("proves through the default TEE prover with client proof data on Helius devnet", async () => {
    const { fetch, urls } = recordingFetch();
    const client = new ZolanaClient({
      solanaRpcUrl: "https://devnet.helius-rpc.com/?api-key=k",
      fetch,
    });
    expect(client.proofDataSource).toBe("client");
    await client.attestProver().catch(() => undefined);
    expect(urls.find((url) => url.includes("/tee/v1/attestation"))).toMatch(
      new RegExp(
        `^${DEFAULT_TEE_PROVER_ENDPOINT.replace(/[.]/gu, "\\.")}/tee/v1/attestation\\?nonce=`,
        "u",
      ),
    );
    expect(
      () =>
        new ZolanaClient({
          solanaRpcUrl: "https://devnet.helius-rpc.com/?api-key=k",
          proofDataSource: "prover",
        }),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "proofDataSource" },
      }),
    );
  });
});
