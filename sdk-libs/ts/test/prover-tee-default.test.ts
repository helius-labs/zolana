import { readFileSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import { ProverClient } from "../src/client/prover/client.js";
import { wireDecoder } from "../src/interface/decode.js";
import { readTeePolicy } from "./helpers/tee-policy.js";

describe("caller-supplied prover policy", () => {
  it("refuses every remote call without a policy before reaching HTTP", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    for (const url of [
      "https://prover.example",
      "https://mainnet.helius-rpc.com/v1/zolana?api-key=k",
    ]) {
      const prover = new ProverClient({ url, fetch });
      for (const call of [
        () => prover.attest(),
        () => prover.checkProvingKeys(),
        () => prover.health(),
      ]) {
        await expect(call()).rejects.toMatchObject({
          code: "CLIENT_INVALID_CONFIG",
          details: { field: "tee" },
        });
      }
      const client = new ZolanaClient({ solanaRpcUrl: url, fetch });
      await expect(client.attestProver()).rejects.toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "tee" },
      });
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it("uses the supplied policy independently of direct, unified, or proxy URLs", async () => {
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
      for (const base of [
        "https://prover.example",
        "https://mainnet.helius-rpc.com/v1/zolana",
        "https://api.example/prover",
      ]) {
        const sent: string[] = [];
        const fetch: typeof globalThis.fetch = async (input, init) => {
          const url = new URL(String(input));
          sent.push(url.pathname);
          expect(url.origin).toBe(new URL(base).origin);
          expect(url.searchParams.get("api-key")).toBe("k");
          if (url.pathname.endsWith("/tee/v1/attestation"))
            return Response.json(fixture["attestation"]);
          const headers = new Headers(init?.headers);
          expect(headers.get("Zolana-Tee")).toBe("v1");
          expect(headers.get("Zolana-Tee-Ciphertext")).toMatch(/^[0-9a-f]+$/u);
          return new Response(null, { status: 404 });
        };
        const endpoint = `${base}?api-key=k`;
        const policy = readTeePolicy(
          new URL("../../../prover/tee/deployments/mainnet-v0.6.0-alpha.json", import.meta.url),
        );
        const client = new ZolanaClient({ solanaRpcUrl: endpoint, proverTee: policy, fetch });
        await expect(client.attestProver()).resolves.toMatchObject({ platform: "aws-nitro" });
        const prover = new ProverClient({ url: endpoint, tee: policy, fetch });
        await expect(prover.checkProvingKeys()).rejects.toThrow();
        const path = new URL(base).pathname.replace(/\/$/u, "");
        expect(sent).toEqual([
          `${path}/tee/v1/attestation`,
          `${path}/tee/v1/attestation`,
          `${path}/proving-keys`,
        ]);
        sent.length = 0;
        const wrong = new ProverClient({
          url: endpoint,
          tee: readTeePolicy(
            new URL("../../../prover/tee/deployments/devnet-e-v0.6.0-alpha.json", import.meta.url),
          ),
          fetch,
        });
        await expect(wrong.checkProvingKeys()).rejects.toMatchObject({
          code: "CLIENT_PROVER_TEE_ATTESTATION",
          details: expect.objectContaining({ check: "measurement" }),
        });
        expect(sent).toEqual([`${path}/tee/v1/attestation`]);
      }
    } finally {
      now.mockRestore();
      random.mockRestore();
    }
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
      const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json({}));
      const prover = new ProverClient({ url, fetch });
      await expect(prover.attest()).rejects.toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "tee" },
      });
      expect(fetch).not.toHaveBeenCalled();
    }
  });
});
