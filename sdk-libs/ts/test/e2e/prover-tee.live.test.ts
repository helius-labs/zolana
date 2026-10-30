import { readFileSync, writeFileSync } from "node:fs";

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import { teePolicyFromJson, ZolanaClient, compressProof } from "../../src/client/index.js";
import {
  transferFixtureInputs,
  transferFixturePublicInputHash,
} from "../helpers/transfer-fixture.js";

describe("configured TEE prover", () => {
  it("attests and returns an encrypted valid proof with a caller-supplied URL and policy", async () => {
    const endpoint = process.env["ZOLANA_TEE_PROVER_URL"];
    const policyPath = process.env["ZOLANA_TEE_PROVER_POLICY"];
    if (endpoint === undefined || policyPath === undefined)
      throw new Error("Supply ZOLANA_TEE_PROVER_URL and ZOLANA_TEE_PROVER_POLICY");
    const policyJson: unknown = JSON.parse(readFileSync(policyPath, "utf8"));
    const policy = teePolicyFromJson(policyJson);
    const proverUrl = new URL(endpoint);
    const proofPathPrefix = `${proverUrl.pathname.replace(/\/+$/u, "")}/prove/`;
    let encryptedProofCalls = 0;
    const observedFetch: typeof globalThis.fetch = async (resource, init) => {
      const url = new URL(resource instanceof Request ? resource.url : resource);
      expect(url.origin).toBe(proverUrl.origin);
      if (url.pathname.startsWith(proofPathPrefix)) {
        const headers = new Headers(init?.headers);
        expect(headers.get("Zolana-Tee")).toBe("v1");
        expect(headers.get("Zolana-Tee-Enc")).toMatch(/^[0-9a-f]{64}$/u);
        expect(headers.get("content-type")).toBe("application/octet-stream");
        expect(init?.body).toBeInstanceOf(Uint8Array);
        encryptedProofCalls++;
      }
      const response = await globalThis.fetch(resource, init);
      if (url.pathname.startsWith(proofPathPrefix)) {
        expect(response.headers.get("content-type")).toContain("application/octet-stream");
      }
      return response;
    };
    // The supplied policy still requires nonce, certificate, measurements,
    // HPKE pin and encrypted-response authentication.
    const client = new ZolanaClient({
      proverUrl: endpoint,
      proverTee: policy,
      fetch: observedFetch,
    });
    const attested = await client.attestProver({ timeoutMs: 120_000 });
    expect(attested.platform).toBe("aws-nitro");
    expect(bytesToHex(attested.hpkePublicKey)).toBe(policy.hpkePublicKey);
    const proof = await client.proofService.prove(transferFixtureInputs(), { timeoutMs: 180_000 });
    // prove() checks the returned proving-key digest; compression additionally
    // validates the proof's G1/G2 points before producing on-chain proof bytes.
    const compressed = compressProof(proof);
    expect([compressed.a.length, compressed.b.length, compressed.c.length]).toEqual([32, 128, 32]);
    expect(compressed.a.some((value) => value !== 0)).toBe(true);
    expect(compressed.b.some((value) => value !== 0)).toBe(true);
    expect(compressed.c.some((value) => value !== 0)).toBe(true);
    expect(encryptedProofCalls).toBeGreaterThan(0);
    // Optional public proof export lets the Rust verifier check this exact
    // response against the shared fixture's public input, without its witness.
    const proofOutput = process.env["ZOLANA_TEE_PROOF_OUTPUT"];
    if (proofOutput !== undefined) {
      writeFileSync(
        proofOutput,
        JSON.stringify({
          a: bytesToHex(proof.a),
          b: bytesToHex(proof.b),
          c: bytesToHex(proof.c),
          publicInputHash: transferFixturePublicInputHash(),
        }),
      );
    }
  }, 240_000);
});
