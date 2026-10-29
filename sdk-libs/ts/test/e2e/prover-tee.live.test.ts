import { readFileSync, writeFileSync } from "node:fs";

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";

import {
  teePolicyFromJson,
  ZolanaClient,
  compressProof,
  type CircuitUtxo,
  type ProverInputs,
  type TransferInput,
  type TransferOutput,
} from "../../src/client/index.js";
import { asField } from "../../src/client/prover/assembly.js";
import { wireDecoder } from "../../src/interface/decode.js";

// A committed, valid circuit witness, independent of any chain or wallet.
const fixture: unknown = JSON.parse(
  readFileSync(
    new URL("../../../../prover/server/prover/request/testdata/transfer-2x2.json", import.meta.url),
    "utf8",
  ),
);
const decode = wireDecoder((path) => new Error(`Invalid proof fixture: ${path}`));
const record = decode.record(fixture, "fixture");

function field(
  source: Readonly<Record<string, unknown>>,
  name: string,
): ReturnType<typeof asField> {
  const encoded = decode.string(source[name], name);
  if (!/^0x[0-9a-f]{64}$/u.test(encoded)) throw new Error(`Invalid fixture field: ${name}`);
  return asField(BigInt(encoded));
}

function fields(
  source: Readonly<Record<string, unknown>>,
  name: string,
): ReturnType<typeof asField>[] {
  return decode.list(source[name], name).map((value) => field({ value }, "value"));
}

function utxo(value: unknown): CircuitUtxo {
  const item = decode.record(value, "utxo");
  return {
    domain: field(item, "domain"),
    owner: field(item, "owner"),
    asset: field(item, "asset"),
    amount: field(item, "amount"),
    blinding: field(item, "blinding"),
    dataHash: field(item, "dataHash"),
    ringDataHash: field(item, "ringDataHash"),
    ringProgramId: field(item, "ringProgramId"),
  };
}

function input(value: unknown): TransferInput {
  const item = decode.record(value, "input");
  return {
    circuit: utxo(item["utxo"]),
    isDummy: field(item, "isDummy"),
    statePathElements: fields(item, "statePathElements"),
    statePathIndex: field(item, "statePathIndex"),
    nullifierLowValue: field(item, "nullifierLowValue"),
    nullifierNextValue: field(item, "nullifierNextValue"),
    nullifierLowPathElements: fields(item, "nullifierLowPathElements"),
    nullifierLowPathIndex: field(item, "nullifierLowPathIndex"),
    treeSlot: field(item, "treeSlot"),
    nullifier: field(item, "nullifier"),
    ownerPublicKeyHash: field(item, "ownerPkHash"),
    nullifierSecret: field(item, "nullifierSecret"),
  };
}

function output(value: unknown): TransferOutput {
  const item = decode.record(value, "output");
  return {
    circuit: utxo(item["utxo"]),
    isDummy: field(item, "isDummy"),
    hash: field(item, "hash"),
    ownerPublicKeyHash: field(item, "ownerPkHash"),
    nullifierPublicKey: field(item, "nullifierPk"),
  };
}

function inputs(): ProverInputs {
  return {
    circuit: "transfer",
    payload: {
      inputs: decode.list(record["inputs"], "inputs").map(input),
      outputs: decode.list(record["outputs"], "outputs").map(output),
      treeSlots: decode.list(record["treeSlots"], "treeSlots").map((value) => {
        const item = decode.record(value, "treeSlot");
        return {
          id: field(item, "id"),
          utxoRoot: field(item, "utxoRoot"),
          nullifierRoot: field(item, "nullifierRoot"),
        };
      }),
      outputTreeId: field(record, "outputTreeId"),
      externalDataHash: field(record, "externalDataHash"),
      privateTxHash: field(record, "privateTxHash"),
      blindingSeed: field(record, "blindingSeed"),
      publicAssets: fields(record, "publicAssets"),
      publicAmounts: fields(record, "publicAmounts"),
      ringProgramId: field(record, "ringProgramId"),
      signerPublicKeyHashes: fields(record, "signerPkHashes"),
      inputFlags: field(record, "inputFlags"),
      publishedOutputOwnerPublicKeyHashes: fields(record, "publishedOutputOwnerPkHashes"),
      cacheTreeId: field(record, "cacheTreeId"),
      cacheReadHashChain: field(record, "cacheReadHashChain"),
      cacheReadHashes: fields(record, "cacheReadHashes"),
      cacheIsCached: fields(record, "cacheIsCached"),
      cacheReadIndex: fields(record, "cacheReadIndex"),
      publicInputHash: field(record, "publicInputHash"),
    },
  };
}

describe("configured TEE prover", () => {
  it("attests and returns an encrypted valid proof with a caller-supplied URL and policy", async () => {
    const endpoint = process.env["ZOLANA_TEE_PROVER_URL"];
    const policyPath = process.env["ZOLANA_TEE_PROVER_POLICY"];
    if (endpoint === undefined || policyPath === undefined)
      throw new Error("Supply ZOLANA_TEE_PROVER_URL and ZOLANA_TEE_PROVER_POLICY");
    const policyJson: unknown = JSON.parse(readFileSync(policyPath, "utf8"));
    const policy = teePolicyFromJson(policyJson);
    let encryptedProofCalls = 0;
    const observedFetch: typeof globalThis.fetch = async (resource, init) => {
      const url = new URL(resource instanceof Request ? resource.url : resource);
      expect(url.origin).toBe(new URL(endpoint).origin);
      if (url.pathname.startsWith("/prove/")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("Zolana-Tee")).toBe("v1");
        expect(headers.get("Zolana-Tee-Enc")).toMatch(/^[0-9a-f]{64}$/u);
        expect(headers.get("content-type")).toBe("application/octet-stream");
        expect(init?.body).toBeInstanceOf(Uint8Array);
        encryptedProofCalls++;
      }
      const response = await globalThis.fetch(resource, init);
      if (url.pathname.startsWith("/prove/")) {
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
    const proof = await client.proofService.prove(inputs(), { timeoutMs: 180_000 });
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
          publicInputHash: decode.string(record["publicInputHash"], "publicInputHash"),
        }),
      );
    }
  }, 240_000);
});
