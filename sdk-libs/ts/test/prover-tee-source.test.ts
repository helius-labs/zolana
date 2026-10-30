import { readFileSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import vector from "../../../test-vectors/tee_fleet_policy.json" with { type: "json" };
import { ProverClient } from "../src/client/prover/client.js";
import {
  TeePolicySource,
  type TeePolicyDocument,
  type TeePolicySourceConfig,
} from "../src/client/prover/tee/source.js";
import { wireDecoder } from "../src/interface/decode.js";
import { expectedProvingKey } from "../src/interface/proving-keys.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const denied = expect.objectContaining({ code: "CLIENT_PROVER_TEE_ATTESTATION" });
const invalid = expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" });

function document(revision = 1, validUntil = vector.policy.expires_at): TeePolicyDocument {
  return { policy: { ...vector.policy, revision }, validUntil };
}

function deferred<T>() {
  let complete: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    complete = resolve;
  });
  return {
    promise,
    resolve(value: T) {
      if (complete === undefined) throw new Error("missing resolver");
      complete(value);
    },
  };
}

function archive() {
  const entry = vector.cases[0];
  if (entry === undefined) throw new Error("missing fixture");
  const json: unknown = JSON.parse(
    readFileSync(new URL(`../../../prover/tee/testdata/${entry.fixture}`, import.meta.url), "utf8"),
  );
  const record = decode.record(json, "attestation");
  return {
    at: Number(decode.integer(record["captured_at"], "time")),
    nonce: hexToBytes(decode.string(record["nonce"], "nonce")),
    attestation: record["attestation"],
  };
}

function fixNonce(nonce: Uint8Array) {
  vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
    bytes.set(nonce);
    return bytes;
  });
}

afterEach(() => vi.restoreAllMocks());

describe("approved TEE policy source", () => {
  it("shares one update and caches it only within its freshness interval", async () => {
    const pending = deferred<TeePolicyDocument>();
    const load = vi.fn(async () => pending.promise);
    const source = new TeePolicySource({ network: "fixture", load });
    const calls = [source.resolve(), source.resolve(), source.resolve()];
    pending.resolve(document());
    const policies = await Promise.all(calls);
    expect(load).toHaveBeenCalledTimes(1);
    expect(policies[0]).toBe(policies[1]);
    expect(await source.resolve()).toBe(policies[0]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("does not let a cancelled update's late result replace a newer accepted policy", async () => {
    const old = deferred<TeePolicyDocument>();
    const load = vi
      .fn<TeePolicySourceConfig["load"]>()
      .mockImplementationOnce(async () => old.promise)
      .mockImplementationOnce(async () => document(2));
    const source = new TeePolicySource({ network: "fixture", load });
    const controller = new AbortController();
    const owner = source.resolve({ signal: controller.signal });
    const follower = source.resolve();
    const cancelled = expect(owner).rejects.toThrow(
      expect.objectContaining({ code: "CLIENT_ABORTED" }),
    );
    controller.abort();
    await cancelled;
    expect((await follower).revision).toBe(2);
    old.resolve(document(1));
    await old.promise;
    expect((await source.resolve()).revision).toBe(2);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("rejects rollback and same-revision substitutions without falling back to cached policy", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    const load = vi.fn(async () => document(2));
    const source = new TeePolicySource({ network: "fixture", load, refreshIntervalMs: 10 });
    await source.resolve();
    now.mockReturnValue(1_800_000_000_020);
    load.mockResolvedValue(document(1));
    await expect(source.resolve()).rejects.toThrow(denied);
    await expect(source.resolve()).rejects.toThrow(denied);
    load.mockResolvedValue({
      ...document(2),
      policy: { ...vector.policy, revision: 2, expires_at: vector.policy.expires_at + 1 },
    });
    await expect(source.resolve()).rejects.toThrow(denied);
  });

  it("caps cached policy validity by the loader's authentication expiry", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    const load = vi.fn(async () => document(1, 1_800_000_001));
    const source = new TeePolicySource({ network: "fixture", load });
    expect((await source.resolve()).expiresAt).toBe(1_800_000_001);
    now.mockReturnValue(1_800_000_001_000);
    await expect(source.resolve()).rejects.toThrow(denied);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("rejects invalid provider configuration and malformed loader results", async () => {
    const load = async () => document();
    for (const refreshIntervalMs of [0, -1, 300_001, NaN]) {
      expect(() => new TeePolicySource({ network: "fixture", load, refreshIntervalMs })).toThrow(
        invalid,
      );
    }
    const source = new TeePolicySource({ network: "mainnet", load });
    await expect(source.resolve()).rejects.toThrow(invalid);
    for (const validUntil of [0, -1, NaN, Infinity]) {
      await expect(
        new TeePolicySource({
          network: "fixture",
          load: async () => document(1, validUntil),
        }).resolve(),
      ).rejects.toThrow(denied);
    }
  });

  it("fails before prover HTTP if policy resolution fails", async () => {
    const source = new TeePolicySource({
      network: "fixture",
      load: async () => {
        throw new Error("untrusted body / secret URL");
      },
    });
    const fetch = vi.fn(async () => new Response(null, { status: 200 }));
    const client = new ProverClient({ url: "https://prover.example", tee: source, fetch });
    await expect(client.attest()).rejects.toThrow(denied);
    await expect(client.checkProvingKeys()).rejects.toThrow(denied);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("preserves the caller's timeout code while waiting for policy metadata", async () => {
    const pending = deferred<TeePolicyDocument>();
    const source = new TeePolicySource({ network: "fixture", load: async () => pending.promise });
    const fetch = vi.fn(async () => new Response(null, { status: 200 }));
    const client = new ProverClient({ url: "https://prover.example", tee: source, fetch });
    await expect(client.attest({ timeoutMs: 20 })).rejects.toThrow(
      expect.objectContaining({ code: "CLIENT_TIMEOUT" }),
    );
    expect(fetch).not.toHaveBeenCalled();
    pending.resolve(document());
    await pending.promise;
  });

  it("invalidates a cached recipient when an update removes its approved generation", async () => {
    const answer = archive();
    const now = vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    fixNonce(answer.nonce);
    const load = vi.fn(async () => document());
    const source = new TeePolicySource({ network: "fixture", load, refreshIntervalMs: 10 });
    let quotes = 0;
    let proofs = 0;
    const client = new ProverClient({
      url: "https://prover.example",
      tee: source,
      fetch: async (input) => {
        if (new URL(String(input)).pathname.endsWith("attestation")) {
          quotes++;
          return Response.json(answer.attestation);
        }
        proofs++;
        return new Response(null, { status: 400 });
      },
    });
    await client.attest();
    load.mockResolvedValue({
      policy: { ...vector.policy, revision: 2, deployments: vector.policy.deployments.slice(1) },
      validUntil: vector.policy.expires_at,
    });
    now.mockReturnValue(answer.at * 1000 + 20);
    fixNonce(answer.nonce);
    await expect(
      client.send(
        "synthetic-private-inputs",
        "sync",
        expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 }),
      ),
    ).rejects.toThrow(denied);
    expect(quotes).toBe(2);
    expect(proofs).toBe(0);
  });

  it("rechecks complete entry pins when an existing key's approved measurements change", async () => {
    const answer = archive();
    const now = vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    fixNonce(answer.nonce);
    const load = vi.fn(async () => document());
    const source = new TeePolicySource({ network: "fixture", load, refreshIntervalMs: 10 });
    const fetch = vi.fn(async () => Response.json(answer.attestation));
    const client = new ProverClient({ url: "https://prover.example", tee: source, fetch });
    await client.attest();
    const [first, second] = vector.policy.deployments;
    if (first === undefined || second === undefined) throw new Error("missing entries");
    load.mockResolvedValue({
      policy: {
        ...vector.policy,
        revision: 2,
        deployments: [
          { ...first, policy: { ...first.policy, measurements: second.policy.measurements } },
          ...vector.policy.deployments.slice(1),
        ],
      },
      validUntil: vector.policy.expires_at,
    });
    now.mockReturnValue(answer.at * 1000 + 20);
    fixNonce(answer.nonce);
    await expect(client.checkProvingKeys()).rejects.toThrow(denied);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("does not reuse a cached enclave key after a required policy refresh fails", async () => {
    const answer = archive();
    const now = vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    fixNonce(answer.nonce);
    const load = vi.fn(async () => document());
    const source = new TeePolicySource({ network: "fixture", load, refreshIntervalMs: 10 });
    const fetch = vi.fn(async () => Response.json(answer.attestation));
    const client = new ProverClient({ url: "https://prover.example", tee: source, fetch });
    await client.attest();
    now.mockReturnValue(answer.at * 1000 + 20);
    load.mockRejectedValue(new Error("repository unavailable"));
    await expect(client.checkProvingKeys()).rejects.toThrow(denied);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
